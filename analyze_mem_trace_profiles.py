#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from array import array
from collections import Counter
from pathlib import Path

from reuse_distance import compute_reuse_distances_streaming


def bucket_log2_from_int_hist(hist: Counter[int]) -> Counter[str]:
    out: Counter[str] = Counter()
    for v, cnt in hist.items():
        if v <= 0:
            out["0"] += cnt
        elif v == 1:
            out["1"] += cnt
        else:
            lo = 1 << (v.bit_length() - 1)
            hi = (lo << 1) - 1
            out[f"{lo}-{hi}"] += cnt
    return out


def miss_ratio_curve(*, cold: int, hist: Counter[int], total_events: int, capacities: list[int]) -> list[float]:
    if total_events <= 0:
        return [0.0 for _ in capacities]
    max_rd = max(hist) if hist else 0
    freq = [0] * (max_rd + 1)
    for rd, cnt in hist.items():
        if rd >= 0:
            freq[rd] += cnt
    prefix = [0] * len(freq)
    run = 0
    for i, v in enumerate(freq):
        run += v
        prefix[i] = run
    out: list[float] = []
    for c in capacities:
        hits = prefix[c] if 0 <= c < len(prefix) else prefix[-1] if prefix else 0
        miss = 1.0 - ((cold + hits) / float(total_events))
        if miss < 0.0:
            miss = 0.0
        out.append(miss)
    return out


class TraceStats:
    INSN_RE = re.compile(r"^\s*(?P<tid>\d+)\s+\S+:\s+(?P<ip>[0-9a-fA-F]+)\s+insn:\s+")

    def __init__(self, path: Path, line_size: int, trace_kind: str, input_format: str):
        self.path = path
        self.line_size = line_size
        self.trace_kind = trace_kind
        self.input_format = input_format
        self.lines = array("Q")
        self.kinds = bytearray()  # 0=read, 1=write, 2=inst
        self.counts: dict[str, int] = {"all": 0, "read": 0, "write": 0}
        self.deltas: dict[str, Counter[int]] = {
            "all": Counter(),
            "read": Counter(),
            "write": Counter(),
        }
        self._is_data = trace_kind == "data"
        self._parse()

    def _parse(self) -> None:
        if self.input_format == "insn_trace":
            self._parse_insn_trace()
            return
        self._parse_mem_jsonl()

    def _parse_mem_jsonl(self) -> None:
        prev: dict[str, dict[int, int]] = {"all": {}, "read": {}, "write": {}}
        with self.path.open("r", encoding="utf-8", errors="replace") as fp:
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                kind = str(obj.get("access", "")).lower()
                addr_obj = obj.get("addr")
                try:
                    if isinstance(addr_obj, str):
                        a = int(addr_obj, 16) if addr_obj.startswith("0x") else int(addr_obj)
                    elif isinstance(addr_obj, int):
                        a = addr_obj
                    else:
                        continue
                    tid = int(obj.get("tid", 0))
                except (ValueError, TypeError):
                    continue

                if self.trace_kind == "data" and kind not in ("read", "write"):
                    continue
                if self.trace_kind == "inst":
                    kind = "inst"
                elif kind not in ("read", "write"):
                    continue

                line_id = a // self.line_size
                self.lines.append(line_id)
                if kind == "write":
                    self.kinds.append(1)
                    self.counts["write"] += 1
                elif kind == "read":
                    self.kinds.append(0)
                    self.counts["read"] += 1
                else:
                    self.kinds.append(2)
                self.counts["all"] += 1

                p_all = prev["all"].get(tid)
                if p_all is not None:
                    self.deltas["all"][line_id - p_all] += 1
                prev["all"][tid] = line_id

                if kind in ("read", "write"):
                    p = prev[kind].get(tid)
                    if p is not None:
                        self.deltas[kind][line_id - p] += 1
                    prev[kind][tid] = line_id

    def _parse_insn_trace(self) -> None:
        self.trace_kind = "inst"
        self._is_data = False
        prev_all: dict[int, int] = {}
        with self.path.open("r", encoding="utf-8", errors="replace") as fp:
            for raw in fp:
                line = raw.strip()
                if not line:
                    continue
                m = self.INSN_RE.match(line)
                if not m:
                    continue
                try:
                    tid = int(m.group("tid"))
                    ip = int(m.group("ip"), 16)
                except ValueError:
                    continue
                line_id = ip // self.line_size
                self.lines.append(line_id)
                self.kinds.append(2)
                self.counts["all"] += 1
                p = prev_all.get(tid)
                if p is not None:
                    self.deltas["all"][line_id - p] += 1
                prev_all[tid] = line_id

    @property
    def events_all(self) -> int:
        return len(self.lines)

    @property
    def accesses(self) -> list[str]:
        if self._is_data:
            return ["all", "read", "write"]
        return ["all"]

    def iter_access(self, access: str):
        if access == "all":
            return iter(self.lines)
        if not self._is_data:
            return iter(())
        target_write = access == "write"
        return (self.lines[i] for i, k in enumerate(self.kinds) if bool(k) == target_write)

    def count_access(self, access: str) -> int:
        return self.counts.get(access, 0)

    def delta_hist(self, access: str) -> Counter[int]:
        return self.deltas.get(access, Counter())


def analyze_access(ts: TraceStats, access: str, rd_definition: str, sdp_max_lines: int) -> dict:
    total = ts.count_access(access)
    cold, rd_hist, reuses = compute_reuse_distances_streaming(
        ts.iter_access(access), total, rd_definition=rd_definition
    )
    max_rd = max(rd_hist) if rd_hist else 1
    cap_upper = max(1, min(sdp_max_lines, max_rd))
    capacities = []
    c = 1
    while c <= cap_upper:
        capacities.append(c)
        c <<= 1
    if capacities[-1] != cap_upper:
        capacities.append(cap_upper)
    mr = miss_ratio_curve(cold=cold, hist=rd_hist, total_events=max(1, total), capacities=capacities)

    delta_hist = ts.delta_hist(access)
    abs_hist: Counter[int] = Counter()
    for d, cnt in delta_hist.items():
        abs_hist[abs(d)] += cnt
    stride_bucket = bucket_log2_from_int_hist(abs_hist)
    d_total = max(1, sum(delta_hist.values()))
    zero = delta_hist.get(0, 0)
    near = zero + delta_hist.get(1, 0) + delta_hist.get(-1, 0)

    return {
        "events": total,
        "cold": cold,
        "reuses": reuses,
        "cold_ratio": (cold / total) if total else 0.0,
        "rd_histogram": {str(k): v for k, v in rd_hist.items()},
        "sdp": {"capacities_lines": capacities, "miss_ratio": mr},
        "stride": {
            "delta_histogram": {str(k): v for k, v in delta_hist.items()},
            "abs_delta_bucket_histogram": dict(stride_bucket),
            "zero_delta_ratio": zero / d_total,
            "nearby_delta_ratio_abs_le_1": near / d_total,
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Analyze one mem trace: RD/SDP + stride profiles")
    ap.add_argument("--input", type=Path, required=True, help="mem JSONL input")
    ap.add_argument(
        "--input-format",
        choices=["auto", "mem_jsonl", "insn_trace"],
        default="auto",
        help="input format; auto infers by file suffix/content",
    )
    ap.add_argument(
        "--trace-kind",
        choices=["auto", "data", "inst"],
        default="auto",
        help="trace type; auto infers from input format/content",
    )
    ap.add_argument("--line-size", type=int, default=64)
    ap.add_argument(
        "--rd-definition",
        choices=["distinct_since_last", "stack_depth"],
        default="stack_depth",
    )
    ap.add_argument("--sdp-max-lines", type=int, default=262144)
    ap.add_argument("--json-out", type=Path, required=True)
    args = ap.parse_args()

    if not args.input.is_file():
        raise SystemExit(f"input not found: {args.input}")
    if args.line_size <= 0 or (args.line_size & (args.line_size - 1)) != 0:
        raise SystemExit("--line-size must be a positive power of two")
    if args.sdp_max_lines <= 0:
        raise SystemExit("--sdp-max-lines must be > 0")

    input_format = args.input_format
    if input_format == "auto":
        if args.input.name.endswith(".trace.txt"):
            input_format = "insn_trace"
        else:
            input_format = "mem_jsonl"
    trace_kind = args.trace_kind
    if trace_kind == "auto":
        trace_kind = "inst" if input_format == "insn_trace" else "data"

    ts = TraceStats(args.input, args.line_size, trace_kind, input_format)
    out = {
        "line_size": args.line_size,
        "rd_definition": args.rd_definition,
        "trace_kind": ts.trace_kind,
        "input_format": input_format,
        "input_path": str(args.input),
        "accesses": ts.accesses,
        "per_access": {a: analyze_access(ts, a, args.rd_definition, args.sdp_max_lines) for a in ts.accesses},
    }
    text = json.dumps(out, indent=2, ensure_ascii=False)
    print(text)
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
