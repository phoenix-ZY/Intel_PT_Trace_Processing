#!/usr/bin/env python3
"""
Windowed comparison for DWT-style evaluation.

Given two mem-access JSONL traces that include an "insn_idx" field per event, this
script computes, per instruction window:
- reuse-distance histogram (stack-distance profile at cache-line granularity)
- histogram similarity via Pearson r and R^2 (same approach as compare_reuse_profiles.py)
- page-level hotness distribution for 4KB pages (top-16/32/64/128 buckets)

This matches the paper's "per 100M instructions interval" evaluation style.
"""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Counter as CounterT, Iterable, Iterator, Optional


def pearson(xs: Iterable[float], ys: Iterable[float]) -> float:
    x = list(xs)
    y = list(ys)
    if len(x) != len(y) or not x:
        return 0.0
    mx = sum(x) / len(x)
    my = sum(y) / len(y)
    num = sum((a - mx) * (b - my) for a, b in zip(x, y))
    denx = math.sqrt(sum((a - mx) ** 2 for a in x))
    deny = math.sqrt(sum((b - my) ** 2 for b in y))
    if denx == 0.0 or deny == 0.0:
        return 0.0
    return num / (denx * deny)


@dataclass(frozen=True)
class Window:
    start: int  # inclusive insn_idx
    end: int  # exclusive insn_idx


def iter_mem_events_in_window(
    path: Path,
    *,
    window: Window,
    access: Optional[str],
    line_size: int,
    insn_idx_offset: int,
) -> Iterator[int]:
    """
    Yield normalized cache-line addresses (addr // line_size) in event order.
    """
    with path.open("r", encoding="utf-8", errors="replace") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind = obj.get("access")
            if kind not in ("read", "write"):
                continue
            if access is not None and kind != access:
                continue
            insn_idx = obj.get("insn_idx")
            if not isinstance(insn_idx, int):
                continue
            insn_idx = insn_idx + insn_idx_offset
            if insn_idx < window.start or insn_idx >= window.end:
                continue
            addr = obj.get("addr")
            if not isinstance(addr, str) or not addr.startswith("0x"):
                continue
            try:
                a = int(addr, 16)
            except ValueError:
                continue
            yield a // line_size


def count_mem_events_in_window(
    path: Path, *, window: Window, access: Optional[str], insn_idx_offset: int
) -> int:
    n = 0
    with path.open("r", encoding="utf-8", errors="replace") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind = obj.get("access")
            if kind not in ("read", "write"):
                continue
            if access is not None and kind != access:
                continue
            insn_idx = obj.get("insn_idx")
            if not isinstance(insn_idx, int):
                continue
            insn_idx = insn_idx + insn_idx_offset
            if insn_idx < window.start or insn_idx >= window.end:
                continue
            addr = obj.get("addr")
            if not isinstance(addr, str) or not addr.startswith("0x"):
                continue
            n += 1
    return n


class Fenwick:
    def __init__(self, n: int):
        self.n = n
        self.bit = [0] * (n + 1)

    def add(self, i: int, delta: int) -> None:
        while i <= self.n:
            self.bit[i] += delta
            i += i & -i

    def sum(self, i: int) -> int:
        s = 0
        while i > 0:
            s += self.bit[i]
            i -= i & -i
        return s


def compute_rd_hist(
    addrs: Iterable[int],
    n: int,
    *,
    rd_definition: str,
) -> tuple[int, int, CounterT[int]]:
    """
    Return (cold, reuses, histogram) for the given window stream.
    """
    bit = Fenwick(n)
    last_pos: dict[int, int] = {}
    cold = 0
    reuses = 0
    hist: CounterT[int] = Counter()
    active_total = 0

    for t, a in enumerate(addrs, 1):
        p = last_pos.get(a)
        if p is None:
            cold += 1
            last_pos[a] = t
            bit.add(t, 1)
            active_total += 1
            continue
        rd = active_total - bit.sum(p)
        if rd_definition == "stack_depth":
            rd += 1
        hist[rd] += 1
        reuses += 1
        bit.add(p, -1)
        bit.add(t, 1)
        last_pos[a] = t

    return cold, reuses, hist


def page_hotness_buckets_in_window(
    path: Path, *, window: Window, access: Optional[str], page_size: int, insn_idx_offset: int
) -> dict:
    counts: CounterT[int] = Counter()
    total = 0
    with path.open("r", encoding="utf-8", errors="replace") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind = obj.get("access")
            if kind not in ("read", "write"):
                continue
            if access is not None and kind != access:
                continue
            insn_idx = obj.get("insn_idx")
            if not isinstance(insn_idx, int):
                continue
            insn_idx = insn_idx + insn_idx_offset
            if insn_idx < window.start or insn_idx >= window.end:
                continue
            addr = obj.get("addr")
            if not isinstance(addr, str) or not addr.startswith("0x"):
                continue
            try:
                a = int(addr, 16)
            except ValueError:
                continue
            page = a // page_size
            counts[page] += 1
            total += 1

    ranked = [c for _, c in counts.most_common(128)]

    def pct(lo: int, hi: int) -> float:
        # lo/hi are 1-indexed ranks: [lo..hi]
        if total <= 0:
            return 0.0
        start = lo - 1
        end = min(hi, len(ranked))
        return sum(ranked[start:end]) / float(total)

    return {
        "total_events": total,
        "unique_pages": len(counts),
        "buckets": {
            "1-16": pct(1, 16),
            "17-32": pct(17, 32),
            "33-64": pct(33, 64),
            "65-128": pct(65, 128),
        },
    }


def compare_window(
    *,
    ref: Path,
    test: Path,
    window: Window,
    access: Optional[str],
    line_size: int,
    rd_definition: str,
    page_size: int,
    ref_insn_idx_offset: int,
    test_insn_idx_offset: int,
) -> dict:
    n_ref = count_mem_events_in_window(
        ref, window=window, access=access, insn_idx_offset=ref_insn_idx_offset
    )
    n_test = count_mem_events_in_window(
        test, window=window, access=access, insn_idx_offset=test_insn_idx_offset
    )
    cold_r, reuses_r, hist_r = compute_rd_hist(
        iter_mem_events_in_window(
            ref,
            window=window,
            access=access,
            line_size=line_size,
            insn_idx_offset=ref_insn_idx_offset,
        ),
        n_ref,
        rd_definition=rd_definition,
    )
    cold_t, reuses_t, hist_t = compute_rd_hist(
        iter_mem_events_in_window(
            test,
            window=window,
            access=access,
            line_size=line_size,
            insn_idx_offset=test_insn_idx_offset,
        ),
        n_test,
        rd_definition=rd_definition,
    )

    bins = sorted(set(hist_r) | set(hist_t))
    ref_counts = [float(hist_r.get(b, 0)) for b in bins]
    test_counts = [float(hist_t.get(b, 0)) for b in bins]
    r = pearson(ref_counts, test_counts)
    r2 = max(0.0, r * r)

    page_ref = page_hotness_buckets_in_window(
        ref,
        window=window,
        access=access,
        page_size=page_size,
        insn_idx_offset=ref_insn_idx_offset,
    )
    page_test = page_hotness_buckets_in_window(
        test,
        window=window,
        access=access,
        page_size=page_size,
        insn_idx_offset=test_insn_idx_offset,
    )

    return {
        "window": {"start_insn_idx": window.start, "end_insn_idx": window.end},
        "access": "all" if access is None else access,
        "rd": {
            "ref": {"events": cold_r + reuses_r, "cold": cold_r, "reuses": reuses_r},
            "test": {"events": cold_t + reuses_t, "cold": cold_t, "reuses": reuses_t},
            "metrics": {"pearson_r": r, "r2": r2, "unique_bins_ref": len(hist_r), "unique_bins_test": len(hist_t)},
        },
        "page_hotness": {"ref": page_ref, "test": page_test},
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Windowed DWT-style comparison (requires insn_idx).")
    ap.add_argument("--ref", type=Path, required=True, help="reference mem JSONL (SDE real)")
    ap.add_argument("--test", type=Path, required=True, help="test mem JSONL (Unicorn virtual)")
    ap.add_argument("--window-insns", type=int, default=100_000_000, help="window size in dynamic instructions")
    ap.add_argument("--max-windows", type=int, default=0, help="limit number of windows (0=no limit)")
    ap.add_argument(
        "--access",
        choices=["all", "read", "write"],
        default="all",
        help="which stream to compare (default: all)",
    )
    ap.add_argument("--line-size", type=int, default=64, help="cache line size bytes (default: 64)")
    ap.add_argument("--page-size", type=int, default=4096, help="page size bytes (default: 4096)")
    ap.add_argument(
        "--ref-insn-idx-offset",
        type=int,
        default=0,
        help="shift ref insn_idx by this amount before windowing (default: 0)",
    )
    ap.add_argument(
        "--test-insn-idx-offset",
        type=int,
        default=0,
        help="shift test insn_idx by this amount before windowing (default: 0)",
    )
    ap.add_argument(
        "--rd-definition",
        choices=["distinct_since_last", "stack_depth"],
        default="stack_depth",
        help="reuse distance definition (default: stack_depth, paper-style)",
    )
    ap.add_argument("--json-out", type=Path, default=None, help="optional JSON output path")
    args = ap.parse_args()

    if not args.ref.is_file():
        raise SystemExit(f"ref not found: {args.ref}")
    if not args.test.is_file():
        raise SystemExit(f"test not found: {args.test}")
    if args.window_insns <= 0:
        raise SystemExit("--window-insns must be > 0")

    access = None if args.access == "all" else args.access

    # Determine maximum insn_idx present (we assume the insn traces are aligned already).
    max_idx = -1
    with args.ref.open("r", encoding="utf-8", errors="replace") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            ii = obj.get("insn_idx")
            if isinstance(ii, int):
                ii2 = ii + int(args.ref_insn_idx_offset)
                if ii2 > max_idx:
                    max_idx = ii2
    if max_idx < 0:
        raise SystemExit("ref trace has no insn_idx; regenerate with updated converter.")

    results = []
    w = 0
    start = 0
    while start <= max_idx:
        end = start + args.window_insns
        win = Window(start=start, end=end)
        results.append(
            compare_window(
                ref=args.ref,
                test=args.test,
                window=win,
                access=access,
                line_size=args.line_size,
                rd_definition=args.rd_definition,
                page_size=args.page_size,
                ref_insn_idx_offset=int(args.ref_insn_idx_offset),
                test_insn_idx_offset=int(args.test_insn_idx_offset),
            )
        )
        w += 1
        if args.max_windows and w >= args.max_windows:
            break
        start = end

    out = {
        "ref_path": str(args.ref),
        "test_path": str(args.test),
        "window_insns": args.window_insns,
        "access": args.access,
        "line_size": args.line_size,
        "page_size": args.page_size,
        "rd_definition": args.rd_definition,
        "ref_insn_idx_offset": int(args.ref_insn_idx_offset),
        "test_insn_idx_offset": int(args.test_insn_idx_offset),
        "windows": results,
    }
    text = json.dumps(out, indent=2, ensure_ascii=False)
    print(text)
    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

