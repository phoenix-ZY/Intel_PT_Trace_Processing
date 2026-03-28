#!/usr/bin/env python3
"""
Compute reuse/stack distance from mem_access.jsonl.

Supported definitions:
- distinct_since_last:
  For a repeated address at time t with previous occurrence at p < t,
  RD(t) = number of distinct addresses referenced in (p, t).
  (Consecutive re-reference -> RD=0)
- stack_depth:
  Classic stack-distance depth (paper-style): RD = distinct_since_last + 1.
  (Consecutive re-reference -> RD=1)

First-time references are counted separately as "cold".

We compute this exactly using a Fenwick tree (BIT) over time indices of last
occurrences:
- Maintain a BIT with 1 at the current last-occurrence index of each address.
- When seeing address a at time t:
  - if first time: mark BIT[t]=1
  - else: let p = last[a]
      reuse = active_total - prefix_sum(p)  (counts last-occurrences after p)
      update BIT[p]=0; BIT[t]=1

Supports computing reuse distance separately for read/write streams by filtering.
"""

from __future__ import annotations

import argparse
import io
import json
import math
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Literal, Optional, TextIO


Access = Literal["read", "write"]


class Fenwick:
    def __init__(self, n: int):
        self.n = n
        self.bit = [0] * (n + 1)

    def add(self, i: int, delta: int) -> None:
        # i is 1-indexed
        n = self.n
        bit = self.bit
        while i <= n:
            bit[i] += delta
            i += i & -i

    def sum(self, i: int) -> int:
        # prefix sum [1..i]
        s = 0
        bit = self.bit
        while i > 0:
            s += bit[i]
            i -= i & -i
        return s


@dataclass(frozen=True)
class RDStats:
    total_events: int
    cold: int
    reuses: int
    max_rd: int
    mean_rd: float
    p50: Optional[int]
    p90: Optional[int]
    p99: Optional[int]
    histogram: Counter[int]


def iter_events(
    path: Path, *, access: Optional[Access], line_size: int
) -> Iterator[int]:
    """
    Yield normalized addresses (as int) for events, optionally filtered by access kind.
    Skips lines that are not memory access events.
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
            addr = obj.get("addr")
            if kind not in ("read", "write"):
                continue
            if access is not None and kind != access:
                continue
            if not isinstance(addr, str) or not addr.startswith("0x"):
                continue
            try:
                a = int(addr, 16)
            except ValueError:
                continue

            # Normalize to cache line to compute reuse at line granularity.
            # We emit a line-id (a // line_size) rather than the aligned address.
            yield a // line_size


def count_events(path: Path, *, access: Optional[Access]) -> int:
    """
    Count memory access events (optionally filtered by access kind) without
    materializing addresses. Used to size data structures for exact RD.
    """
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
            addr = obj.get("addr")
            if not isinstance(addr, str) or not addr.startswith("0x"):
                continue
            n += 1
    return n


def compute_reuse_distances_streaming(
    addrs: Iterable[int], n: int, *, rd_definition: str
) -> tuple[int, Counter[int], int]:
    """
    Returns (cold_count, histogram, reuse_count).
    Histogram maps reuse distance -> count (only for non-cold reuses).
    """
    bit = Fenwick(n)
    last_pos: dict[int, int] = {}

    cold = 0
    reuse_hist: Counter[int] = Counter()
    reuses = 0
    active_total = 0

    for t, a in enumerate(addrs, 1):
        p = last_pos.get(a)
        if p is None:
            cold += 1
            last_pos[a] = t
            bit.add(t, 1)
            active_total += 1
            continue

        # Number of active last-occurrences strictly after p.
        rd = active_total - bit.sum(p)
        if rd_definition == "stack_depth":
            rd += 1
        reuse_hist[rd] += 1
        reuses += 1

        # Move "last occurrence" marker from p -> t.
        bit.add(p, -1)
        bit.add(t, 1)
        last_pos[a] = t
        # active_total unchanged

    return cold, reuse_hist, reuses


def percentile_from_hist(hist: Counter[int], pct: float) -> Optional[int]:
    if not hist:
        return None
    if pct <= 0:
        return min(hist)
    if pct >= 100:
        return max(hist)
    total = sum(hist.values())
    target = math.ceil(total * (pct / 100.0))
    run = 0
    for k in sorted(hist):
        run += hist[k]
        if run >= target:
            return k
    return max(hist)


def summarize(
    stream_path: Path,
    access: Optional[Access],
    *,
    line_size: int,
    rd_definition: str,
) -> RDStats:
    total_events = count_events(stream_path, access=access)
    addrs = iter_events(stream_path, access=access, line_size=line_size)
    cold, hist, reuses = compute_reuse_distances_streaming(
        addrs, total_events, rd_definition=rd_definition
    )
    total_rd = sum(k * v for k, v in hist.items())
    mean_rd = (total_rd / reuses) if reuses else 0.0
    max_rd = max(hist) if hist else 0

    return RDStats(
        total_events=total_events,
        cold=cold,
        reuses=reuses,
        max_rd=max_rd,
        mean_rd=mean_rd,
        p50=percentile_from_hist(hist, 50),
        p90=percentile_from_hist(hist, 90),
        p99=percentile_from_hist(hist, 99),
        histogram=hist,
    )


def bucket_log2(hist: Counter[int]) -> Counter[str]:
    """
    Bucket reuse distances into log2 ranges: 0, 1, 2-3, 4-7, 8-15, ...
    """
    out: Counter[str] = Counter()
    for rd, cnt in hist.items():
        if rd <= 0:
            out["0"] += cnt
        elif rd == 1:
            out["1"] += cnt
        else:
            hi = 1 << (rd.bit_length() - 1)
            lo = hi
            hi2 = (hi << 1) - 1
            out[f"{lo}-{hi2}"] += cnt
    return out


def print_report(name: str, st: RDStats, *, top_n: int, out: TextIO) -> None:
    print(f"== {name} ==", file=out)
    print(f"events: {st.total_events}", file=out)
    print(f"cold(first-touch): {st.cold}", file=out)
    print(f"reuses: {st.reuses}", file=out)
    if st.reuses:
        print(f"mean reuse distance: {st.mean_rd:.3f}", file=out)
        print(f"p50/p90/p99: {st.p50}/{st.p90}/{st.p99}", file=out)
        print(f"max reuse distance: {st.max_rd}", file=out)
    else:
        print("no reuses (all cold).", file=out)

    if st.histogram:
        print(file=out)
        print("top exact reuse distances:", file=out)
        for rd, cnt in st.histogram.most_common(top_n):
            print(f"  rd={rd}: {cnt}", file=out)

        print(file=out)
        print("log2-bucketed reuse distances:", file=out)
        b = bucket_log2(st.histogram)
        for k in sorted(
            b,
            key=lambda s: (
                0 if s == "0" else 1 if s == "1" else int(s.split("-", 1)[0])
            ),
        ):
            print(f"  {k}: {b[k]}", file=out)
    print(file=out)


def main() -> int:
    ap = argparse.ArgumentParser(description="Compute reuse distance from mem_access.jsonl")
    ap.add_argument(
        "-i",
        "--input",
        type=Path,
        default=Path("mem_access.jsonl"),
        help="mem_access JSONL (default: mem_access.jsonl)",
    )
    ap.add_argument(
        "--line-size",
        type=int,
        default=64,
        help="cache line size in bytes for address normalization (default: 64)",
    )
    ap.add_argument(
        "--report-out",
        type=Path,
        default=None,
        help="optional path to write the full report text",
    )
    ap.add_argument(
        "--top",
        type=int,
        default=15,
        help="top-N exact reuse distances to print (default: 15)",
    )
    ap.add_argument(
        "--rd-definition",
        choices=["distinct_since_last", "stack_depth"],
        default="stack_depth",
        help=(
            "reuse-distance definition: distinct_since_last (old behavior) "
            "or stack_depth (paper-style, default)"
        ),
    )
    args = ap.parse_args()

    if not args.input.is_file():
        raise SystemExit(f"input not found: {args.input}")
    if args.line_size <= 0 or (args.line_size & (args.line_size - 1)) != 0:
        raise SystemExit("--line-size must be a positive power of two")

    st_all = summarize(
        args.input,
        access=None,
        line_size=args.line_size,
        rd_definition=args.rd_definition,
    )
    st_r = summarize(
        args.input,
        access="read",
        line_size=args.line_size,
        rd_definition=args.rd_definition,
    )
    st_w = summarize(
        args.input,
        access="write",
        line_size=args.line_size,
        rd_definition=args.rd_definition,
    )

    buf = io.StringIO()
    print(
        f"RD definition: {args.rd_definition}, line size: {args.line_size}B",
        file=buf,
    )
    print(file=buf)
    print_report("ALL (read+write)", st_all, top_n=args.top, out=buf)
    print_report("READ", st_r, top_n=args.top, out=buf)
    print_report("WRITE", st_w, top_n=args.top, out=buf)
    report_text = buf.getvalue()

    # Always print to stdout.
    print(report_text, end="")

    if args.report_out is not None:
        args.report_out.parent.mkdir(parents=True, exist_ok=True)
        args.report_out.write_text(report_text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

