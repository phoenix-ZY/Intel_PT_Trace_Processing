#!/usr/bin/env python3
"""
Compare two memory traces by reuse-distance profile similarity.

This script reports:
- Histogram-level similarity: Pearson r / R^2, L1 distance, top-K WMAPE
- Cold-ratio delta
- Largest-error RD bins
- SDP similarity (miss-ratio curve vs cache-size curve) with R^2 and max error
"""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from pathlib import Path
from typing import Iterable, Optional

from reuse_distance import iter_events, count_events, compute_reuse_distances_streaming


def rd_histogram(
    path: Path,
    *,
    access: Optional[str],
    line_size: int,
    rd_definition: str,
) -> tuple[int, int, Counter[int]]:
    total = count_events(path, access=access)
    addrs = iter_events(path, access=access, line_size=line_size)
    cold, hist, reuses = compute_reuse_distances_streaming(
        addrs, total, rd_definition=rd_definition
    )
    return cold, reuses, hist


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


def miss_ratio_curve(
    *, cold: int, hist: Counter[int], total_events: int, capacities: list[int]
) -> list[float]:
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
    misses: list[float] = []
    for c in capacities:
        hits = prefix[c] if 0 <= c < len(prefix) else prefix[-1] if prefix else 0
        miss = 1.0 - ((cold + hits) / float(total_events))
        if miss < 0.0:
            miss = 0.0
        misses.append(miss)
    return misses


def analyze_one_access(
    *,
    ref_path: Path,
    test_path: Path,
    access_name: str,
    line_size: int,
    rd_definition: str,
    top_k: int,
    max_error_bins: int,
    sdp_max_lines: int,
) -> dict:
    access = None if access_name == "all" else access_name
    ref_cold, ref_reuses, ref_hist = rd_histogram(
        ref_path,
        access=access,
        line_size=line_size,
        rd_definition=rd_definition,
    )
    test_cold, test_reuses, test_hist = rd_histogram(
        test_path,
        access=access,
        line_size=line_size,
        rd_definition=rd_definition,
    )
    ref_total = ref_cold + ref_reuses
    test_total = test_cold + test_reuses

    bins = sorted(set(ref_hist) | set(test_hist))
    ref_counts = [float(ref_hist.get(b, 0)) for b in bins]
    test_counts = [float(test_hist.get(b, 0)) for b in bins]

    r = pearson(ref_counts, test_counts)
    r2 = max(0.0, r * r)

    ref_sum = sum(ref_counts)
    test_sum = sum(test_counts)
    if ref_sum > 0 and test_sum > 0:
        ref_probs = [c / ref_sum for c in ref_counts]
        test_probs = [c / test_sum for c in test_counts]
        l1 = sum(abs(a - b) for a, b in zip(ref_probs, test_probs))
    else:
        l1 = 0.0

    top_bins = [b for b, _ in ref_hist.most_common(max(1, top_k))]
    denom = sum(ref_hist.get(b, 0) for b in top_bins)
    if denom > 0:
        wmape = sum(abs(ref_hist.get(b, 0) - test_hist.get(b, 0)) for b in top_bins) / denom
    else:
        wmape = 0.0

    err_bins = []
    for b in bins:
        a = ref_hist.get(b, 0)
        t = test_hist.get(b, 0)
        err_bins.append(
            {
                "rd": b,
                "ref_count": a,
                "test_count": t,
                "abs_err": abs(a - t),
                "rel_err_vs_ref": (abs(a - t) / a) if a > 0 else None,
            }
        )
    err_bins.sort(key=lambda x: x["abs_err"], reverse=True)
    err_bins = err_bins[: max(1, max_error_bins)]

    cap_upper = max(
        1,
        min(
            sdp_max_lines,
            max(
                max(ref_hist) if ref_hist else 1,
                max(test_hist) if test_hist else 1,
            ),
        ),
    )
    capacities = []
    c = 1
    while c <= cap_upper:
        capacities.append(c)
        c <<= 1
    if capacities[-1] != cap_upper:
        capacities.append(cap_upper)

    ref_mr = miss_ratio_curve(
        cold=ref_cold, hist=ref_hist, total_events=max(1, ref_total), capacities=capacities
    )
    test_mr = miss_ratio_curve(
        cold=test_cold, hist=test_hist, total_events=max(1, test_total), capacities=capacities
    )
    mr_r = pearson(ref_mr, test_mr)
    mr_r2 = max(0.0, mr_r * mr_r)
    mr_l1 = sum(abs(a - b) for a, b in zip(ref_mr, test_mr)) / max(1, len(capacities))
    mr_max_abs = max(abs(a - b) for a, b in zip(ref_mr, test_mr)) if capacities else 0.0

    return {
        "access": access_name,
        "ref": {
            "events": ref_total,
            "cold": ref_cold,
            "reuses": ref_reuses,
            "cold_ratio": (ref_cold / ref_total) if ref_total else 0.0,
            "unique_rd_bins": len(ref_hist),
        },
        "test": {
            "events": test_total,
            "cold": test_cold,
            "reuses": test_reuses,
            "cold_ratio": (test_cold / test_total) if test_total else 0.0,
            "unique_rd_bins": len(test_hist),
        },
        "metrics": {
            "pearson_r": r,
            "r2": r2,
            "l1_prob_distance": l1,
            "topk_wmape": wmape,
            "topk": max(1, top_k),
            "cold_ratio_abs_diff": abs(
                ((ref_cold / ref_total) if ref_total else 0.0)
                - ((test_cold / test_total) if test_total else 0.0)
            ),
        },
        "largest_error_bins": err_bins,
        "sdp": {
            "capacities_lines": capacities,
            "ref_miss_ratio": ref_mr,
            "test_miss_ratio": test_mr,
            "metrics": {
                "pearson_r": mr_r,
                "r2": mr_r2,
                "mean_abs_error": mr_l1,
                "max_abs_error": mr_max_abs,
            },
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Compare RD profiles between two traces")
    ap.add_argument("--ref", type=Path, required=True, help="reference mem JSONL")
    ap.add_argument("--test", type=Path, required=True, help="test mem JSONL")
    ap.add_argument(
        "--access",
        choices=["all", "read", "write", "all_streams"],
        default="all_streams",
        help="which stream to compare (default: all_streams)",
    )
    ap.add_argument("--line-size", type=int, default=64, help="cache line size")
    ap.add_argument(
        "--rd-definition",
        choices=["distinct_since_last", "stack_depth"],
        default="stack_depth",
        help="reuse distance definition (default: stack_depth)",
    )
    ap.add_argument("--top-k", type=int, default=50, help="top-K bins for WMAPE")
    ap.add_argument(
        "--max-error-bins",
        type=int,
        default=20,
        help="how many largest-error bins to include (default: 20)",
    )
    ap.add_argument(
        "--sdp-max-lines",
        type=int,
        default=262144,
        help="max cache capacity points (in lines) for SDP curve (default: 262144)",
    )
    ap.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="optional JSON output path",
    )
    args = ap.parse_args()

    if not args.ref.is_file():
        raise SystemExit(f"ref not found: {args.ref}")
    if not args.test.is_file():
        raise SystemExit(f"test not found: {args.test}")
    if args.line_size <= 0 or (args.line_size & (args.line_size - 1)) != 0:
        raise SystemExit("--line-size must be a positive power of two")
    if args.sdp_max_lines <= 0:
        raise SystemExit("--sdp-max-lines must be positive")

    if args.access == "all_streams":
        accesses = ["all", "read", "write"]
    else:
        accesses = [args.access]

    per_access = {}
    for a in accesses:
        per_access[a] = analyze_one_access(
            ref_path=args.ref,
            test_path=args.test,
            access_name=a,
            line_size=args.line_size,
            rd_definition=args.rd_definition,
            top_k=max(1, args.top_k),
            max_error_bins=max(1, args.max_error_bins),
            sdp_max_lines=args.sdp_max_lines,
        )

    result = {
        "rd_definition": args.rd_definition,
        "line_size": args.line_size,
        "ref_path": str(args.ref),
        "test_path": str(args.test),
        "access_mode": args.access,
        "per_access": per_access,
    }

    print(json.dumps(result, indent=2, ensure_ascii=False))
    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

