#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from pathlib import Path
from typing import Iterable


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


def jsd(p: list[float], q: list[float]) -> float:
    def kl(a: list[float], b: list[float]) -> float:
        out = 0.0
        for x, y in zip(a, b):
            if x <= 0.0 or y <= 0.0:
                continue
            out += x * math.log2(x / y)
        return out

    m = [(a + b) * 0.5 for a, b in zip(p, q)]
    return 0.5 * kl(p, m) + 0.5 * kl(q, m)


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


def parse_int_hist(d: dict[str, int]) -> Counter[int]:
    c: Counter[int] = Counter()
    for k, v in d.items():
        c[int(k)] = int(v)
    return c


def compare_access(ref: dict, test: dict, top_k: int, max_error_bins: int, sdp_max_lines: int) -> dict:
    ref_hist = parse_int_hist(ref["rd_histogram"])
    test_hist = parse_int_hist(test["rd_histogram"])
    bins = sorted(set(ref_hist) | set(test_hist))
    ref_counts = [float(ref_hist.get(b, 0)) for b in bins]
    test_counts = [float(test_hist.get(b, 0)) for b in bins]
    r = pearson(ref_counts, test_counts)
    r2 = max(0.0, r * r)

    ref_sum = sum(ref_counts)
    test_sum = sum(test_counts)
    if ref_sum > 0 and test_sum > 0:
        ref_probs = [x / ref_sum for x in ref_counts]
        test_probs = [x / test_sum for x in test_counts]
        l1 = sum(abs(a - b) for a, b in zip(ref_probs, test_probs))
    else:
        l1 = 0.0

    top_bins = [b for b, _ in ref_hist.most_common(max(1, top_k))]
    denom = sum(ref_hist.get(b, 0) for b in top_bins)
    wmape = (
        sum(abs(ref_hist.get(b, 0) - test_hist.get(b, 0)) for b in top_bins) / denom
        if denom > 0
        else 0.0
    )

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

    ref_events = int(ref["events"])
    test_events = int(test["events"])
    ref_cold = int(ref["cold"])
    test_cold = int(test["cold"])
    cap_upper = max(
        1,
        min(sdp_max_lines, max(max(ref_hist) if ref_hist else 1, max(test_hist) if test_hist else 1)),
    )
    capacities = []
    c = 1
    while c <= cap_upper:
        capacities.append(c)
        c <<= 1
    if capacities[-1] != cap_upper:
        capacities.append(cap_upper)
    ref_mr = miss_ratio_curve(cold=ref_cold, hist=ref_hist, total_events=max(1, ref_events), capacities=capacities)
    test_mr = miss_ratio_curve(cold=test_cold, hist=test_hist, total_events=max(1, test_events), capacities=capacities)
    mr_r = pearson(ref_mr, test_mr)
    mr_r2 = max(0.0, mr_r * mr_r)
    mr_l1 = sum(abs(a - b) for a, b in zip(ref_mr, test_mr)) / max(1, len(capacities))
    mr_max = max(abs(a - b) for a, b in zip(ref_mr, test_mr)) if capacities else 0.0

    ref_stride_hist = Counter(ref["stride"]["abs_delta_bucket_histogram"])
    test_stride_hist = Counter(test["stride"]["abs_delta_bucket_histogram"])
    stride_bins = sorted(
        set(ref_stride_hist) | set(test_stride_hist),
        key=lambda s: 0 if s == "0" else 1 if s == "1" else int(s.split("-", 1)[0]),
    )
    sr = [float(ref_stride_hist.get(b, 0)) for b in stride_bins]
    st = [float(test_stride_hist.get(b, 0)) for b in stride_bins]
    spr = pearson(sr, st)
    spr2 = max(0.0, spr * spr)
    srs = sum(sr)
    sts = sum(st)
    if srs > 0 and sts > 0:
        sp_ref = [x / srs for x in sr]
        sp_test = [x / sts for x in st]
        sl1 = sum(abs(a - b) for a, b in zip(sp_ref, sp_test))
        sjsd = jsd(sp_ref, sp_test)
    else:
        sp_ref = [0.0 for _ in stride_bins]
        sp_test = [0.0 for _ in stride_bins]
        sl1 = 0.0
        sjsd = 0.0
    stride_err = []
    for b, rp, tp in zip(stride_bins, sp_ref, sp_test):
        stride_err.append({"bucket": b, "ref_prob": rp, "test_prob": tp, "abs_err": abs(rp - tp)})
    stride_err.sort(key=lambda x: x["abs_err"], reverse=True)

    return {
        "ref": {
            "events": ref_events,
            "cold": ref_cold,
            "reuses": int(ref["reuses"]),
            "cold_ratio": float(ref["cold_ratio"]),
            "unique_rd_bins": len(ref_hist),
        },
        "test": {
            "events": test_events,
            "cold": test_cold,
            "reuses": int(test["reuses"]),
            "cold_ratio": float(test["cold_ratio"]),
            "unique_rd_bins": len(test_hist),
        },
        "metrics": {
            "pearson_r": r,
            "r2": r2,
            "l1_prob_distance": l1,
            "topk_wmape": wmape,
            "topk": max(1, top_k),
            "cold_ratio_abs_diff": abs(float(ref["cold_ratio"]) - float(test["cold_ratio"])),
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
                "max_abs_error": mr_max,
            },
        },
        "stride": {
            "bucket_definition": "|delta_lines| log2 bins",
            "bins": stride_bins,
            "ref_prob": sp_ref,
            "test_prob": sp_test,
            "metrics": {
                "pearson_r": spr,
                "r2": spr2,
                "l1_prob_distance": sl1,
                "jsd": sjsd,
            },
            "ref_stride": {
                "zero_delta_ratio": float(ref["stride"]["zero_delta_ratio"]),
                "nearby_delta_ratio_abs_le_1": float(ref["stride"]["nearby_delta_ratio_abs_le_1"]),
            },
            "test_stride": {
                "zero_delta_ratio": float(test["stride"]["zero_delta_ratio"]),
                "nearby_delta_ratio_abs_le_1": float(test["stride"]["nearby_delta_ratio_abs_le_1"]),
            },
            "largest_error_bins": stride_err[: max(1, top_k)],
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Compare two analyzed mem-trace profile JSON files")
    ap.add_argument("--ref-analysis", type=Path, required=True)
    ap.add_argument("--test-analysis", type=Path, required=True)
    ap.add_argument("--top-k", type=int, default=50)
    ap.add_argument("--max-error-bins", type=int, default=20)
    ap.add_argument("--sdp-max-lines", type=int, default=262144)
    ap.add_argument("--json-out", type=Path, required=True)
    args = ap.parse_args()

    if not args.ref_analysis.is_file():
        raise SystemExit(f"ref-analysis not found: {args.ref_analysis}")
    if not args.test_analysis.is_file():
        raise SystemExit(f"test-analysis not found: {args.test_analysis}")
    ref = json.loads(args.ref_analysis.read_text(encoding="utf-8"))
    test = json.loads(args.test_analysis.read_text(encoding="utf-8"))
    if ref.get("line_size") != test.get("line_size"):
        raise SystemExit("line_size mismatch between analysis files")
    if ref.get("trace_kind") != test.get("trace_kind"):
        raise SystemExit("trace_kind mismatch between analysis files")

    ref_accesses = ref.get("accesses") or list(ref.get("per_access", {}).keys())
    test_accesses = test.get("accesses") or list(test.get("per_access", {}).keys())
    accesses = [a for a in ref_accesses if a in set(test_accesses)]
    if not accesses:
        raise SystemExit("no common access kinds between analysis files")
    out = {
        "rd_definition": ref.get("rd_definition"),
        "line_size": ref.get("line_size"),
        "trace_kind": ref.get("trace_kind"),
        "ref_path": ref.get("input_path"),
        "test_path": test.get("input_path"),
        "ref_analysis": str(args.ref_analysis),
        "test_analysis": str(args.test_analysis),
        "accesses": accesses,
        "per_access": {},
    }
    for access in accesses:
        out["per_access"][access] = compare_access(
            ref["per_access"][access],
            test["per_access"][access],
            top_k=max(1, args.top_k),
            max_error_bins=max(1, args.max_error_bins),
            sdp_max_lines=max(1, args.sdp_max_lines),
        )

    text = json.dumps(out, indent=2, ensure_ascii=False)
    print(text)
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
