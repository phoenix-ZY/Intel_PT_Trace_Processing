#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import json
import math
from collections import Counter
from pathlib import Path
from typing import Iterable

DEFAULT_EXCLUDED_FEATURES = {"stride_entropy", "rd_entropy"}
DEFAULT_INST_EXTRA_EXCLUDE_PATTERNS = {"prefetch_*"}


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


def cosine(xs: list[float], ys: list[float]) -> float:
    if len(xs) != len(ys) or not xs:
        return 0.0
    dot = sum(a * b for a, b in zip(xs, ys))
    nx = math.sqrt(sum(a * a for a in xs))
    ny = math.sqrt(sum(b * b for b in ys))
    if nx == 0.0 or ny == 0.0:
        return 0.0
    return dot / (nx * ny)


def cdf_l1(xs: list[float], ys: list[float]) -> float:
    if len(xs) != len(ys) or not xs:
        return 0.0
    sx = 0.0
    sy = 0.0
    acc = 0.0
    for a, b in zip(xs, ys):
        sx += a
        sy += b
        acc += abs(sx - sy)
    return acc / max(1, len(xs))


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


def bucket_order_key(label: str) -> tuple[int, int]:
    if label == "0":
        return (0, 0)
    if label == "1":
        return (1, 1)
    if label.startswith(">="):
        try:
            return (3, int(label[2:]))
        except ValueError:
            return (4, 0)
    if "-" in label:
        try:
            return (2, int(label.split("-", 1)[0]))
        except ValueError:
            return (4, 0)
    try:
        return (2, int(label))
    except ValueError:
        return (4, 0)


def feature_vector_from_obj(obj: dict, kind: str) -> tuple[list[str], list[float]]:
    f = obj.get("feature", {})
    if kind == "rd":
        bins = f.get("rd_bins")
        prob = f.get("rd_prob")
    else:
        bins = f.get("stride_bins")
        prob = f.get("stride_prob")
    if isinstance(bins, list) and isinstance(prob, list) and len(bins) == len(prob) and bins:
        return [str(x) for x in bins], [float(x) for x in prob]
    if kind == "rd":
        h = parse_int_hist(obj["rd_histogram"])
    else:
        h = Counter(obj["stride"]["abs_delta_bucket_histogram"])
    labels = sorted([str(k) for k in h.keys()], key=bucket_order_key)
    total = float(sum(h.get(int(k), 0) if kind == "rd" else h.get(k, 0) for k in labels))
    if kind == "rd":
        probs = [float(h.get(int(k), 0)) / total if total > 0 else 0.0 for k in labels]
    else:
        probs = [float(h.get(k, 0)) / total if total > 0 else 0.0 for k in labels]
    return labels, probs


def should_exclude_feature(name: str, excluded_patterns: set[str]) -> bool:
    for pat in excluded_patterns:
        if not pat:
            continue
        if "*" in pat:
            if fnmatch.fnmatch(name, pat):
                return True
            continue
        if name == pat:
            return True
    return False


def extract_feature_scalars(obj: dict, excluded_features: set[str] | None = None) -> dict[str, float]:
    feat = obj.get("feature", {})
    out: dict[str, float] = {}
    if not isinstance(feat, dict):
        return out
    excluded = excluded_features or set()
    for k, v in feat.items():
        if k in ("rd_bins", "rd_prob", "stride_bins", "stride_prob"):
            continue
        if should_exclude_feature(k, excluded):
            continue
        if isinstance(v, (int, float)):
            out[k] = float(v)
    return out


def compare_named_vectors(ref_vec: dict[str, float], test_vec: dict[str, float], top_k: int) -> dict:
    keys = sorted(set(ref_vec) | set(test_vec))
    rv = [float(ref_vec.get(k, 0.0)) for k in keys]
    tv = [float(test_vec.get(k, 0.0)) for k in keys]
    r = pearson(rv, tv)
    diffs = []
    for k, a, b in zip(keys, rv, tv):
        d = abs(a - b)
        diffs.append(
            {
                "dimension": k,
                "ref_value": a,
                "test_value": b,
                "abs_diff": d,
                "rel_diff_vs_ref": (d / abs(a)) if abs(a) > 1e-15 else None,
            }
        )
    diffs.sort(key=lambda x: x["abs_diff"], reverse=True)
    cos = cosine(rv, tv)
    r2 = max(0.0, r * r)
    l1_mean_abs = sum(abs(a - b) for a, b in zip(rv, tv)) / max(1, len(keys))
    max_abs = max((abs(a - b) for a, b in zip(rv, tv)), default=0.0)
    # Higher-is-better single score for ranking:
    # keep distribution shape similarity as the main signal,
    # while penalizing absolute magnitude mismatch.
    l1_term = 1.0 / (1.0 + l1_mean_abs)
    max_term = 1.0 / (1.0 + max_abs)
    overall_score = 0.45 * cos + 0.30 * r2 + 0.15 * l1_term + 0.10 * max_term
    return {
        "dimensions": len(keys),
        "metrics": {
            "cosine": cos,
            "pearson_r": r,
            "r2": r2,
            "l1_mean_abs": l1_mean_abs,
            "max_abs_diff": max_abs,
            "overall_score": overall_score,
            "overall_score_components": {
                "cosine": cos,
                "r2": r2,
                "l1_term": l1_term,
                "max_term": max_term,
            },
        },
        "largest_error_dims": diffs[: max(1, top_k)],
    }


def compare_access(
    ref: dict,
    test: dict,
    top_k: int,
    max_error_bins: int,
    sdp_max_lines: int,
    excluded_features: set[str] | None = None,
) -> dict:
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
    stride_bins = sorted(set(ref_stride_hist) | set(test_stride_hist), key=bucket_order_key)
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

    rd_fb_ref_bins, rd_fb_ref = feature_vector_from_obj(ref, "rd")
    rd_fb_test_bins, rd_fb_test = feature_vector_from_obj(test, "rd")
    rd_union = sorted(set(rd_fb_ref_bins) | set(rd_fb_test_bins), key=bucket_order_key)
    rd_ref_map = {k: v for k, v in zip(rd_fb_ref_bins, rd_fb_ref)}
    rd_test_map = {k: v for k, v in zip(rd_fb_test_bins, rd_fb_test)}
    rd_ref_vec = [rd_ref_map.get(k, 0.0) for k in rd_union]
    rd_test_vec = [rd_test_map.get(k, 0.0) for k in rd_union]

    st_fb_ref_bins, st_fb_ref = feature_vector_from_obj(ref, "stride")
    st_fb_test_bins, st_fb_test = feature_vector_from_obj(test, "stride")
    st_union = sorted(set(st_fb_ref_bins) | set(st_fb_test_bins), key=bucket_order_key)
    st_ref_map = {k: v for k, v in zip(st_fb_ref_bins, st_fb_ref)}
    st_test_map = {k: v for k, v in zip(st_fb_test_bins, st_fb_test)}
    st_ref_vec = [st_ref_map.get(k, 0.0) for k in st_union]
    st_test_vec = [st_test_map.get(k, 0.0) for k in st_union]

    # Build one unified representation vector with a single namespace:
    # distribution metrics + derived scalar metrics.
    ref_unified: dict[str, float] = {}
    test_unified: dict[str, float] = {}

    for k, v in zip(rd_union, rd_ref_vec):
        ref_unified[f"rd_prob::{k}"] = float(v)
    for k, v in zip(rd_union, rd_test_vec):
        test_unified[f"rd_prob::{k}"] = float(v)
    for k, v in zip(st_union, st_ref_vec):
        ref_unified[f"stride_prob::{k}"] = float(v)
    for k, v in zip(st_union, st_test_vec):
        test_unified[f"stride_prob::{k}"] = float(v)

    ref_unified["cold_ratio"] = float(ref.get("cold_ratio", 0.0))
    test_unified["cold_ratio"] = float(test.get("cold_ratio", 0.0))
    ref_unified["stride_zero_delta_ratio"] = float(ref["stride"].get("zero_delta_ratio", 0.0))
    test_unified["stride_zero_delta_ratio"] = float(test["stride"].get("zero_delta_ratio", 0.0))
    ref_unified["stride_nearby_delta_ratio_abs_le_1"] = float(
        ref["stride"].get("nearby_delta_ratio_abs_le_1", 0.0)
    )
    test_unified["stride_nearby_delta_ratio_abs_le_1"] = float(
        test["stride"].get("nearby_delta_ratio_abs_le_1", 0.0)
    )

    for c, v in zip(capacities, ref_mr):
        ref_unified[f"sdp_miss_ratio@{c}"] = float(v)
    for c, v in zip(capacities, test_mr):
        test_unified[f"sdp_miss_ratio@{c}"] = float(v)

    ref_unified.update(extract_feature_scalars(ref, excluded_features))
    test_unified.update(extract_feature_scalars(test, excluded_features))
    overall_vector = compare_named_vectors(ref_unified, test_unified, top_k)

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
        "feature_metrics": {
            "rd_cosine": cosine(rd_ref_vec, rd_test_vec),
            "rd_cdf_l1": cdf_l1(rd_ref_vec, rd_test_vec),
            "stride_cosine": cosine(st_ref_vec, st_test_vec),
            "stride_cdf_l1": cdf_l1(st_ref_vec, st_test_vec),
        },
        "overall_vector": overall_vector,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Compare two analyzed mem-trace profile JSON files")
    ap.add_argument("--ref-analysis", type=Path, required=True)
    ap.add_argument("--test-analysis", type=Path, required=True)
    ap.add_argument("--top-k", type=int, default=50)
    ap.add_argument("--max-error-bins", type=int, default=20)
    ap.add_argument("--sdp-max-lines", type=int, default=262144)
    ap.add_argument(
        "--exclude-features",
        type=str,
        default=",".join(sorted(DEFAULT_EXCLUDED_FEATURES)),
        help="comma-separated feature scalar names to exclude from overall vector scoring",
    )
    ap.add_argument(
        "--inst-extra-exclude-features",
        type=str,
        default=",".join(sorted(DEFAULT_INST_EXTRA_EXCLUDE_PATTERNS)),
        help="extra scalar feature patterns excluded only when trace_kind=inst (supports wildcard like prefetch_*)",
    )
    ap.add_argument("--json-out", type=Path, required=True)
    args = ap.parse_args()
    excluded_features = {x.strip() for x in args.exclude_features.split(",") if x.strip()}
    inst_extra_excluded = {x.strip() for x in args.inst_extra_exclude_features.split(",") if x.strip()}

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
    trace_kind = str(ref.get("trace_kind") or "")
    if trace_kind == "inst":
        excluded_features = set(excluded_features) | set(inst_extra_excluded)

    ref_accesses = ref.get("accesses") or list(ref.get("per_access", {}).keys())
    test_accesses = test.get("accesses") or list(test.get("per_access", {}).keys())
    accesses = [a for a in ref_accesses if a in set(test_accesses)]
    if not accesses:
        raise SystemExit("no common access kinds between analysis files")
    out = {
        "rd_definition": ref.get("rd_definition"),
        "line_size": ref.get("line_size"),
        "trace_kind": trace_kind,
        "excluded_feature_scalars": sorted(excluded_features),
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
            excluded_features=excluded_features,
        )

    text = json.dumps(out, indent=2, ensure_ascii=False)
    print(text)
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
