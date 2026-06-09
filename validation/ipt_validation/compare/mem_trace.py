from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Iterable

from intel_pt_trace_processing.core.features import load_json_object, memory_feature_view

DEFAULT_EXCLUDED_FEATURES = {"accesses_per_1k_insns"}


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


def cosine(xs: list[float], ys: list[float]) -> float:
    if len(xs) != len(ys) or not xs:
        return 0.0
    dot = sum(a * b for a, b in zip(xs, ys))
    nx = math.sqrt(sum(a * a for a in xs))
    ny = math.sqrt(sum(b * b for b in ys))
    if nx == 0.0 or ny == 0.0:
        return 0.0
    return dot / (nx * ny)


def compare_named_vectors(
    ref_vec: dict[str, float],
    test_vec: dict[str, float],
    top_k: int,
    excluded_features: set[str] | None = None,
) -> dict:
    excluded = excluded_features or set()
    keys = sorted((set(ref_vec) | set(test_vec)) - excluded)
    rv = [float(ref_vec.get(k, 0.0)) for k in keys]
    tv = [float(test_vec.get(k, 0.0)) for k in keys]
    r = pearson(rv, tv)
    diffs = []
    for key, ref_value, test_value in zip(keys, rv, tv):
        abs_diff = abs(ref_value - test_value)
        diffs.append(
            {
                "dimension": key,
                "ref_value": ref_value,
                "test_value": test_value,
                "abs_diff": abs_diff,
                "rel_diff_vs_ref": (abs_diff / abs(ref_value)) if abs(ref_value) > 1e-15 else None,
            }
        )
    diffs.sort(key=lambda item: item["abs_diff"], reverse=True)
    l1_mean_abs = sum(abs(a - b) for a, b in zip(rv, tv)) / max(1, len(keys))
    max_abs = max((abs(a - b) for a, b in zip(rv, tv)), default=0.0)
    r2 = max(0.0, r * r)
    l1_term = 1.0 / (1.0 + l1_mean_abs)
    max_term = 1.0 / (1.0 + max_abs)
    cos = cosine(rv, tv)
    return {
        "dimensions": len(keys),
        "metrics": {
            "cosine": cos,
            "pearson_r": r,
            "r2": r2,
            "l1_mean_abs": l1_mean_abs,
            "max_abs_diff": max_abs,
            "overall_score": 0.45 * cos + 0.30 * r2 + 0.15 * l1_term + 0.10 * max_term,
            "overall_score_components": {
                "cosine": cos,
                "r2": r2,
                "l1_term": l1_term,
                "max_term": max_term,
            },
        },
        "largest_error_dims": diffs[: max(1, top_k)],
    }


def compare_memory_profiles(
    *,
    ref_profile: Path,
    test_profile: Path,
    json_out: Path,
    memory: str = "data",
    top_k: int = 20,
    excluded_features: set[str] | None = None,
) -> dict:
    ref_obj = load_json_object(ref_profile)
    test_obj = load_json_object(test_profile)
    ref = memory_feature_view(ref_obj, memory=memory)
    test = memory_feature_view(test_obj, memory=memory)
    if not ref:
        raise ValueError(f"empty ref {memory} feature view: {ref_profile}")
    if not test:
        raise ValueError(f"empty test {memory} feature view: {test_profile}")
    excluded = excluded_features if excluded_features is not None else set(DEFAULT_EXCLUDED_FEATURES)

    out = {
        "schema": "trace-feature-vector-compare-v1",
        "ref_profile": str(ref_profile),
        "test_profile": str(test_profile),
        "memory_view": memory,
        "excluded_features": sorted(excluded),
        "ref_features": ref,
        "test_features": test,
        "overall_vector": compare_named_vectors(
            ref,
            test,
            top_k=max(1, top_k),
            excluded_features=excluded,
        ),
    }
    json_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare final memory feature groups from trace_profile.json")
    parser.add_argument("--ref-profile", type=Path, required=True)
    parser.add_argument("--test-profile", type=Path, required=True)
    parser.add_argument(
        "--memory",
        choices=["data", "inst", "instruction"],
        default="data",
        help="Feature group to compare: data_memory or instruction_memory.",
    )
    parser.add_argument("--top-k", type=int, default=50)
    parser.add_argument("--max-error-bins", type=int, default=20, help="Deprecated; accepted for runner compatibility.")
    parser.add_argument("--sdp-max-lines", type=int, default=262144, help="Deprecated; accepted for runner compatibility.")
    parser.add_argument(
        "--exclude-features",
        type=str,
        default=",".join(sorted(DEFAULT_EXCLUDED_FEATURES)),
        help="Comma-separated feature names excluded from vector scoring.",
    )
    parser.add_argument(
        "--inst-extra-exclude-features",
        type=str,
        default="",
        help="Deprecated; accepted for runner compatibility.",
    )
    parser.add_argument("--json-out", type=Path, required=True)
    args = parser.parse_args()
    excluded_features = {item.strip() for item in args.exclude_features.split(",") if item.strip()}
    out = compare_memory_profiles(
        ref_profile=args.ref_profile,
        test_profile=args.test_profile,
        json_out=args.json_out,
        memory=args.memory,
        top_k=max(1, args.top_k),
        excluded_features=excluded_features,
    )
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
