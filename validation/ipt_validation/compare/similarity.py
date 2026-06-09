from __future__ import annotations

import json
import math
from itertools import combinations
from pathlib import Path
from typing import Any

from intel_pt_trace_processing.core.features import load_json_object, memory_feature_view


def load_compare_metrics(path: Path, metric_prefix: str = "") -> dict:
    obj = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, object] = {}
    if obj.get("schema") != "trace-feature-vector-compare-v1":
        return out
    ov = obj.get("overall_vector", {})
    metrics = ov.get("metrics", {}) if isinstance(ov, dict) else {}
    if isinstance(metrics, dict):
        for key, value in metrics.items():
            if isinstance(value, (int, float)):
                out[f"{metric_prefix}overall_{key}"] = value
    if isinstance(ov, dict):
        dims = ov.get("dimensions")
        if isinstance(dims, (int, float)):
            out[f"{metric_prefix}overall_dims"] = dims
        top_dims = ov.get("largest_error_dims", [])
        top0 = top_dims[0] if top_dims and isinstance(top_dims[0], dict) else {}
        out[f"{metric_prefix}overall_top_dim"] = top0.get("dimension", "")
        out[f"{metric_prefix}overall_top_dim_abs_diff"] = top0.get("abs_diff", 0.0)
        out[f"{metric_prefix}overall_top3_dims"] = "|".join(
            str(x.get("dimension", ""))
            for x in top_dims[:3]
            if isinstance(x, dict) and x.get("dimension")
        )
    return out


def maybe_write_feature_bundle(
    *,
    out_path: Path,
    sde_profile: Path,
    perf_profile: Path,
    data_compare: Path,
) -> None:
    sde_obj = load_json_object(sde_profile)
    sde_data = memory_feature_view(sde_obj, memory="data")
    perf_obj = load_json_object(perf_profile)
    perf_data = memory_feature_view(perf_obj, memory="data")
    data_cmp = json.loads(data_compare.read_text(encoding="utf-8"))

    bundle = {
        "schema": "trace-feature-bundle-v2",
        "data": {
            "ref_profile": str(sde_profile),
            "test_profile": str(perf_profile),
            "ref_features": {"all": sde_data},
            "test_features": {"all": perf_data},
            "overall_vector_similarity": {"all": data_cmp.get("overall_vector", {})},
        },
    }
    out_path.write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")


def cosine(xs: list[float], ys: list[float]) -> float:
    if len(xs) != len(ys) or not xs:
        return 0.0
    dot = sum(a * b for a, b in zip(xs, ys))
    nx = math.sqrt(sum(a * a for a in xs))
    ny = math.sqrt(sum(b * b for b in ys))
    if nx == 0.0 or ny == 0.0:
        return 0.0
    return dot / (nx * ny)


def pearson(xs: list[float], ys: list[float]) -> float:
    if len(xs) != len(ys) or not xs:
        return 0.0
    mx = sum(xs) / len(xs)
    my = sum(ys) / len(ys)
    num = sum((a - mx) * (b - my) for a, b in zip(xs, ys))
    denx = math.sqrt(sum((a - mx) ** 2 for a in xs))
    deny = math.sqrt(sum((b - my) ** 2 for b in ys))
    if denx == 0.0 or deny == 0.0:
        return 0.0
    return num / (denx * deny)


def flatten_feature_vector(feature_obj: dict) -> dict[str, float]:
    out: dict[str, float] = {}
    for key in ("rd", "stride"):
        bins = feature_obj.get(f"{key}_bins", [])
        probs = feature_obj.get(f"{key}_prob", [])
        if isinstance(bins, list) and isinstance(probs, list):
            for b, p in zip(bins, probs):
                out[f"{key}_prob::{b}"] = float(p)
    for k, v in feature_obj.items():
        if k in ("rd_bins", "rd_prob", "stride_bins", "stride_prob"):
            continue
        if isinstance(v, (int, float)):
            out[k] = float(v)
    return out


def compare_named_vectors(ref_vec: dict[str, float], test_vec: dict[str, float], top_k: int = 3) -> dict:
    keys = sorted(set(ref_vec) | set(test_vec))
    rv = [float(ref_vec.get(k, 0.0)) for k in keys]
    tv = [float(test_vec.get(k, 0.0)) for k in keys]
    diffs = [{"dim": k, "abs_diff": abs(a - b)} for k, a, b in zip(keys, rv, tv)]
    diffs.sort(key=lambda x: x["abs_diff"], reverse=True)
    r = pearson(rv, tv)
    return {
        "dims": len(keys),
        "cosine": cosine(rv, tv),
        "r2": max(0.0, r * r),
        "l1_mean_abs": sum(abs(a - b) for a, b in zip(rv, tv)) / max(1, len(keys)),
        "top_dims": [x["dim"] for x in diffs[: max(1, top_k)]],
    }


def warmup_cross_similarity(cases: list[Any], out_base: Path) -> tuple[Path, Path] | None:
    ok_cases = [c for c in cases if c.status == "ok" and c.out_dir]
    by_bench: dict[str, list[Any]] = {}
    for c in ok_cases:
        by_bench.setdefault(c.bench, []).append(c)

    rows: list[dict] = []
    for bench, bench_cases in by_bench.items():
        bench_cases.sort(key=lambda x: x.warmup)
        if len(bench_cases) < 2:
            continue
        bundle_cache: dict[str, dict] = {}
        for c in bench_cases:
            bundles = list((Path(c.out_dir) / "report").glob("*.features.bundle.json"))
            if not bundles:
                continue
            try:
                bundle_cache[c.out_dir] = json.loads(bundles[0].read_text(encoding="utf-8"))
            except Exception:
                continue
        for a, b in combinations(bench_cases, 2):
            ba = bundle_cache.get(a.out_dir)
            bb = bundle_cache.get(b.out_dir)
            if not ba or not bb:
                continue
            spaces = [
                ("data_ref", ba.get("data", {}).get("ref_features", {}).get("all", {}), bb.get("data", {}).get("ref_features", {}).get("all", {})),
                ("data_test", ba.get("data", {}).get("test_features", {}).get("all", {}), bb.get("data", {}).get("test_features", {}).get("all", {})),
            ]
            for space, fa, fb in spaces:
                if not isinstance(fa, dict) or not isinstance(fb, dict) or not fa or not fb:
                    continue
                cmp = compare_named_vectors(flatten_feature_vector(fa), flatten_feature_vector(fb), top_k=3)
                rows.append(
                    {
                        "bench": bench,
                        "warmup_a": a.warmup,
                        "warmup_b": b.warmup,
                        "space": space,
                        "cosine": cmp["cosine"],
                        "r2": cmp["r2"],
                        "l1_mean_abs": cmp["l1_mean_abs"],
                        "dims": cmp["dims"],
                        "top3_dims": "|".join(cmp["top_dims"]),
                    }
                )

    if not rows:
        return None

    out_json = out_base / "warmup_pairwise_similarity.json"
    out_csv = out_base / "warmup_pairwise_similarity.csv"
    out_json.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    keys = ["bench", "warmup_a", "warmup_b", "space", "cosine", "r2", "l1_mean_abs", "dims", "top3_dims"]
    lines = [",".join(keys)]
    for r in rows:
        lines.append(",".join(str(r[k]).replace(",", ";") for k in keys))
    out_csv.write_text("\n".join(lines) + "\n", encoding="utf-8")

    for bench in sorted({r["bench"] for r in rows}):
        b = [r for r in rows if r["bench"] == bench and r["space"] == "data_ref"]
        if not b:
            continue
        mean_cos = sum(float(x["cosine"]) for x in b) / len(b)
        print(f"[warmup] bench={bench} data_ref_pairs={len(b)} mean_cos={mean_cos:.4f}")
    return out_json, out_csv


def flatten_trace_profile(profile: dict[str, Any]) -> dict[str, Any]:
    metadata = profile.get("metadata") if isinstance(profile, dict) else None
    if not isinstance(metadata, dict):
        metadata = {}
    source = metadata.get("source")
    if not isinstance(source, dict):
        source = {}
    row: dict[str, Any] = {
        "schema": profile.get("schema", ""),
        "prefix": metadata.get("prefix", ""),
        "source_kind": source.get("kind", ""),
        "source_path": source.get("path", ""),
    }
    features = profile.get("features")
    if not isinstance(features, dict):
        return row
    for group, values in features.items():
        if not isinstance(values, dict):
            continue
        for key, value in values.items():
            if isinstance(value, bool):
                continue
            if isinstance(value, (int, float, str)):
                row[f"{group}_{key}"] = value
    return row
