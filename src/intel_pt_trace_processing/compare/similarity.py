from __future__ import annotations

import json
import math
from itertools import combinations
from pathlib import Path
from typing import Any


def load_compare_metrics(path: Path, metric_prefix: str = "") -> dict:
    obj = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, object] = {}
    excluded = obj.get("excluded_feature_scalars")
    if isinstance(excluded, list):
        out[f"{metric_prefix}excluded_feature_scalars"] = "|".join(str(x) for x in excluded)
    accesses = obj.get("accesses") or list(obj.get("per_access", {}).keys())
    for access in accesses:
        pa = obj["per_access"][access]
        p = f"{metric_prefix}{access}_"
        for section, section_prefix in (("metrics", "rd_"), ("feature_metrics", "")):
            metrics = pa.get(section, {})
            if isinstance(metrics, dict):
                for k, v in metrics.items():
                    if isinstance(v, (int, float)):
                        out[f"{p}{section_prefix}{k}"] = v
        for section, section_prefix in (("sdp", "sdp_"), ("stride", "stride_")):
            metrics = pa.get(section, {}).get("metrics", {})
            if isinstance(metrics, dict):
                for k, v in metrics.items():
                    if isinstance(v, (int, float)):
                        out[f"{p}{section_prefix}{k}"] = v
        ov = pa.get("overall_vector", {})
        om = ov.get("metrics", {}) if isinstance(ov, dict) else {}
        if isinstance(om, dict):
            for k, v in om.items():
                if isinstance(v, (int, float)):
                    out[f"{p}overall_{k}"] = v
        comps = om.get("overall_score_components") if isinstance(om, dict) else None
        if isinstance(comps, dict):
            for k, v in comps.items():
                if isinstance(v, (int, float)):
                    out[f"{p}overall_component_{k}"] = v
        out[f"{p}overall_dims"] = ov.get("dimensions", 0) if isinstance(ov, dict) else 0
        top_dims = ov.get("largest_error_dims", []) if isinstance(ov, dict) else []
        top0 = top_dims[0] if top_dims and isinstance(top_dims[0], dict) else {}
        out[f"{p}overall_top_dim"] = top0.get("dimension", "")
        out[f"{p}overall_top_dim_abs_diff"] = top0.get("abs_diff", 0.0)
        top3 = [x.get("dimension", "") for x in top_dims[:3] if isinstance(x, dict) and x.get("dimension")]
        out[f"{p}overall_top3_dims"] = "|".join(top3)
    return out


def maybe_write_feature_bundle(
    *,
    out_path: Path,
    sde_data_analysis: Path,
    sde_inst_analysis: Path,
    perf_data_analysis: Path,
    perf_inst_analysis: Path,
    data_compare: Path,
    inst_compare: Path,
) -> None:
    def pick_features(analysis_obj: dict) -> dict:
        per = analysis_obj.get("per_access", {})
        out: dict[str, dict] = {}
        for access, access_obj in per.items():
            feat = access_obj.get("feature")
            if isinstance(feat, dict):
                out[access] = feat
        return out

    sde_data = json.loads(sde_data_analysis.read_text(encoding="utf-8"))
    sde_inst = json.loads(sde_inst_analysis.read_text(encoding="utf-8"))
    perf_data = json.loads(perf_data_analysis.read_text(encoding="utf-8"))
    perf_inst = json.loads(perf_inst_analysis.read_text(encoding="utf-8"))
    data_cmp = json.loads(data_compare.read_text(encoding="utf-8"))
    inst_cmp = json.loads(inst_compare.read_text(encoding="utf-8"))

    bundle = {
        "schema": "trace-feature-bundle-v1",
        "line_size": sde_data.get("line_size"),
        "rd_definition": sde_data.get("rd_definition"),
        "rd_hist_cap_lines": sde_data.get("rd_hist_cap_lines"),
        "stride_bin_cap_lines": sde_data.get("stride_bin_cap_lines"),
        "data": {
            "ref_path": sde_data.get("input_path"),
            "test_path": perf_data.get("input_path"),
            "ref_features": pick_features(sde_data),
            "test_features": pick_features(perf_data),
            "feature_metrics": {
                access: data_cmp.get("per_access", {}).get(access, {}).get("feature_metrics", {})
                for access in data_cmp.get("accesses", [])
            },
            "overall_vector_similarity": {
                access: data_cmp.get("per_access", {}).get(access, {}).get("overall_vector", {})
                for access in data_cmp.get("accesses", [])
            },
        },
        "inst": {
            "ref_path": sde_inst.get("input_path"),
            "test_path": perf_inst.get("input_path"),
            "ref_features": pick_features(sde_inst),
            "test_features": pick_features(perf_inst),
            "feature_metrics": {
                access: inst_cmp.get("per_access", {}).get(access, {}).get("feature_metrics", {})
                for access in inst_cmp.get("accesses", [])
            },
            "overall_vector_similarity": {
                access: inst_cmp.get("per_access", {}).get(access, {}).get("overall_vector", {})
                for access in inst_cmp.get("accesses", [])
            },
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
                ("inst_ref", ba.get("inst", {}).get("ref_features", {}).get("all", {}), bb.get("inst", {}).get("ref_features", {}).get("all", {})),
                ("inst_test", ba.get("inst", {}).get("test_features", {}).get("all", {}), bb.get("inst", {}).get("test_features", {}).get("all", {})),
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
