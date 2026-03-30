#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")  # headless
import matplotlib.pyplot as plt


def flatten_feature_vector(feature_obj: dict[str, Any]) -> dict[str, float]:
    out: dict[str, float] = {}
    rd_bins = feature_obj.get("rd_bins", [])
    rd_prob = feature_obj.get("rd_prob", [])
    if isinstance(rd_bins, list) and isinstance(rd_prob, list):
        for b, p in zip(rd_bins, rd_prob):
            try:
                out[f"rd_prob::{b}"] = float(p)
            except Exception:
                continue
    st_bins = feature_obj.get("stride_bins", [])
    st_prob = feature_obj.get("stride_prob", [])
    if isinstance(st_bins, list) and isinstance(st_prob, list):
        for b, p in zip(st_bins, st_prob):
            try:
                out[f"stride_prob::{b}"] = float(p)
            except Exception:
                continue
    for k, v in feature_obj.items():
        if k in ("rd_bins", "rd_prob", "stride_bins", "stride_prob"):
            continue
        if isinstance(v, bool):
            continue
        if isinstance(v, (int, float)):
            fv = float(v)
            if math.isfinite(fv):
                out[k] = fv
    return out


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


def pick_representative_bundle_per_bench(bundle_paths: list[Path]) -> dict[str, Path]:
    """
    Pick one bundle per bench. If multiple warmup tags exist, pick the largest numeric seconds.
    """

    def warmup_seconds_from_tag(tag: str) -> float:
        t = tag.strip().lower()
        if not t.endswith("s"):
            return -1.0
        core = t[:-1].replace("p", ".")
        try:
            return float(core)
        except Exception:
            return -1.0

    best: dict[str, tuple[float, str, Path]] = {}
    for p in bundle_paths:
        # .../<bench>/<tag>/report/*.features.bundle.json
        try:
            tag = p.parents[1].name
            bench = p.parents[2].name
        except Exception:
            continue
        w = warmup_seconds_from_tag(tag)
        cur = best.get(bench)
        key = (w, tag, p)
        if cur is None or (w, tag) > (cur[0], cur[1]):
            best[bench] = key
    return {bench: tup[2] for bench, tup in best.items()}


def write_dim_index_csv(path: Path, *, bench: str, access: str, dims: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["bench,access,feature_idx,feature_dim"]
    for i, d in enumerate(dims, start=1):
        # CSV escape for dim
        dd = d.replace('"', '""')
        if any(ch in dd for ch in [",", '"', "\n", "\r"]):
            dd = f'"{dd}"'
        lines.append(f"{bench},{access},{i},{dd}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def plot_one_bench(
    *,
    bench: str,
    bundle_path: Path,
    out_dir: Path,
    access: str = "all",
    drop_topk_abs_diff: int = 10,
    max_dims: int = 240,
) -> Path | None:
    obj = json.loads(bundle_path.read_text(encoding="utf-8"))
    data = obj.get("data", {})
    if not isinstance(data, dict):
        return None
    ref_feats = data.get("ref_features", {})
    test_feats = data.get("test_features", {})
    if not isinstance(ref_feats, dict) or not isinstance(test_feats, dict):
        return None
    rf = ref_feats.get(access)
    tf = test_feats.get(access)
    if not isinstance(rf, dict) or not isinstance(tf, dict):
        return None

    rflat = flatten_feature_vector(rf)
    tflat = flatten_feature_vector(tf)

    dims_all = sorted(set(rflat.keys()) | set(tflat.keys()))
    pairs = []
    for d in dims_all:
        a = float(rflat.get(d, 0.0))
        b = float(tflat.get(d, 0.0))
        pairs.append((d, a, b, abs(a - b)))

    # Drop the largest-error dimensions to avoid one or two huge outliers dominating the view.
    if drop_topk_abs_diff > 0 and len(pairs) > drop_topk_abs_diff:
        pairs_sorted = sorted(pairs, key=lambda x: x[3], reverse=True)
        dropped = {x[0] for x in pairs_sorted[:drop_topk_abs_diff]}
        pairs = [x for x in pairs if x[0] not in dropped]

    # Keep the plot compact: cap total dimensions (after dropping outliers).
    if max_dims > 0 and len(pairs) > max_dims:
        # Prefer keeping scalar features first, then histogram bins.
        def rank_dim(d: str) -> tuple[int, str]:
            if d.startswith("rd_prob::") or d.startswith("stride_prob::"):
                return (1, d)
            return (0, d)

        pairs = sorted(pairs, key=lambda x: rank_dim(x[0]))[:max_dims]

    # Final order: stable + readable
    pairs.sort(key=lambda x: x[0])

    dims = [p[0] for p in pairs]
    rv = [p[1] for p in pairs]
    tv = [p[2] for p in pairs]
    xs = list(range(1, len(dims) + 1))

    cos = cosine(rv, tv)
    r = pearson(rv, tv)
    r2 = max(0.0, r * r)
    l1 = sum(abs(a - b) for a, b in zip(rv, tv)) / max(1, len(dims))
    max_abs = max((abs(a - b) for a, b in zip(rv, tv)), default=0.0)

    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{bench}.data_features.similarity.compact.png"
    map_path = out_dir / f"{bench}.data_features.feature_index.csv"
    write_dim_index_csv(map_path, bench=bench, access=access, dims=dims)

    # Compact plot: numeric x-axis only.
    width = 10.0
    fig = plt.figure(figsize=(width, 3.8), dpi=180, constrained_layout=True)
    ax0 = fig.add_subplot(1, 1, 1)
    ax0.plot(xs, rv, linewidth=1.0, label="SDE (ref)", color="#1f77b4", marker="o", markersize=2.0)
    ax0.plot(xs, tv, linewidth=1.0, label="perf recovered (test)", color="#ff7f0e", alpha=0.9, marker="o", markersize=2.0)
    ax0.set_xlabel("feature index")
    ax0.set_ylabel("feature value")
    ax0.grid(True, axis="y", alpha=0.25)
    ax0.legend(loc="upper right", frameon=False, fontsize=8)
    # Show fewer x ticks for readability.
    if len(xs) > 0:
        step = max(1, len(xs) // 20)
        ax0.set_xticks(list(range(1, len(xs) + 1, step)))

    tag = bundle_path.parents[1].name
    fig.suptitle(
        f"{bench}  data/{access}  (picked warmup={tag})\n"
        f"cos={cos:.4f}  pearson_r={r:.4f}  r2={r2:.4f}  l1_mean_abs={l1:.6g}  max_abs_diff={max_abs:.6g}  "
        f"(dims={len(dims)}, dropped_topk={drop_topk_abs_diff})",
        fontsize=10,
    )
    fig.savefig(out_path)
    plt.close(fig)
    return out_path


def main() -> int:
    ap = argparse.ArgumentParser(description="Plot per-benchmark similarity for data feature vectors (SDE vs perf recovered).")
    ap.add_argument(
        "--output-base",
        type=Path,
        default=Path("/home/huangtianhao/Intel_PT_Trace_Processing/outputs/spec5_sde_perf_subset"),
        help="outputs directory containing <bench>/<warmup>/report/*.features.bundle.json",
    )
    ap.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="directory to write PNGs (default: <output-base>/plots_data_feature_similarity)",
    )
    ap.add_argument("--access", type=str, default="all", help="which access key to plot (default: all)")
    ap.add_argument(
        "--drop-topk-abs-diff",
        type=int,
        default=10,
        help="drop the top-K dimensions with largest abs diff (default: 10; 0 disables)",
    )
    ap.add_argument(
        "--max-dims",
        type=int,
        default=240,
        help="cap number of plotted dimensions after dropping outliers (default: 240; 0 disables)",
    )
    args = ap.parse_args()

    base: Path = args.output_base
    out_dir: Path = args.out_dir or (base / "plots_data_feature_similarity")

    bundle_paths = sorted(base.glob("*/*/report/*.features.bundle.json"))
    if not bundle_paths:
        print(f"[error] no bundles under {base}")
        return 2
    picked = pick_representative_bundle_per_bench(bundle_paths)
    if not picked:
        print("[error] failed to pick representative bundles")
        return 3

    ok = 0
    for bench in sorted(picked.keys()):
        p = picked[bench]
        out = plot_one_bench(
            bench=bench,
            bundle_path=p,
            out_dir=out_dir,
            access=args.access,
            drop_topk_abs_diff=args.drop_topk_abs_diff,
            max_dims=args.max_dims,
        )
        if out is not None:
            ok += 1
            print(f"[ok] {bench}: {out}")
        else:
            print(f"[warn] {bench}: skip (missing data/{args.access} features?)")

    print(f"[done] benches={len(picked)} plotted={ok} out_dir={out_dir}")
    return 0 if ok > 0 else 4


if __name__ == "__main__":
    raise SystemExit(main())

