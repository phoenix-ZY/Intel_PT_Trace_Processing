#!/usr/bin/env python3
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parent
OUTPUTS = ROOT / "outputs"
CLOUD_CSV = OUTPUTS / "cloud_trace" / "perf_full_features.csv"
SPEC_CSV = OUTPUTS / "spec5_perf_trace_only" / "perf_full_features.csv"
OUT_DIR = OUTPUTS / "analysis"
FIG_DIR = OUT_DIR / "figures"


NON_FEATURE_COLS = {
    "bench",
    "warmup_tag",
    "warmup_seconds",
    "access",
    "data_analysis_json",
    "inst_analysis_json",
    "portrait_json",
}


FEATURE_FAMILIES: list[tuple[str, str]] = [
    ("mix", r"^(mix_|mix_opmix_|mix_submix_)"),
    ("data_locality", r"^(data_rd_prob::|data_stride_prob::|data_rd_entropy$|data_stride_entropy$|data_rd_local_mass_|data_stride_)"),
    ("data_prefetch", r"^data_prefetch_"),
    ("inst_locality", r"^(inst_rd_prob::|inst_stride_prob::|inst_rd_entropy$|inst_stride_entropy$|inst_rd_local_mass_|inst_stride_)"),
    ("branch", r"^branch_"),
    ("syscall", r"^syscall_"),
    ("deps_scalar", r"^dep_(raw|war|waw)_"),
    ("deps_vector", r"^dep_vec_"),
]


@dataclass(frozen=True)
class RidgeResult:
    weights: pd.Series
    intercept: float
    r2: float


def _ensure_out_dir() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    FIG_DIR.mkdir(parents=True, exist_ok=True)


def _read_df(csv_path: Path, suite: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    df.insert(0, "suite", suite)
    return df


def _schema_check(df_a: pd.DataFrame, df_b: pd.DataFrame) -> dict:
    cols_a = list(df_a.columns)
    cols_b = list(df_b.columns)
    return {
        "a_cols": len(cols_a),
        "b_cols": len(cols_b),
        "same_order": cols_a == cols_b,
        "a_only": sorted(set(cols_a) - set(cols_b)),
        "b_only": sorted(set(cols_b) - set(cols_a)),
    }


def _numeric_feature_cols(df: pd.DataFrame) -> list[str]:
    cols = []
    for c in df.columns:
        if c in NON_FEATURE_COLS or c in {"suite", "ipc_total"}:
            continue
        if pd.api.types.is_numeric_dtype(df[c]):
            cols.append(c)
    return cols


def _family_cols(cols: Iterable[str], family_regex: str) -> list[str]:
    rx = re.compile(family_regex)
    return [c for c in cols if rx.search(c)]


def _cohens_d(x: np.ndarray, y: np.ndarray) -> float:
    x = x[np.isfinite(x)]
    y = y[np.isfinite(y)]
    if len(x) < 2 or len(y) < 2:
        return float("nan")
    nx, ny = len(x), len(y)
    vx, vy = x.var(ddof=1), y.var(ddof=1)
    pooled = ((nx - 1) * vx + (ny - 1) * vy) / max(nx + ny - 2, 1)
    if pooled <= 0:
        return float("nan")
    return (x.mean() - y.mean()) / math.sqrt(pooled)


def _ridge_fit_standardized(
    X: np.ndarray, y: np.ndarray, lam: float = 10.0
) -> RidgeResult:
    # Standardize X and y (y centered only), then fit ridge via closed form.
    X = np.asarray(X, dtype=float)
    y = np.asarray(y, dtype=float)
    keep = np.isfinite(y) & np.all(np.isfinite(X), axis=1)
    X = X[keep]
    y = y[keep]

    x_mean = X.mean(axis=0)
    x_std = X.std(axis=0)
    x_std = np.where(x_std == 0, 1.0, x_std)
    Xs = (X - x_mean) / x_std

    y_mean = y.mean()
    yc = y - y_mean

    n, p = Xs.shape
    I = np.eye(p)
    w = np.linalg.solve(Xs.T @ Xs + lam * I, Xs.T @ yc)
    yhat = Xs @ w + y_mean
    ss_res = float(np.sum((y - yhat) ** 2))
    ss_tot = float(np.sum((y - y.mean()) ** 2))
    r2 = 1.0 - ss_res / ss_tot if ss_tot > 0 else float("nan")

    # Convert to original-scale linear model: y ≈ intercept + X @ beta
    beta = w / x_std
    intercept = y_mean - float(np.dot(x_mean, beta))
    return RidgeResult(weights=pd.Series(beta), intercept=intercept, r2=r2)


def _pca_2d(X: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    # Standardize and compute first 2 PCs via SVD.
    X = np.asarray(X, dtype=float)
    keep = np.all(np.isfinite(X), axis=1)
    X = X[keep]

    mean = X.mean(axis=0)
    std = X.std(axis=0)
    std = np.where(std == 0, 1.0, std)
    Xs = (X - mean) / std

    U, S, Vt = np.linalg.svd(Xs, full_matrices=False)
    comps = Vt[:2].T  # p x 2
    coords = Xs @ comps  # n x 2
    var = (S**2) / max(len(Xs) - 1, 1)
    var_ratio = var / var.sum() if var.sum() > 0 else np.full_like(var, np.nan)
    return coords, comps, var_ratio[:2]


def _workload_group(bench: str, suite: str) -> str:
    if suite == "cloud":
        return bench.split(".", 1)[0] if isinstance(bench, str) and "." in bench else str(bench)
    # SPEC: keep full bench name (e.g., 525.x264_r) and also allow a coarse "spec"
    return str(bench)


def _kmeans(X: np.ndarray, k: int, seed: int = 0, n_iter: int = 100) -> tuple[np.ndarray, np.ndarray]:
    """
    Minimal k-means (Lloyd) for standardized numeric arrays.
    Returns (labels, centroids).
    """
    rng = np.random.default_rng(seed)
    X = np.asarray(X, dtype=float)
    n = X.shape[0]
    if k <= 1 or k > n:
        raise ValueError("invalid k")
    # init with random unique points
    idx = rng.choice(n, size=k, replace=False)
    C = X[idx].copy()
    labels = np.zeros(n, dtype=int)
    for _ in range(n_iter):
        # assign
        d2 = ((X[:, None, :] - C[None, :, :]) ** 2).sum(axis=2)
        new_labels = d2.argmin(axis=1)
        if np.array_equal(new_labels, labels):
            break
        labels = new_labels
        # update
        for j in range(k):
            m = labels == j
            if not np.any(m):
                C[j] = X[rng.integers(0, n)]
            else:
                C[j] = X[m].mean(axis=0)
    return labels, C


def _cluster_purity(labels: np.ndarray, true_labels: Iterable[str]) -> float:
    true_labels = np.asarray(list(true_labels))
    labels = np.asarray(labels)
    pur = []
    for c in np.unique(labels):
        m = labels == c
        if m.sum() == 0:
            continue
        vals, counts = np.unique(true_labels[m], return_counts=True)
        pur.append(counts.max() / m.sum())
    return float(np.mean(pur)) if pur else float("nan")


def _ridge_cv_r2(X: np.ndarray, y: np.ndarray, lam: float = 10.0, kfold: int = 5, seed: int = 0) -> float:
    rng = np.random.default_rng(seed)
    X = np.asarray(X, dtype=float)
    y = np.asarray(y, dtype=float)
    keep = np.isfinite(y) & np.all(np.isfinite(X), axis=1)
    X = X[keep]
    y = y[keep]
    n = len(y)
    if n < kfold + 2:
        return float("nan")
    idx = np.arange(n)
    rng.shuffle(idx)
    folds = np.array_split(idx, kfold)
    r2s = []
    for i in range(kfold):
        te = folds[i]
        tr = np.concatenate([folds[j] for j in range(kfold) if j != i])
        res = _ridge_fit_standardized(X[tr], y[tr], lam=lam)
        yhat = res.intercept + X[te] @ res.weights.to_numpy(float)
        ss_res = float(np.sum((y[te] - yhat) ** 2))
        ss_tot = float(np.sum((y[te] - y[te].mean()) ** 2))
        r2 = 1.0 - ss_res / ss_tot if ss_tot > 0 else float("nan")
        r2s.append(r2)
    return float(np.nanmean(r2s))


def _ridge_cv_accuracy(X: np.ndarray, y01: np.ndarray, lam: float = 10.0, kfold: int = 5, seed: int = 0) -> float:
    rng = np.random.default_rng(seed)
    X = np.asarray(X, dtype=float)
    y01 = np.asarray(y01, dtype=float)
    keep = np.isfinite(y01) & np.all(np.isfinite(X), axis=1)
    X = X[keep]
    y01 = y01[keep]
    n = len(y01)
    if n < kfold + 2:
        return float("nan")
    idx = np.arange(n)
    rng.shuffle(idx)
    folds = np.array_split(idx, kfold)
    accs = []
    for i in range(kfold):
        te = folds[i]
        tr = np.concatenate([folds[j] for j in range(kfold) if j != i])
        res = _ridge_fit_standardized(X[tr], y01[tr], lam=lam)
        pred = res.intercept + X[te] @ res.weights.to_numpy(float)
        yhat = (pred >= 0.5).astype(float)
        accs.append(float((yhat == y01[te]).mean()))
    return float(np.mean(accs))


def _pcr_fit(X: np.ndarray, y: np.ndarray, n_comp: int, lam: float = 0.0) -> RidgeResult:
    """
    Principal Components Regression (optionally ridge in PC space).
    Returns a linear model in original X space: y ≈ intercept + X @ beta
    """
    X = np.asarray(X, dtype=float)
    y = np.asarray(y, dtype=float)
    keep = np.isfinite(y) & np.all(np.isfinite(X), axis=1)
    X = X[keep]
    y = y[keep]
    x_mean = X.mean(axis=0)
    x_std = X.std(axis=0)
    x_std = np.where(x_std == 0, 1.0, x_std)
    Xs = (X - x_mean) / x_std
    y_mean = y.mean()
    yc = y - y_mean

    U, S, Vt = np.linalg.svd(Xs, full_matrices=False)
    r = min(n_comp, Vt.shape[0])
    Z = U[:, :r] * S[:r]  # scores
    I = np.eye(r)
    w_pc = np.linalg.solve(Z.T @ Z + lam * I, Z.T @ yc)
    beta_std = (Vt[:r].T @ w_pc)  # in standardized X space
    beta = beta_std / x_std
    intercept = y_mean - float(np.dot(x_mean, beta))
    yhat = intercept + X @ beta
    ss_res = float(np.sum((y - yhat) ** 2))
    ss_tot = float(np.sum((y - y.mean()) ** 2))
    r2 = 1.0 - ss_res / ss_tot if ss_tot > 0 else float("nan")
    return RidgeResult(weights=pd.Series(beta), intercept=intercept, r2=r2)


def _pcr_cv_r2(X: np.ndarray, y: np.ndarray, n_comp: int, lam: float = 0.0, kfold: int = 5, seed: int = 0) -> float:
    rng = np.random.default_rng(seed)
    X = np.asarray(X, dtype=float)
    y = np.asarray(y, dtype=float)
    keep = np.isfinite(y) & np.all(np.isfinite(X), axis=1)
    X = X[keep]
    y = y[keep]
    n = len(y)
    if n < kfold + 2:
        return float("nan")
    idx = np.arange(n)
    rng.shuffle(idx)
    folds = np.array_split(idx, kfold)
    r2s = []
    for i in range(kfold):
        te = folds[i]
        tr = np.concatenate([folds[j] for j in range(kfold) if j != i])
        res = _pcr_fit(X[tr], y[tr], n_comp=n_comp, lam=lam)
        yhat = res.intercept + X[te] @ res.weights.to_numpy(float)
        ss_res = float(np.sum((y[te] - yhat) ** 2))
        ss_tot = float(np.sum((y[te] - y[te].mean()) ** 2))
        r2 = 1.0 - ss_res / ss_tot if ss_tot > 0 else float("nan")
        r2s.append(r2)
    return float(np.nanmean(r2s))

def main() -> None:
    _ensure_out_dir()

    cloud = _read_df(CLOUD_CSV, "cloud")
    spec = _read_df(SPEC_CSV, "spec")

    schema = _schema_check(cloud.drop(columns=["suite"]), spec.drop(columns=["suite"]))
    (OUT_DIR / "schema_check.json").write_text(json.dumps(schema, indent=2), encoding="utf-8")

    # Basic IPC by bench (mean/std over repeats)
    def ipc_table(df: pd.DataFrame) -> pd.DataFrame:
        g = df.groupby(["suite", "bench"], dropna=False)["ipc_total"]
        out = g.agg(ipc_mean="mean", ipc_std="std", n="count").reset_index()
        return out.sort_values(["suite", "ipc_mean"], ascending=[True, False])

    ipc_all = pd.concat([ipc_table(cloud), ipc_table(spec)], ignore_index=True)
    ipc_all.to_csv(OUT_DIR / "ipc_by_bench.csv", index=False)

    # Figure: IPC by bench (horizontal bar)
    try:
        fig, ax = plt.subplots(figsize=(10, 12))
        plot = ipc_all.copy()
        plot["label"] = plot["suite"].astype(str) + " | " + plot["bench"].astype(str)
        plot = plot.sort_values(["ipc_mean"], ascending=True)
        colors = plot["suite"].map({"cloud": "#1f77b4", "spec": "#d62728"}).fillna("#7f7f7f")
        ax.barh(plot["label"], plot["ipc_mean"], color=colors)
        ax.set_xlabel("ipc_total (mean over repeats)")
        ax.set_title("IPC by bench (cloud vs spec)")
        ax.grid(True, axis="x", alpha=0.25)
        plt.tight_layout()
        fig.savefig(FIG_DIR / "ipc_by_bench.png", dpi=200)
        plt.close(fig)
    except Exception as e:
        (OUT_DIR / "figure_ipc_by_bench_error.txt").write_text(str(e), encoding="utf-8")

    # Feature columns
    feats = _numeric_feature_cols(cloud)
    # Remove features that are constant or mostly missing in either suite
    def keep_feature(c: str) -> bool:
        a = cloud[c]
        b = spec[c]
        def ok(s: pd.Series) -> bool:
            nn = s.notna().sum()
            if nn < max(3, int(0.6 * len(s))):
                return False
            return s.nunique(dropna=True) >= 2
        return ok(a) and ok(b)

    feats2 = [c for c in feats if keep_feature(c)]
    (OUT_DIR / "feature_list.json").write_text(json.dumps({"n_features": len(feats2), "features": feats2}, indent=2), encoding="utf-8")

    # Correlations with IPC (per suite)
    def corr_table(df: pd.DataFrame, suite: str) -> pd.DataFrame:
        rows = []
        for c in feats2:
            x = df[c]
            y = df["ipc_total"]
            keep = x.notna() & y.notna()
            if keep.sum() < 5:
                continue
            r = float(np.corrcoef(x[keep].to_numpy(float), y[keep].to_numpy(float))[0, 1])
            rows.append((c, r, int(keep.sum())))
        out = pd.DataFrame(rows, columns=["feature", "pearson_r", "n"]).sort_values("pearson_r", key=lambda s: s.abs(), ascending=False)
        out.to_csv(OUT_DIR / f"feature_ipc_corr_{suite}.csv", index=False)
        return out

    corr_cloud = corr_table(cloud, "cloud")
    corr_spec = corr_table(spec, "spec")

    # Ridge model per suite (predict IPC from features)
    def ridge_table(df: pd.DataFrame, suite: str, lam: float = 10.0) -> pd.DataFrame:
        X = df[feats2].to_numpy(float)
        y = df["ipc_total"].to_numpy(float)
        res = _ridge_fit_standardized(X, y, lam=lam)
        w = res.weights.copy()
        w.index = feats2
        out = pd.DataFrame(
            {
                "feature": feats2,
                "weight": w.values,
                "abs_weight": np.abs(w.values),
            }
        ).sort_values("abs_weight", ascending=False)
        meta = {"suite": suite, "lambda": lam, "r2": res.r2, "intercept": res.intercept}
        (OUT_DIR / f"ridge_meta_{suite}.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        out.to_csv(OUT_DIR / f"ridge_weights_{suite}.csv", index=False)
        return out, meta

    ridge_cloud, ridge_cloud_meta = ridge_table(cloud, "cloud", lam=10.0)
    ridge_spec, ridge_spec_meta = ridge_table(spec, "spec", lam=10.0)

    # Suite-level feature differences (effect size) based on per-bench means (reduces repeat noise)
    def bench_means(df: pd.DataFrame) -> pd.DataFrame:
        bm = df.groupby(["suite", "bench"], dropna=False)[feats2 + ["ipc_total"]].mean(numeric_only=True).reset_index()
        return bm

    bm_cloud = bench_means(cloud)
    bm_spec = bench_means(spec)

    diff_rows = []
    for c in feats2 + ["ipc_total"]:
        x = bm_cloud[c].to_numpy(float)
        y = bm_spec[c].to_numpy(float)
        d = _cohens_d(x, y)
        diff_rows.append(
            {
                "feature": c,
                "cloud_mean": float(np.nanmean(x)),
                "spec_mean": float(np.nanmean(y)),
                "cohens_d_cloud_minus_spec": d,
            }
        )
    suite_diff = pd.DataFrame(diff_rows).sort_values("cohens_d_cloud_minus_spec", key=lambda s: s.abs(), ascending=False)
    suite_diff.to_csv(OUT_DIR / "suite_feature_effect.csv", index=False)

    # PCA program portrait (all samples together)
    both = pd.concat([cloud, spec], ignore_index=True)
    both.insert(2, "workload_group", both.apply(lambda r: _workload_group(r["bench"], r["suite"]), axis=1))
    X_all = both[feats2].to_numpy(float)
    coords, comps, vr = _pca_2d(X_all)

    # coords correspond to rows that are finite across all feats2; track indices
    keep = np.all(np.isfinite(X_all), axis=1)
    pts = both.loc[keep, ["suite", "bench", "warmup_tag", "ipc_total"]].copy()
    pts.insert(2, "workload_group", both.loc[keep, "workload_group"].to_numpy())
    pts.insert(len(pts.columns), "pc1", coords[:, 0])
    pts.insert(len(pts.columns), "pc2", coords[:, 1])
    pts.to_csv(OUT_DIR / "pca_points.csv", index=False)
    (OUT_DIR / "pca_meta.json").write_text(
        json.dumps({"pc1_var_ratio": float(vr[0]), "pc2_var_ratio": float(vr[1]), "n_points": int(len(pts))}, indent=2),
        encoding="utf-8",
    )

    # Figure: PCA scatter (colored by suite)
    try:
        fig, ax = plt.subplots(figsize=(8, 6))
        for suite_name, color in [("cloud", "#1f77b4"), ("spec", "#d62728")]:
            m = pts["suite"] == suite_name
            ax.scatter(pts.loc[m, "pc1"], pts.loc[m, "pc2"], s=28, alpha=0.75, label=suite_name, color=color, edgecolors="none")
        ax.set_xlabel(f"PC1 ({vr[0]*100:.1f}% var)")
        ax.set_ylabel(f"PC2 ({vr[1]*100:.1f}% var)")
        ax.set_title("Program portrait (PCA 2D) — colored by suite")
        ax.grid(True, alpha=0.2)
        ax.legend(frameon=False)
        plt.tight_layout()
        fig.savefig(FIG_DIR / "pca_suite_scatter.png", dpi=200)
        plt.close(fig)
    except Exception as e:
        (OUT_DIR / "figure_pca_suite_error.txt").write_text(str(e), encoding="utf-8")

    # Family summary: how much each family correlates with IPC (max abs corr)
    fam_summary_rows = []
    for suite_name, df in [("cloud", cloud), ("spec", spec)]:
        corr = corr_cloud if suite_name == "cloud" else corr_spec
        corr_map = dict(zip(corr["feature"], corr["pearson_r"]))
        for fam, rx in FEATURE_FAMILIES:
            fam_cols = _family_cols(feats2, rx)
            if not fam_cols:
                continue
            vals = [abs(corr_map.get(c, float("nan"))) for c in fam_cols]
            vals = [v for v in vals if np.isfinite(v)]
            fam_summary_rows.append(
                {
                    "suite": suite_name,
                    "family": fam,
                    "n_features": len(fam_cols),
                    "max_abs_pearson_r": float(max(vals)) if vals else float("nan"),
                }
            )
    fam_summary = pd.DataFrame(fam_summary_rows).sort_values(["suite", "max_abs_pearson_r"], ascending=[True, False])
    fam_summary.to_csv(OUT_DIR / "family_corr_summary.csv", index=False)

    # Unified modeling & separability checks
    # Use bench-level means to reduce replicate noise when comparing suites/configurations.
    bench_means_all = both.groupby(["suite", "bench", "workload_group"], dropna=False)[feats2 + ["ipc_total"]].mean(numeric_only=True).reset_index()
    bench_means_all.to_csv(OUT_DIR / "bench_means.csv", index=False)

    Xb = bench_means_all[feats2].to_numpy(float)
    yb_ipc = bench_means_all["ipc_total"].to_numpy(float)

    # Standardize for clustering / classification
    x_mean = np.nanmean(Xb, axis=0)
    x_std = np.nanstd(Xb, axis=0)
    x_std = np.where(x_std == 0, 1.0, x_std)
    Xb_z = (Xb - x_mean) / x_std
    keep_b = np.all(np.isfinite(Xb_z), axis=1) & np.isfinite(yb_ipc)
    Xb_z = Xb_z[keep_b]
    bench_means_kept = bench_means_all.loc[keep_b].reset_index(drop=True)
    yb_ipc = yb_ipc[keep_b]

    # Explainability: unified ridge CV R² (tune lambda)
    lam_grid = [1.0, 10.0, 100.0, 1_000.0, 10_000.0, 100_000.0]
    cv_rows = []
    for lam in lam_grid:
        cv_rows.append({"lambda": lam, "cv_r2": _ridge_cv_r2(Xb_z, yb_ipc, lam=lam, kfold=5, seed=0)})
    cv_df = pd.DataFrame(cv_rows).sort_values("cv_r2", ascending=False)
    cv_df.to_csv(OUT_DIR / "unified_ipc_cv_grid.csv", index=False)
    best = cv_df.iloc[0].to_dict()
    (OUT_DIR / "unified_ipc_cv.json").write_text(
        json.dumps({"kfold": 5, "best_lambda": float(best["lambda"]), "best_cv_r2": float(best["cv_r2"])}, indent=2),
        encoding="utf-8",
    )

    # Dimensionality reduction: PCR (PCA + linear regression) CV R²
    ncomp_grid = [2, 5, 10, 20]
    pcr_rows = []
    for nc in ncomp_grid:
        pcr_rows.append({"n_components": nc, "cv_r2": _pcr_cv_r2(Xb_z, yb_ipc, n_comp=nc, lam=0.0, kfold=5, seed=0)})
    pcr_df = pd.DataFrame(pcr_rows).sort_values("cv_r2", ascending=False)
    pcr_df.to_csv(OUT_DIR / "unified_ipc_pcr_cv_grid.csv", index=False)
    pcr_best = pcr_df.iloc[0].to_dict()
    (OUT_DIR / "unified_ipc_pcr_cv.json").write_text(
        json.dumps({"kfold": 5, "best_n_components": int(pcr_best["n_components"]), "best_cv_r2": float(pcr_best["cv_r2"])}, indent=2),
        encoding="utf-8",
    )

    # Cross-suite transfer: train on cloud, test on spec (and reverse), using ridge
    def transfer_r2(train_suite: str, test_suite: str, lam: float = 1000.0) -> float:
        tr = bench_means_kept["suite"] == train_suite
        te = bench_means_kept["suite"] == test_suite
        if tr.sum() < 5 or te.sum() < 5:
            return float("nan")
        res = _ridge_fit_standardized(Xb_z[tr.to_numpy()], yb_ipc[tr.to_numpy()], lam=lam)
        yhat = res.intercept + Xb_z[te.to_numpy()] @ res.weights.to_numpy(float)
        y = yb_ipc[te.to_numpy()]
        ss_res = float(np.sum((y - yhat) ** 2))
        ss_tot = float(np.sum((y - y.mean()) ** 2))
        return 1.0 - ss_res / ss_tot if ss_tot > 0 else float("nan")

    transfer = {
        "lambda": 1000.0,
        "cloud_to_spec_r2": transfer_r2("cloud", "spec", lam=1000.0),
        "spec_to_cloud_r2": transfer_r2("spec", "cloud", lam=1000.0),
    }
    (OUT_DIR / "ipc_transfer_r2.json").write_text(json.dumps(transfer, indent=2), encoding="utf-8")

    # Can features distinguish suite? (cloud vs spec) via ridge classifier
    y_suite01 = (bench_means_kept["suite"].to_numpy() == "spec").astype(float)
    suite_cv_acc = _ridge_cv_accuracy(Xb_z, y_suite01, lam=10.0, kfold=5, seed=1)
    (OUT_DIR / "suite_separability.json").write_text(
        json.dumps({"ridge_lambda": 10.0, "kfold": 5, "cv_accuracy": suite_cv_acc}, indent=2),
        encoding="utf-8",
    )

    # Clustering on unified (bench-means) features and compute purity vs suite and workload_group
    k = 6 if len(bench_means_kept) >= 12 else max(2, len(bench_means_kept) // 2)
    labels_km, _ = _kmeans(Xb_z, k=k, seed=0, n_iter=200)
    bench_means_kept = bench_means_kept.copy()
    bench_means_kept["cluster"] = labels_km
    bench_means_kept.to_csv(OUT_DIR / "bench_means_with_clusters.csv", index=False)
    purity_suite = _cluster_purity(labels_km, bench_means_kept["suite"].to_numpy())
    purity_group = _cluster_purity(labels_km, bench_means_kept["workload_group"].to_numpy())
    (OUT_DIR / "clustering_summary.json").write_text(
        json.dumps({"kmeans_k": int(k), "purity_suite": purity_suite, "purity_workload_group": purity_group}, indent=2),
        encoding="utf-8",
    )

    # Figure: bench-mean portrait + clusters (make it readable: avoid per-point labels)
    try:
        # Recompute PCA basis on bench-means (clean and stable for this plot)
        Xbm = bench_means_kept[feats2].to_numpy(float)
        mean_bm = Xbm.mean(axis=0)
        std_bm = Xbm.std(axis=0)
        std_bm = np.where(std_bm == 0, 1.0, std_bm)
        Xbm_z = (Xbm - mean_bm) / std_bm
        U, S, Vt = np.linalg.svd(Xbm_z, full_matrices=False)
        coords_bm = Xbm_z @ Vt[:2].T

        # Prepare styling
        dfp = bench_means_kept.reset_index(drop=True).copy()
        dfp["x"] = coords_bm[:, 0]
        dfp["y"] = coords_bm[:, 1]

        # Color by workload_group (more interpretable than cluster id)
        groups = list(pd.unique(dfp["workload_group"].astype(str)))
        cmap = plt.get_cmap("tab20")
        group_color = {g: cmap(i % 20) for i, g in enumerate(sorted(groups))}
        colors = dfp["workload_group"].astype(str).map(group_color).to_list()

        # A) Clean version (no text, with legend for workload colors)
        fig, ax = plt.subplots(figsize=(8.8, 6.6))
        for suite_name, marker in [("cloud", "o"), ("spec", "s")]:
            m = dfp["suite"] == suite_name
            ax.scatter(
                dfp.loc[m, "x"],
                dfp.loc[m, "y"],
                c=np.array(colors, dtype=object)[m.to_numpy()],
                s=70,
                marker=marker,
                alpha=0.88,
                edgecolors="white",
                linewidths=0.6,
                label=f"suite={suite_name}",
            )
        ax.set_xlabel("BM-PC1")
        ax.set_ylabel("BM-PC2")
        ax.set_title("Bench-mean portrait (color=workload_group, shape=suite)")
        ax.grid(True, alpha=0.18)
        # Suite legend
        leg1 = ax.legend(frameon=False, loc="upper right", title="suite")
        ax.add_artist(leg1)
        # Workload legend (many entries): put outside
        handles = [
            plt.Line2D([0], [0], marker="o", color="none", markerfacecolor=group_color[g], markersize=8, label=g)
            for g in sorted(groups)
        ]
        ax.legend(
            handles=handles,
            frameon=False,
            loc="center left",
            bbox_to_anchor=(1.02, 0.5),
            title="workload_group (color)",
        )
        plt.tight_layout()
        fig.savefig(FIG_DIR / "benchmean_clusters_clean.png", dpi=220)
        plt.close(fig)

        # B) Annotated version: label each workload_group once at its centroid
        fig, ax = plt.subplots(figsize=(9.6, 7.2))
        for suite_name, marker in [("cloud", "o"), ("spec", "s")]:
            m = dfp["suite"] == suite_name
            ax.scatter(
                dfp.loc[m, "x"],
                dfp.loc[m, "y"],
                c=np.array(colors, dtype=object)[m.to_numpy()],
                s=80,
                marker=marker,
                alpha=0.85,
                edgecolors="white",
                linewidths=0.7,
                label=f"suite={suite_name}",
            )

        cent = (
            dfp.groupby(["suite", "workload_group"], dropna=False)[["x", "y"]]
            .mean()
            .reset_index()
        )
        for _, r in cent.iterrows():
            txt = str(r["workload_group"])
            ax.annotate(
                txt,
                (float(r["x"]), float(r["y"])),
                fontsize=9,
                alpha=0.8,
                ha="center",
                va="center",
                bbox=dict(boxstyle="round,pad=0.18", fc="white", ec="none", alpha=0.65),
            )

        ax.set_xlabel("BM-PC1")
        ax.set_ylabel("BM-PC2")
        ax.set_title("Bench-mean portrait (labels at group centroids)")
        ax.grid(True, alpha=0.18)
        leg1 = ax.legend(frameon=False, loc="upper right", title="suite")
        ax.add_artist(leg1)
        handles = [
            plt.Line2D([0], [0], marker="o", color="none", markerfacecolor=group_color[g], markersize=8, label=g)
            for g in sorted(groups)
        ]
        ax.legend(
            handles=handles,
            frameon=False,
            loc="center left",
            bbox_to_anchor=(1.02, 0.5),
            title="workload_group (color)",
        )
        plt.tight_layout()
        fig.savefig(FIG_DIR / "benchmean_clusters.png", dpi=220)
        plt.close(fig)
    except Exception as e:
        (OUT_DIR / "figure_benchmean_clusters_error.txt").write_text(str(e), encoding="utf-8")

    # Similarity among cloud configs within the same service group vs between groups (on bench means)
    cloud_bm = bench_means_kept[bench_means_kept["suite"] == "cloud"].reset_index(drop=True)
    if len(cloud_bm) >= 3:
        Xc = cloud_bm[feats2].to_numpy(float)
        Xc = (Xc - np.nanmean(Xc, axis=0)) / np.where(np.nanstd(Xc, axis=0) == 0, 1.0, np.nanstd(Xc, axis=0))
        keep_c = np.all(np.isfinite(Xc), axis=1)
        Xc = Xc[keep_c]
        cloud_bm = cloud_bm.loc[keep_c].reset_index(drop=True)
        # pairwise distances
        dists = []
        for i in range(len(cloud_bm)):
            for j in range(i + 1, len(cloud_bm)):
                di = float(np.linalg.norm(Xc[i] - Xc[j]))
                same = cloud_bm.loc[i, "workload_group"] == cloud_bm.loc[j, "workload_group"]
                dists.append({"i": int(i), "j": int(j), "bench_i": cloud_bm.loc[i, "bench"], "bench_j": cloud_bm.loc[j, "bench"], "same_group": bool(same), "dist": di})
        dist_df = pd.DataFrame(dists)
        dist_df.to_csv(OUT_DIR / "cloud_pairwise_dist.csv", index=False)
        same = dist_df[dist_df["same_group"]]["dist"].to_numpy(float)
        diff = dist_df[~dist_df["same_group"]]["dist"].to_numpy(float)
        cloud_sim = {
            "pairs_total": int(len(dist_df)),
            "same_group_pairs": int((dist_df["same_group"]).sum()),
            "diff_group_pairs": int((~dist_df["same_group"]).sum()),
            "same_group_dist_mean": float(np.nanmean(same)) if len(same) else float("nan"),
            "diff_group_dist_mean": float(np.nanmean(diff)) if len(diff) else float("nan"),
        }
        (OUT_DIR / "cloud_similarity.json").write_text(json.dumps(cloud_sim, indent=2), encoding="utf-8")

        # Figure: same-group vs diff-group distance (boxplot)
        try:
            same_d = dist_df[dist_df["same_group"]]["dist"].to_numpy(float)
            diff_d = dist_df[~dist_df["same_group"]]["dist"].to_numpy(float)
            fig, ax = plt.subplots(figsize=(6, 5))
            ax.boxplot([same_d, diff_d], tick_labels=["same service", "different service"], showfliers=False)
            ax.set_ylabel("L2 distance in standardized feature space")
            ax.set_title("Cloud config similarity: within vs across service groups")
            ax.grid(True, axis="y", alpha=0.25)
            plt.tight_layout()
            fig.savefig(FIG_DIR / "cloud_similarity_box.png", dpi=200)
            plt.close(fig)
        except Exception as e:
            (OUT_DIR / "figure_cloud_similarity_error.txt").write_text(str(e), encoding="utf-8")

    # Markdown report
    def topn(df: pd.DataFrame, n: int = 12) -> pd.DataFrame:
        return df.head(n).copy()

    def df_to_md(df: pd.DataFrame, max_rows: int = 12) -> str:
        if df.empty:
            return "_(empty)_\n"
        d = df.head(max_rows).copy()
        # Avoid pandas.to_markdown() which depends on optional 'tabulate'.
        cols = list(d.columns)
        # Convert to strings with reasonable formatting
        def fmt(v) -> str:
            if v is None or (isinstance(v, float) and (math.isnan(v) or math.isinf(v))):
                return ""
            if isinstance(v, (float, np.floating)):
                # Keep small scientific values readable
                av = abs(float(v))
                if av != 0 and (av < 1e-4 or av >= 1e5):
                    return f"{float(v):.3e}"
                return f"{float(v):.6g}"
            return str(v)

        rows = [[fmt(v) for v in row] for row in d.to_numpy()]
        widths = [len(c) for c in cols]
        for r in rows:
            for i, cell in enumerate(r):
                widths[i] = max(widths[i], len(cell))

        def line(items: list[str]) -> str:
            return "| " + " | ".join(it.ljust(widths[i]) for i, it in enumerate(items)) + " |\n"

        out = ""
        out += line(cols)
        out += "| " + " | ".join(("-" * widths[i]) for i in range(len(cols))) + " |\n"
        for r in rows:
            out += line(r)
        out += "\n"
        return out

    report = []
    report.append("# Cloud vs SPEC5 Instruction-Feature Analysis\n")
    report.append("## 1) Schema / Dimension Check\n")
    report.append(f"- **cloud columns**: {schema['a_cols']}\n")
    report.append(f"- **spec columns**: {schema['b_cols']}\n")
    report.append(f"- **exact same columns (order too)**: {schema['same_order']}\n")
    report.append("\n")

    report.append("## 2) Dataset Size & IPC Overview\n")
    report.append(f"- **cloud samples**: {len(cloud)} (unique bench: {cloud['bench'].nunique()})\n")
    report.append(f"- **spec samples**: {len(spec)} (unique bench: {spec['bench'].nunique()})\n")
    report.append("\n")
    report.append("### IPC by bench (mean over repeats)\n\n")
    report.append("![IPC by bench](figures/ipc_by_bench.png)\n\n")
    report.append(df_to_md(ipc_all, max_rows=40))

    report.append("## 3) Which features differ most between suites?\n")
    report.append("Effect size is computed on **per-bench means** (Cohen's d, cloud minus spec). Larger |d| means stronger separation.\n\n")
    report.append(df_to_md(suite_diff[["feature", "cloud_mean", "spec_mean", "cohens_d_cloud_minus_spec"]], max_rows=25))

    report.append("## 4) IPC impact: correlations (per suite)\n")
    report.append("Top features by absolute Pearson correlation with `ipc_total`.\n\n")
    report.append("### Cloud\n\n")
    report.append(df_to_md(topn(corr_cloud), max_rows=15))
    report.append("### SPEC\n\n")
    report.append(df_to_md(topn(corr_spec), max_rows=15))

    report.append("## 5) IPC impact: ridge linear model (per suite)\n")
    report.append("Closed-form ridge regression on all numeric features (after filtering constant/mostly-missing), predicting `ipc_total`.\n\n")
    report.append(f"- **cloud ridge R²**: {ridge_cloud_meta['r2']:.4f}\n")
    report.append(f"- **spec ridge R²**: {ridge_spec_meta['r2']:.4f}\n\n")
    report.append("### Cloud top weights (|weight|)\n\n")
    report.append(df_to_md(ridge_cloud[["feature", "weight", "abs_weight"]], max_rows=15))
    report.append("### SPEC top weights (|weight|)\n\n")
    report.append(df_to_md(ridge_spec[["feature", "weight", "abs_weight"]], max_rows=15))

    report.append("## 6) Program portrait (PCA 2D)\n")
    report.append("A 2D embedding computed from standardized features (rows with finite values across all used features).\n\n")
    report.append("![PCA suite scatter](figures/pca_suite_scatter.png)\n\n")
    pca_meta = json.loads((OUT_DIR / "pca_meta.json").read_text(encoding="utf-8"))
    report.append(f"- **points**: {pca_meta['n_points']}\n")
    report.append(f"- **PC1 variance ratio**: {pca_meta['pc1_var_ratio']:.4f}\n")
    report.append(f"- **PC2 variance ratio**: {pca_meta['pc2_var_ratio']:.4f}\n\n")
    report.append("- Output table: `outputs/analysis/pca_points.csv`\n\n")

    report.append("## 7) Family-level summary\n")
    report.append("For each suite & feature family, shows the **max |corr| with IPC** among features in that family.\n\n")
    report.append(df_to_md(fam_summary, max_rows=50))

    report.append("## 8) Unified modeling & separability (bench-mean level)\n")
    report.append("To integrate cloud+spec in a single model fairly, we compute **per-bench means** and run analyses on those points.\n\n")
    uni = json.loads((OUT_DIR / "unified_ipc_cv.json").read_text(encoding="utf-8"))
    uni_pcr = json.loads((OUT_DIR / "unified_ipc_pcr_cv.json").read_text(encoding="utf-8"))
    trn = json.loads((OUT_DIR / "ipc_transfer_r2.json").read_text(encoding="utf-8"))
    sep = json.loads((OUT_DIR / "suite_separability.json").read_text(encoding="utf-8"))
    clu = json.loads((OUT_DIR / "clustering_summary.json").read_text(encoding="utf-8"))
    report.append(f"- **Unified IPC explainability (ridge, 5-fold CV best R²)**: {uni['best_cv_r2']:.4f} (lambda={uni['best_lambda']:.0f})\n")
    report.append(f"- **Unified IPC explainability (PCR, 5-fold CV best R²)**: {uni_pcr['best_cv_r2']:.4f} (n_components={uni_pcr['best_n_components']})\n")
    report.append(f"- **Can features separate cloud vs spec? (ridge classifier, 5-fold CV accuracy)**: {sep['cv_accuracy']:.4f}\n")
    report.append(f"- **KMeans clusters (k={clu['kmeans_k']}) purity vs suite**: {clu['purity_suite']:.4f}\n")
    report.append(f"- **KMeans clusters (k={clu['kmeans_k']}) purity vs workload_group**: {clu['purity_workload_group']:.4f}\n\n")
    report.append("![Bench-mean clusters](figures/benchmean_clusters.png)\n\n")
    report.append("### Cross-suite IPC prediction (distribution shift check)\n\n")
    report.append(f"- **train cloud → test spec (R²)**: {trn['cloud_to_spec_r2']:.4f}\n")
    report.append(f"- **train spec → test cloud (R²)**: {trn['spec_to_cloud_r2']:.4f}\n\n")

    cloud_sim_path = OUT_DIR / "cloud_similarity.json"
    if cloud_sim_path.exists():
        cs = json.loads(cloud_sim_path.read_text(encoding="utf-8"))
        report.append("### Cloud configs: are they more similar within the same service?\n\n")
        report.append("![Cloud similarity](figures/cloud_similarity_box.png)\n\n")
        report.append(f"- **mean feature-space distance (same service group)**: {cs['same_group_dist_mean']:.4f}\n")
        report.append(f"- **mean feature-space distance (different service groups)**: {cs['diff_group_dist_mean']:.4f}\n\n")

    report.append("## 9) Output files\n")
    report.append("- `outputs/analysis/REPORT.md`\n")
    report.append("- `outputs/analysis/schema_check.json`\n")
    report.append("- `outputs/analysis/ipc_by_bench.csv`\n")
    report.append("- `outputs/analysis/suite_feature_effect.csv`\n")
    report.append("- `outputs/analysis/feature_ipc_corr_cloud.csv`, `outputs/analysis/feature_ipc_corr_spec.csv`\n")
    report.append("- `outputs/analysis/ridge_weights_cloud.csv`, `outputs/analysis/ridge_weights_spec.csv`\n")
    report.append("- `outputs/analysis/ridge_meta_cloud.json`, `outputs/analysis/ridge_meta_spec.json`\n")
    report.append("- `outputs/analysis/pca_points.csv`, `outputs/analysis/pca_meta.json`\n")
    report.append("- `outputs/analysis/family_corr_summary.csv`\n")
    report.append("- `outputs/analysis/bench_means.csv`\n")
    report.append("- `outputs/analysis/unified_ipc_cv.json`\n")
    report.append("- `outputs/analysis/unified_ipc_cv_grid.csv`\n")
    report.append("- `outputs/analysis/unified_ipc_pcr_cv.json`, `outputs/analysis/unified_ipc_pcr_cv_grid.csv`\n")
    report.append("- `outputs/analysis/ipc_transfer_r2.json`\n")
    report.append("- `outputs/analysis/suite_separability.json`\n")
    report.append("- `outputs/analysis/bench_means_with_clusters.csv`, `outputs/analysis/clustering_summary.json`\n")
    report.append("- `outputs/analysis/cloud_pairwise_dist.csv`, `outputs/analysis/cloud_similarity.json` (if cloud benches exist)\n")
    report.append("\n")
    report.append("## 10) Figures\n")
    report.append("- `outputs/analysis/figures/ipc_by_bench.png`\n")
    report.append("- `outputs/analysis/figures/pca_suite_scatter.png`\n")
    report.append("- `outputs/analysis/figures/benchmean_clusters.png`\n")
    report.append("- `outputs/analysis/figures/benchmean_clusters_clean.png`\n")
    report.append("- `outputs/analysis/figures/cloud_similarity_box.png` (cloud only)\n")

    (OUT_DIR / "REPORT.md").write_text("".join(report), encoding="utf-8")

    print("Wrote analysis to", OUT_DIR)


if __name__ == "__main__":
    main()

