#!/usr/bin/env python3
from __future__ import annotations

"""
Micro-architecture independent (MIIC) analytical performance model.

This is a *new* backend that consumes existing artifacts produced by the current
perf+intel_pt pipeline:
  - *.perf.recovered.data.analysis.json (data locality w/ RD histogram)
  - *.perf.inst.analysis.json           (instruction locality w/ RD histogram)
  - *.insn.portrait.json                (instruction mix / branch stats / IPC annotation)

It implements a lightweight interval-style cycle stack inspired by:
  "Analytical Processor Performance and Power Modeling Using Micro-Architecture
   Independent Characteristics" (IEEE TC 2016).

Scope (pragmatic for this repo):
  - Use RD/stack-distance distributions to derive cache miss ratios for arbitrary
    LRU cache sizes (in lines).
  - Use portrait branch entropy to estimate branch miss rate (configurable mapping).
  - Compute a CPI stack with: base + branch + i-cache + d-cache (+ optional bus).
  - MLP, load-dependence distributions, and ROB-dependent critical path modeling
    are left as configurable simplifications for now (defaults are conservative).
"""

import dataclasses
import json
import math
from pathlib import Path
from typing import Any, Iterable


@dataclasses.dataclass(frozen=True)
class CacheLevel:
    name: str
    size_bytes: int
    assoc: int
    latency_cycles: float

    def lines(self, line_size: int) -> int:
        if line_size <= 0:
            return 0
        return max(0, int(self.size_bytes // line_size))


@dataclasses.dataclass(frozen=True)
class CpuSprLikeConfig:
    """
    A reasonable starting point for an Intel Sapphire Rapids-like core+cache.

    Notes:
      - Latencies are *approximate* and intentionally configurable. The model is
        primarily for what-if sensitivity and relative comparisons across configs.
      - The original paper models many additional effects (MLP, bandwidth, chained LLC hits,
        ROB effects). We keep the core skeleton and wire it to features we can extract today.
    """

    line_size: int = 64
    dispatch_width: int = 6

    # Caches (private L1I/L1D, private L2, shared LLC/L3)
    l1i: CacheLevel = CacheLevel("L1I", 48 * 1024, 12, 1.0)
    l1d: CacheLevel = CacheLevel("L1D", 48 * 1024, 12, 4.0)
    l2: CacheLevel = CacheLevel("L2", 2 * 1024 * 1024, 16, 14.0)
    l3: CacheLevel = CacheLevel("L3", 30 * 1024 * 1024, 12, 42.0)

    mem_latency_cycles: float = 220.0

    # Branch model knobs (entropy -> miss rate mapping)
    branch_miss_slope: float = 0.20  # miss_rate ≈ slope * entropy
    branch_miss_bias: float = 0.00
    branch_miss_rate_cap: float = 0.30
    branch_penalty_cycles: float = 16.0  # effective mispredict penalty (resolution + frontend refill)

    # Memory-level parallelism (MLP) simplification for now.
    mlp: float = 1.0


def _safe_float(x: Any, default: float = 0.0) -> float:
    try:
        v = float(x)
        if math.isfinite(v):
            return v
    except Exception:
        pass
    return float(default)


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _pick(obj: dict[str, Any], keys: Iterable[str], *, default: float = 0.0) -> float:
    for k in keys:
        if k in obj:
            return _safe_float(obj.get(k), default=default)
    return float(default)


def rd_miss_ratio_from_feature(feature: dict[str, Any], *, cache_lines: int) -> float:
    """
    Compute miss ratio for an LRU cache given a stack-distance / RD histogram.

    We expect:
      feature["rd_bins"]  like ["1","2","3-4",...,"131073-262144",">=262144"]
      feature["rd_prob"]  probabilities for each bin, summing ~1.

    Assumption:
      rd_bins are in *cache lines* (the existing pipeline uses --analysis-line-size).
    """
    if cache_lines <= 0:
        return 1.0
    bins = feature.get("rd_bins")
    prob = feature.get("rd_prob")
    if not isinstance(bins, list) or not isinstance(prob, list) or not bins or len(bins) != len(prob):
        return 0.0

    def bin_low_high(b: str) -> tuple[int, int | None]:
        t = str(b).strip()
        if t.startswith(">="):
            lo = int(t[2:].strip())
            return lo, None
        if "-" in t:
            a, c = t.split("-", 1)
            return int(a.strip()), int(c.strip())
        return int(t), int(t)

    miss = 0.0
    for b, p in zip(bins, prob):
        pp = _safe_float(p, default=0.0)
        if pp <= 0:
            continue
        try:
            lo, hi = bin_low_high(str(b))
        except Exception:
            continue
        # Any stack distance strictly greater than cache size is a miss.
        if hi is None:
            if lo > cache_lines:
                miss += pp
        else:
            if lo > cache_lines:
                miss += pp
            elif hi <= cache_lines:
                continue
            else:
                # Partial overlap: approximate with uniform distribution in [lo, hi].
                span = max(1, hi - lo + 1)
                over = max(0, hi - cache_lines)
                miss += pp * (over / span)
    return max(0.0, min(1.0, miss))


def extract_locality_feature_from_analysis_json(path: Path, *, access: str = "all") -> dict[str, Any]:
    obj = _load_json(path)
    per = obj.get("per_access", {})
    if not isinstance(per, dict):
        return {}
    aobj = per.get(access)
    if not isinstance(aobj, dict):
        return {}
    feat = aobj.get("feature")
    return feat if isinstance(feat, dict) else {}


def load_portrait_flat(path: Path) -> dict[str, float]:
    """
    Use the existing portrait JSON format; keep dependency on the repo local.
    """
    # Local import to keep this module usable standalone.
    import analyze_insn_trace_portrait as insn_portrait  # type: ignore

    obj = _load_json(path)
    flat = insn_portrait.flatten_portrait_metrics(obj)
    out: dict[str, float] = {}
    for k, v in flat.items():
        if isinstance(v, (int, float)):
            fv = float(v)
            if math.isfinite(fv):
                out[k] = fv
    return out


@dataclasses.dataclass(frozen=True)
class MiicInputs:
    n_instructions: float
    # Fractions (0..1) and rates
    load_frac: float
    store_frac: float
    cond_branch_per_1k: float
    branch_taken_entropy: float
    # Locality features
    data_feature: dict[str, Any]
    inst_feature: dict[str, Any]


def build_miic_inputs(
    *,
    data_analysis_json: Path,
    inst_analysis_json: Path,
    portrait_json: Path | None,
    access: str = "all",
) -> MiicInputs:
    data_feat = extract_locality_feature_from_analysis_json(data_analysis_json, access=access)
    inst_feat = extract_locality_feature_from_analysis_json(inst_analysis_json, access=access) if inst_analysis_json.is_file() else {}
    flat = load_portrait_flat(portrait_json) if portrait_json is not None and portrait_json.is_file() else {}

    n = _pick(flat, ("portrait_parsed_instructions",), default=0.0)
    # Operand mix is the best proxy we have for memory traffic today.
    load_frac = _pick(flat, ("portrait_opmix_mem_to_reg",), default=0.0)
    store_frac = _pick(flat, ("portrait_opmix_reg_to_mem", "portrait_opmix_imm_to_mem"), default=0.0)
    # Clamp and renormalize lightly.
    load_frac = max(0.0, min(1.0, load_frac))
    store_frac = max(0.0, min(1.0, store_frac))

    cond_per_1k = _pick(flat, ("portrait_branch_conditional_per_1k",), default=0.0)
    taken_entropy = _pick(flat, ("portrait_branch_taken_entropy",), default=0.0)

    return MiicInputs(
        n_instructions=float(n),
        load_frac=float(load_frac),
        store_frac=float(store_frac),
        cond_branch_per_1k=float(cond_per_1k),
        branch_taken_entropy=float(taken_entropy),
        data_feature=data_feat,
        inst_feature=inst_feat,
    )


@dataclasses.dataclass(frozen=True)
class MiicPrediction:
    cycles: float
    ipc: float
    cpi: float
    stack: dict[str, float]  # named cycle components
    derived: dict[str, float]  # useful intermediate metrics


def predict_interval_cycles(inputs: MiicInputs, *, cfg: CpuSprLikeConfig) -> MiicPrediction:
    N = max(0.0, float(inputs.n_instructions))
    if N <= 0:
        return MiicPrediction(
            cycles=float("nan"),
            ipc=float("nan"),
            cpi=float("nan"),
            stack={"error_no_instructions": 1.0},
            derived={},
        )

    line = int(cfg.line_size)
    l1i_lines = cfg.l1i.lines(line)
    l1d_lines = cfg.l1d.lines(line)
    l2_lines = cfg.l2.lines(line)
    l3_lines = cfg.l3.lines(line)

    # Miss ratios from RD histograms (assume they reflect stack distance in lines).
    mr_i_l1 = rd_miss_ratio_from_feature(inputs.inst_feature, cache_lines=l1i_lines)
    mr_i_l2 = rd_miss_ratio_from_feature(inputs.inst_feature, cache_lines=l2_lines)
    mr_i_l3 = rd_miss_ratio_from_feature(inputs.inst_feature, cache_lines=l3_lines)

    mr_d_l1 = rd_miss_ratio_from_feature(inputs.data_feature, cache_lines=l1d_lines)
    mr_d_l2 = rd_miss_ratio_from_feature(inputs.data_feature, cache_lines=l2_lines)
    mr_d_l3 = rd_miss_ratio_from_feature(inputs.data_feature, cache_lines=l3_lines)

    # Convert ratios to counts. We only have fractions, so estimate accesses as fractions of N.
    # This is intentionally simple; if you later want better load/store counts, we can plumb
    # them from the recovered mem JSONL stream.
    n_load = N * max(0.0, min(1.0, inputs.load_frac))
    n_store = N * max(0.0, min(1.0, inputs.store_frac))
    n_data = n_load + n_store

    m_i_l1 = N * mr_i_l1
    m_i_l2 = N * mr_i_l2
    m_i_l3 = N * mr_i_l3

    m_d_l1 = n_data * mr_d_l1
    m_d_l2 = n_data * mr_d_l2
    m_d_l3 = n_data * mr_d_l3

    # Inclusive-ish decomposition: L1 misses that hit in L2, L2 misses that hit in L3, etc.
    def decomp(m1: float, m2: float, m3: float) -> tuple[float, float, float]:
        hit_l2 = max(0.0, m1 - m2)
        hit_l3 = max(0.0, m2 - m3)
        hit_mem = max(0.0, m3)
        return hit_l2, hit_l3, hit_mem

    i_l2, i_l3, i_mem = decomp(m_i_l1, m_i_l2, m_i_l3)
    d_l2, d_l3, d_mem = decomp(m_d_l1, m_d_l2, m_d_l3)

    # Base: assume effective dispatch is dispatch_width.
    Deff = max(1e-9, float(cfg.dispatch_width))
    base = N / Deff

    # I-cache penalty: each miss costs next-level latency (simplified).
    p_icache = i_l2 * cfg.l2.latency_cycles + i_l3 * cfg.l3.latency_cycles + i_mem * cfg.mem_latency_cycles

    # D-cache penalty: similarly. Apply MLP division for memory component only (simple).
    mlp = max(1.0, float(cfg.mlp))
    p_dcache = (
        d_l2 * cfg.l2.latency_cycles
        + d_l3 * cfg.l3.latency_cycles
        + (d_mem * cfg.mem_latency_cycles) / mlp
    )

    # Branch penalty: miss rate from entropy mapping, miss count from conditional branches per 1k.
    br_entropy = max(0.0, min(1.0, float(inputs.branch_taken_entropy)))
    br_miss_rate = cfg.branch_miss_bias + cfg.branch_miss_slope * br_entropy
    br_miss_rate = max(0.0, min(float(cfg.branch_miss_rate_cap), br_miss_rate))
    n_cond_br = (max(0.0, float(inputs.cond_branch_per_1k)) / 1000.0) * N
    m_bpred = n_cond_br * br_miss_rate
    p_branch = m_bpred * float(cfg.branch_penalty_cycles)

    cycles = base + p_branch + p_icache + p_dcache
    ipc = (N / cycles) if cycles > 0 else float("nan")
    cpi = (cycles / N) if N > 0 else float("nan")

    stack = {
        "base": base,
        "branch": p_branch,
        "icache": p_icache,
        "dcache": p_dcache,
    }
    derived = {
        "N": N,
        "Deff": Deff,
        "branch_entropy": br_entropy,
        "branch_miss_rate_est": br_miss_rate,
        "cond_branches_est": n_cond_br,
        "branch_misses_est": m_bpred,
        "n_data_accesses_est": n_data,
        "mr_i_l1": mr_i_l1,
        "mr_i_l2": mr_i_l2,
        "mr_i_l3": mr_i_l3,
        "mr_d_l1": mr_d_l1,
        "mr_d_l2": mr_d_l2,
        "mr_d_l3": mr_d_l3,
        "l1i_lines": float(l1i_lines),
        "l1d_lines": float(l1d_lines),
        "l2_lines": float(l2_lines),
        "l3_lines": float(l3_lines),
        "mlp": float(mlp),
    }
    return MiicPrediction(cycles=float(cycles), ipc=float(ipc), cpi=float(cpi), stack=stack, derived=derived)

