#!/usr/bin/env python3
"""
SPEC CPU 5xx: Intel PT capture + locality feature extraction (no SDE, no SDE-vs-perf compare).

Runs the same perf path as `run_spec5_sde_perf_similarity.py --no-enable-sde`:
  launch benchmark → perf record → perf script --insn-trace → recover_mem_addrs_uc
  → `*.perf.*.analysis.json` under each case's `report/`.

For SDE reference traces and similarity scores against SDE, use:
  `run_spec5_sde_perf_similarity.py` (default enables SDE + compare_mem_trace_metrics).

Outputs:
  `--output-base/<bench>/<warmup_tag>/` per case, plus `summary.json` / `summary.csv`.
  Warmup pairwise similarity files are only produced when feature bundles exist (SDE path).
"""

from __future__ import annotations

import argparse
from pathlib import Path

from run_spec5_sde_perf_similarity import DEFAULT_REPRESENTATIVE_BENCHES, run_spec_batch_main


def main() -> int:
    ap = argparse.ArgumentParser(
        description="SPEC5 batch: perf Intel PT + recover_mem_addrs_uc analysis only (no SDE)"
    )
    ap.add_argument(
        "--spec-root",
        type=Path,
        default=Path("/home/huangtianhao/speccpu2017"),
        help="SPEC CPU root",
    )
    ap.add_argument("--warmup-sweep", type=str, default="60,120", help="comma list, e.g. 60,120")
    ap.add_argument("--total-insns", type=int, default=2_000_000)
    ap.add_argument("--line-size", type=int, default=64)
    ap.add_argument("--perf-record-seconds", type=float, default=0.001)
    ap.add_argument("--perf-mmap-pages", type=int, default=1024, help="perf record -m pages (PT buffer size)")
    ap.add_argument("--perf-event", type=str, default="intel_pt/cyc,noretcomp=0/u")
    ap.add_argument("--perf-max-insn-lines", type=int, default=500_000)
    ap.add_argument("--trace-post-sde-sleep", type=float, default=8.0)
    ap.add_argument("--trace-settle-timeout", type=float, default=300.0)
    ap.add_argument("--trace-settle-interval", type=float, default=1.0)
    ap.add_argument("--trace-stable-rounds", type=int, default=4)
    ap.add_argument("--recover-init-regs", choices=["zero", "random"], default="random")
    ap.add_argument(
        "--recover-reg-staging",
        choices=["legacy", "dwt"],
        default="dwt",
        help="register staging strategy passed to recover_mem_addrs_uc",
    )
    ap.add_argument(
        "--recover-mvs",
        choices=["on", "off"],
        default="on",
        help="whether to enable MVS in recover_mem_addrs_uc",
    )
    ap.add_argument("--recover-fill-seed", type=int, default=1)
    ap.add_argument(
        "--recover-page-init",
        choices=["zero", "random", "stable"],
        default="zero",
        help="page initialization policy for recover_mem_addrs_uc (default: zero)",
    )
    ap.add_argument(
        "--recover-page-init-seed",
        type=int,
        default=1,
        help="seed for page random initialization (used when --recover-page-init=random)",
    )
    ap.add_argument("--recover-salvage-invalid-mem", action=argparse.BooleanOptionalAction, default=True)
    ap.add_argument("--recover-salvage-reads", action=argparse.BooleanOptionalAction, default=True)
    ap.add_argument("--recover-progress-every", type=int, default=0)
    ap.add_argument(
        "--analysis-rd-hist-cap-lines",
        type=int,
        default=262144,
        help="cap RD histogram bins above this line distance (0 disables cap)",
    )
    ap.add_argument(
        "--analysis-stride-bin-cap-lines",
        type=int,
        default=262144,
        help="cap stride |delta| bins above this line distance into tail bucket (0 disables cap)",
    )
    ap.add_argument(
        "--output-base",
        type=Path,
        default=Path("/home/huangtianhao/Intel_PT_Trace_Processing/outputs/spec5_perf_trace_only"),
    )
    ap.add_argument(
        "--benchmarks",
        type=str,
        default="",
        help="optional comma list; empty means representative subset "
        + f"({', '.join(DEFAULT_REPRESENTATIVE_BENCHES[:3])}, …)",
    )
    ap.add_argument("--bench-limit", type=int, default=0, help="for quick test, limit benchmark count")
    ap.add_argument(
        "--post-workers",
        type=int,
        default=8,
        help="number of workers for parallel post-processing (default: 8)",
    )
    ap.add_argument("--stop-on-error", action="store_true", help="stop batch immediately on first failure")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument(
        "--insn-portrait",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Second perf script with --xed + instruction portrait JSON (perf needs Intel XED)",
    )
    args = ap.parse_args()

    # Fields required by run_trace_phase / run_post_phase when SDE is disabled (unused but must exist).
    args.enable_sde = False
    args.sde = Path("/dev/null")
    args.stride_top_k = 20
    args.write_feature_bundle = False

    return run_spec_batch_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
