# SDE validation (off main line)

This folder is **not** part of the production CBS ↔ IPT workflow. It keeps the
host-native SPEC + Intel SDE debugtrace path used to validate Unicorn-based memory
recovery against ground-truth memory accesses.

## Entry point

```bash
cd Intel_PT_Trace_Processing
python3 validation/run_spec5_sde_perf_similarity.py \
  --warmup-sweep 5,60,120 \
  --output-base outputs/spec5_sde_perf_subset
```

Implementation lives under `validation/ipt_validation/` and is only imported from
this driver. It calls the main-line API modules (`intel_pt_trace_processing.core`,
`intel_pt_trace_processing.perf`) for perf feature extraction.

## Layout

```text
validation/
  run_spec5_sde_perf_similarity.py   # CLI entry
  ipt_validation/
    collect/                         # SPEC batch trace + post-process
    compare/                         # SDE vs perf similarity + mem_trace compare
    workloads/                       # SPEC launch helpers
```

## Production path

- **Workload launch + PT record**: `colocation-bench-suite`
- **PT feature extraction API**: `trace_feature_api.py` at repo root

See `colocation-bench-suite/docs/CBS_IPT_ALIGNMENT.md`.

Per-case SDE vs perf comparison: `ipt_validation/compare/mem_trace.py`.
Batch summaries: `summary.json` / `summary.csv` under `--output-base`.
