# Intel_PT_Trace_Processing Project Map (Current)

The current main workflow is "Python orchestration + C core processing", and the perf-only post-processing logic is factored into a reusable module (`perf_pipeline.py`).

Entry scripts (you will most likely start here):
- **SPEC: SDE vs perf similarity**: `run_spec5_sde_perf_similarity.py`
- **SPEC: perf-only feature extraction**: `run_spec5_perf_trace_analysis.py`
- **Cloud: Docker collection + perf-only feature extraction**: `run_cloud_perf_trace_analysis.py`
- **Downstream model (optional)**: `run_miic_interval_backend.py`

## 1) Workflows and responsibilities

- `run_spec5_sde_perf_similarity.py`
  - Batch runner for SPEC CPU 5xx with warmup sweeps
  - SDE path: calls `analyze_sde_trace_uc` (single pass emits SDE mem/insn + data/inst analysis)
  - perf path: calls `recover_mem_addrs_uc` (single pass recovers mem + emits data/inst analysis)
  - Finally calls `compare_mem_trace_metrics.py` to produce similarity JSON and aggregates `summary.json/csv`

- `run_spec5_perf_trace_analysis.py`
  - Batch runner for SPEC CPU 5xx with warmup sweeps, but **without SDE** and without similarity compare
  - Reuses `perf_pipeline.perf_postprocess_one` for the perf-only path
  - Useful for perf-only feature export / dataset generation / aligning SPEC and cloud outputs to the same schema

- `run_cloud_perf_trace_analysis.py`
  - Runs typical cloud services and benchmark clients inside Docker
  - Collection: `perf record` (Intel PT) targeting a single thread (busiest TID)
  - Post-process: reuses `perf_pipeline.perf_postprocess_one`, producing analysis JSON in the same schema as SPEC perf-only

- `run_miic_interval_backend.py`
  - Walks an existing output directory (SPEC or cloud layout) and finds `report/*.perf.recovered.data.analysis.json`
  - Loads data/inst locality features + optional portrait, runs an interval-style cycle-stack model, and exports CSV/JSON
  - Model implementation: `miic_interval_model.py`

- `analyze_sde_trace_uc.c`
  - Input: SDE debugtrace
  - Outputs (optional combinations):
    - `*.sde.mem.real.jsonl`
    - `*.sde.insn.trace.txt`
    - `*.sde.data.analysis.json`
    - `*.sde.inst.analysis.json`

- `recover_mem_addrs_uc.c`
  - Input: perf instruction trace (`<tid> <time>: <ip> insn: <bytes...>`)
  - Outputs:
    - `*.perf.mem.recovered.jsonl`
    - `*.perf.recovered.data.analysis.json`
    - `*.perf.inst.analysis.json`

- `perf_pipeline.py`
  - Reusable perf-only post-processing layer: `perf.data → perf script → insn trace → recover_mem_addrs_uc → analysis JSON`
  - Key functions:
    - `add_perf_postprocess_args()` / `validate_perf_postprocess_args()`
    - `perf_postprocess_one()`: returns aux_lost / trace_errors / insn_lines and all output paths

- `trace_feature_core.h` / `trace_feature_core.c`
  - Shared feature/statistics core (RD/SDP/stride)
  - Used by both SDE and perf pipelines

- `compare_mem_trace_metrics.py`
  - Input: two analysis JSON files (typically one from SDE, one from perf recovered)
  - Output: similarity metrics JSON (RD/SDP/stride, etc.)

- `analyze_insn_trace_portrait.py`
  - Builds an "instruction portrait" (mix / branch stats / rates) and provides flatten helpers
  - Optional in perf-only pipeline (enabled by default) to produce `*.insn.portrait.json`

- `export_perf_full_features.py` / `export_trace_features_to_excel.py`
  - Aggregates `report/*.analysis.json` into CSV/XLSX (quick analysis/plotting)

- `plot_data_feature_similarity.py`
  - Compares/visualizes similarity or feature distributions (research/experiment scripts)

## 2) Common output layouts

### SPEC（SDE vs perf / perf-only）

- `outputs/<spec_out>/<bench>/<warmup>/inputs`
  - Raw SDE debugtrace input (only present in SDE vs perf workflow)

- `outputs/<spec_out>/<bench>/<warmup>/intermediate`
  - `perf.data`, `*.perf.script.txt`, `*.perf.insn.trace.txt`, optional portrait temp files

- `outputs/<spec_out>/<bench>/<warmup>/mem`
  - `*.sde.mem.real.jsonl` (only SDE vs perf)
  - `*.perf.mem.recovered.jsonl`

- `outputs/<spec_out>/<bench>/<warmup>/report`
  - `*.sde.data.analysis.json`
  - `*.sde.inst.analysis.json`
  - `*.perf.recovered.data.analysis.json`
  - `*.perf.inst.analysis.json`
  - `*.sde_vs_perf*.compare.json`
  - `*.perf.script.stderr.txt` / `*.perf.recover.report.json` and other logs/health info

### Cloud (perf-only)

- `outputs/cloud_trace/<service>.<config>/intermediate`
  - `*.perf.script.txt`, `*.perf.insn.trace.txt`, optional portrait temp files

- `outputs/cloud_trace/<service>.<config>/mem`
  - `*.perf.mem.recovered.jsonl`

- `outputs/cloud_trace/<service>.<config>/report`
  - `*.perf.recovered.data.analysis.json`
  - `*.perf.inst.analysis.json`
  - `*.insn.portrait.json` (if `--insn-portrait` is enabled)
  - stderr/logs

## 3) Build and run

```bash
cd Intel_PT_Trace_Processing
bash build_recover_mem_addrs_uc.sh
python3 run_spec5_sde_perf_similarity.py --warmup-sweep 5,20
```

## 4) Notes

The older Python-based conversion / single-trace analysis chain (`sde_debugtrace_convert.py`, `analyze_mem_trace_profiles.py`, `reuse_distance.py`) has been removed and is no longer part of the current main workflow.
