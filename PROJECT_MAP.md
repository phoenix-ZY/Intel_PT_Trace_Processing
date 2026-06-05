# Intel_PT_Trace_Processing Project Map (Current)

The current main workflow is "Python orchestration + C core processing", and the perf-only post-processing logic is factored into a reusable module (`perf_pipeline.py`).

For the full architecture and responsibility boundaries, see `docs/ARCHITECTURE.md`.
For the detailed staged migration plan, see `docs/REFACTOR_PLAN.md`.

At a high level the repository has four responsibilities:
- **Trace collection**: produce `perf.data` (and SDE debugtrace when validation is needed).
- **One-shot software feature extraction**: turn one `perf.data` into one final feature JSON.
- **SDE validation**: compare perf-recovered locality features against true SDE memory accesses.
- **Analytical performance modeling**: consume extracted software features plus hardware assumptions.

Entry scripts (you will most likely start here):
- **SPEC: SDE vs perf similarity**: `scripts/collect/run_spec5_sde_perf_similarity.py`
- **SPEC: perf-only feature extraction**: `scripts/collect/run_spec5_perf_trace_analysis.py`
- **Cloud: Docker collection + perf-only feature extraction**: `scripts/collect/run_cloud_perf_trace_analysis.py`
- **Downstream model (optional)**: `scripts/model/run_miic_interval_backend.py`

Public API for downstream projects (recommended integration point):
- **Software-feature extraction API**: `trace_feature_api.py`
  - Single importable function `extract_software_features(perf_data) -> dict` that wraps the
    whole `perf.data → software features` pipeline.
  - Intended for downstream consumers (e.g. ArchLens) that only need the *software* features
    and want to attach their own hardware/microarchitecture parameters afterwards.

## 1) Workflows and responsibilities

- `scripts/collect/run_spec5_sde_perf_similarity.py`
  - Batch runner for SPEC CPU 5xx with warmup sweeps
  - SDE path: calls `analyze_sde_trace_uc` (single pass emits SDE mem/insn + data/inst analysis)
  - perf path: calls `recover_mem_addrs_uc` (single pass recovers mem + emits data/inst analysis)
  - Finally calls `scripts/tools/compare_mem_trace_metrics.py` to produce similarity JSON and aggregates `summary.json/csv`

- `scripts/collect/run_spec5_perf_trace_analysis.py`
  - Batch runner for SPEC CPU 5xx with warmup sweeps, but **without SDE** and without similarity compare
  - Reuses `perf_pipeline.perf_postprocess_one` for the perf-only path
  - Useful for perf-only feature export / dataset generation / aligning SPEC and cloud outputs to the same schema

- `scripts/collect/run_cloud_perf_trace_analysis.py`
  - Runs typical cloud services and benchmark clients inside Docker
  - Collection: `perf record` (Intel PT) targeting a single thread (busiest TID)
  - Post-process: reuses `perf_pipeline.perf_postprocess_one`, producing analysis JSON in the same schema as SPEC perf-only

- `scripts/model/run_miic_interval_backend.py`
  - Walks an existing output directory (SPEC or cloud layout) and finds `report/*.perf.recovered.data.analysis.json`
  - Loads data/inst locality features + optional portrait, runs an interval-style cycle-stack model, and exports CSV/JSON
  - Model implementation: `src/intel_pt_trace_processing/model/miic_interval.py`
  - This is the theoretical performance calculation layer. It consumes extracted software
    features and attaches configurable hardware assumptions (cache sizes/latencies,
    dispatch width, branch penalty, memory latency, MLP).

- `csrc/analyze_sde_trace_uc.c`
  - Input: SDE debugtrace
  - Outputs (optional combinations):
    - `*.sde.mem.real.jsonl`
    - `*.sde.insn.trace.txt`
    - `*.sde.data.analysis.json`
    - `*.sde.inst.analysis.json`

- `csrc/recover_mem_addrs_uc.c`
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
  - This is the low-level layer; the batch runners call it directly. New downstream
    integrations should prefer `trace_feature_api.py` (below) instead.

- `trace_feature_api.py` (public software-feature API)
  - Stable, importable entry point that wraps `perf_postprocess_one()` into a single call:
    - `extract_software_features(perf_data, *, config=None, work_dir=None, ...) -> dict`
    - `extract_software_features_to_json(perf_data, output_json, ...) -> Path`
    - `FeatureExtractionConfig`: tuning knobs; defaults mirror `add_perf_postprocess_args()`
  - Returns a `trace-profile-v1` dict: `data_locality`, `inst_locality`, `recover_report`,
    optional `insn_portrait`, and pipeline `health` counters.
  - New normalized consumers should read `features.data_memory`,
    `features.instruction_memory`, `features.instruction_portrait`, and
    `features.recovery`.
  - **Scope boundary**: produces *software* features only. It deliberately does NOT attach any
    hardware/microarchitecture parameters — that step belongs to the downstream consumer
    (e.g. ArchLens). Trace collection (`perf record`) and SDE validation are out of scope.
  - Also runnable as a CLI: `python3 trace_feature_api.py perf.data -o features.json`.

- `src/intel_pt_trace_processing/perf/processor.py`
  - New one-shot perf processor used by `trace_feature_api.py`.
  - Keeps the old pipeline underneath for now, but returns a unified profile shape.

- `src/intel_pt_trace_processing/sde/processor.py`
  - New SDE processor wrapper around `analyze_sde_trace_uc`.
  - Defaults to data-memory features only, matching the validation use case.

- `src/intel_pt_trace_processing/core/theory.py`
  - Optional theory-model boundary and initial MIIC interval post-pass.

- `csrc/trace_feature_processor.c` (experimental one-pass stream processor)
  - Input: `perf script --insn-trace` stream on stdin.
  - Output: one combined JSON containing `inst_locality`, `data_locality`, recover health,
    and XED-based instruction portrait statistics.
  - Depends on XED headers/libraries and is built by `build_recover_mem_addrs_uc.sh`
    when a usable XED kit is available.
  - This is a future faster path; the public Python API currently uses
    `perf_pipeline.py + recover_mem_addrs_uc`.

- `csrc/trace_feature_core.h` / `csrc/trace_feature_core.c`
  - Shared feature/statistics core (RD/SDP/stride)
  - Used by both SDE and perf pipelines

- `scripts/tools/compare_mem_trace_metrics.py`
  - Input: two analysis JSON files (typically one from SDE, one from perf recovered)
  - Output: similarity metrics JSON (RD/SDP/stride, etc.)

- `analyze_insn_trace_portrait.py`
  - Builds an "instruction portrait" (mix / branch stats / rates) and provides flatten helpers
  - Optional in perf-only pipeline (enabled by default) to produce `*.insn.portrait.json`

- `scripts/tools/export_perf_full_features.py` / `scripts/tools/export_trace_features_to_excel.py`
  - Aggregates `report/*.analysis.json` into CSV/XLSX (quick analysis/plotting)

- `src/intel_pt_trace_processing/tools/flatten.py`
  - Generic `trace-profile-v1` flattener.
  - Builds dynamic CSV columns from whatever the feature profile returns.

- `scripts/tools/plot_data_feature_similarity.py`
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
python3 scripts/collect/run_spec5_sde_perf_similarity.py --warmup-sweep 5,20
```

## 4) Notes

The older Python-based conversion / single-trace analysis chain (`sde_debugtrace_convert.py`, `analyze_mem_trace_profiles.py`, `reuse_distance.py`) has been removed and is no longer part of the current main workflow.
