# Intel_PT_Trace_Processing Project Map (Current)

The current main workflow is "Python orchestration + C one-pass processing", and the perf-only post-processing logic is factored into `src/intel_pt_trace_processing/perf/stream.py`.

For the full architecture and responsibility boundaries, see `docs/ARCHITECTURE.md`.

At a high level the repository has three current responsibilities:
- **Trace collection**: produce `perf.data` (and SDE debugtrace when validation is needed).
- **One-shot software feature extraction**: turn one `perf.data` into one final feature JSON.
- **SDE validation**: compare perf-recovered locality features against true SDE memory accesses.

Entry scripts (you will most likely start here):
- **SPEC: SDE vs perf similarity**: `scripts/collect/run_spec5_sde_perf_similarity.py`
- **SPEC: perf-only feature extraction**: `scripts/collect/run_spec5_perf_trace_analysis.py`
- **Cloud: Docker collection + perf-only feature extraction**: `scripts/collect/run_cloud_perf_trace_analysis.py`

Public API for downstream projects (recommended integration point):
- **Software-feature extraction API**: `trace_feature_api.py`
  - Single importable function `extract_software_features(perf_data) -> dict` that wraps the
    whole `perf.data -> software features` stream processor.
  - Intended for downstream consumers (e.g. ArchLens) that only need the *software* features
    and want to attach their own hardware/microarchitecture parameters afterwards.

## 1) Workflows and responsibilities

- `scripts/collect/run_spec5_sde_perf_similarity.py`
  - Batch runner for SPEC CPU 5xx with warmup sweeps
  - SDE path: calls `analyze_sde_trace_uc` (single pass emits SDE mem/insn + data/inst analysis)
  - perf path: streams `perf script --insn-trace` through `trace_feature_processor`
  - Finally calls `scripts/tools/compare_mem_trace_metrics.py` to produce similarity JSON and aggregates `summary.json/csv`

- `scripts/collect/run_spec5_perf_trace_analysis.py`
  - Batch runner for SPEC CPU 5xx with warmup sweeps, but **without SDE** and without similarity compare
  - Reuses `intel_pt_trace_processing.perf.stream.process_perf_stream` for the perf-only path
  - Useful for perf-only feature export / dataset generation / aligning SPEC and cloud outputs to the same schema

- `scripts/collect/run_cloud_perf_trace_analysis.py`
  - Runs typical cloud services and benchmark clients inside Docker
  - Collection: target workload is pinned to one CPU/core; `perf record` uses Intel PT with `perf -C`
  - Post-process: reuses `intel_pt_trace_processing.perf.stream.process_perf_stream`, producing analysis JSON in the same schema as SPEC perf-only

- `csrc/analyze_sde_trace_uc.c`
  - Input: SDE debugtrace
  - Outputs (optional combinations):
    - `*.sde.insn.trace.txt`
    - `*.sde.data.analysis.json`
    - `*.sde.inst.analysis.json`

- `csrc/recover_mem_addrs_uc.c`
  - Input: perf instruction trace (`<tid> <time>: <ip> insn: <bytes...>`)
  - Outputs:
    - `*.perf.recovered.data.analysis.json`
    - `*.perf.inst.analysis.json`

- `csrc/trace_feature_processor.c`
  - Input: `perf script --insn-trace -F tid,cpu,time,ip,insn,ipc` stream on stdin.
  - Output: one combined JSON containing `inst_locality`, `data_locality`, recover health,
    and XED-based instruction portrait statistics.
  - This is the default perf processing backend.

- `src/intel_pt_trace_processing/perf/stream.py`
  - Reusable perf-only post-processing layer: `perf.data -> perf script -> trace_feature_processor -> analysis JSON`
  - Key functions:
    - `add_perf_processor_args()` / `validate_perf_processor_args()`
    - `process_perf_stream()`: returns aux_lost / trace_errors / insn_lines and output paths
  - This is the low-level layer; the batch runners call it directly. New downstream
    integrations should prefer `trace_feature_api.py` (below) instead.

- `trace_feature_api.py` (public software-feature API)
  - Stable, importable entry point that wraps `process_perf_stream()` into a single call:
    - `extract_software_features(perf_data, *, config=None, work_dir=None, ...) -> dict`
    - `extract_software_features_to_json(perf_data, output_json, ...) -> Path`
    - `FeatureExtractionConfig`: tuning knobs; defaults mirror `add_perf_postprocess_args()`
  - Returns a `trace-profile-v1` dict: `data_locality`, `inst_locality`, `recover_report`,
    optional `insn_portrait`, and processor `health` counters.
  - New normalized consumers should read `features.data_memory`,
    `features.instruction_memory`, `features.instruction_portrait`, and
    `features.recovery`.
  - **Scope boundary**: produces *software* features only. It deliberately does NOT attach any
    hardware/microarchitecture parameters — that step belongs to the downstream consumer
    (e.g. ArchLens). Trace collection (`perf record`) and SDE validation are out of scope.
  - Also runnable as a CLI: `python3 trace_feature_api.py perf.data -o features.json`.

- `src/intel_pt_trace_processing/perf/processor.py`
  - New one-shot perf processor used by `trace_feature_api.py`.
  - Uses `trace_feature_processor` underneath and returns a unified profile shape.

- `src/intel_pt_trace_processing/sde/processor.py`
  - New SDE processor wrapper around `analyze_sde_trace_uc`.
  - Defaults to data-memory features only, matching the validation use case.

- `csrc/trace_feature_core.h` / `csrc/trace_feature_core.c`
  - Shared feature/statistics core (RD/SDP/stride)
  - Used by both SDE and perf pipelines

- `scripts/tools/compare_mem_trace_metrics.py`
  - Input: two analysis JSON files (typically one from SDE, one from perf recovered)
  - Output: similarity metrics JSON (RD/SDP/stride, etc.)

- `src/intel_pt_trace_processing/core/portrait_metrics.py`
  - Flattens the instruction portrait JSON emitted by `trace_feature_processor` for CSV/export consumers.

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
