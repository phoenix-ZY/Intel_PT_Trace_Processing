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
  - Collection: target workload is pinned to one CPU/core; Intel PT uses
    `perf -a -C CPU -G container-cgroup` so unrelated tasks on the core are excluded
  - Post-process: verifies the sudo user's build-id cache, removes each target
    container after collection, then decodes all benches in parallel into the
    same canonical `trace-profile-v2` schema as SPEC perf-only

- `csrc/analyze_sde_trace_uc.c`
  - Input: SDE debugtrace
  - Outputs (optional combinations):
    - `*.sde.insn.trace.txt`
    - `*.sde.data.analysis.json`

- `csrc/recover_mem_addrs_uc.c`
  - Input: perf instruction trace (`<tid> <time>: <ip> insn: <bytes...>`)
  - Low-level optional outputs:
    - `*.perf.recovered.data.analysis.json`
    - `*.perf.inst.analysis.json`

- `csrc/trace_feature_processor.c`
  - Input: `perf script --insn-trace -F tid,cpu,time,ip,insn,ipc` stream on stdin.
  - Output: one processor JSON consumed by Python and wrapped into canonical `trace-profile-v2`.
  - This is the default perf processing backend.

- `src/intel_pt_trace_processing/perf/stream.py`
  - Reusable perf-only post-processing layer: `perf.data -> perf script -> trace_feature_processor -> trace_profile.json`
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
  - Returns a `trace-profile-v2` dict with seven final feature groups:
    `features.instruction_mix`, `features.data_memory`, `features.instruction_memory`,
    `features.branch`, `features.syscall`, `features.register_dependency`, and
    `features.ipc`. Source/artifact/health/recovery details live under `metadata`.
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
  - Input: two canonical trace profiles (`--ref-profile/--test-profile`)
  - Output: similarity metrics JSON (RD/SDP/stride, etc.)

- `src/intel_pt_trace_processing/core/portrait_metrics.py`
  - Flattens the instruction portrait JSON emitted by `trace_feature_processor` for CSV/export consumers.

- `scripts/tools/export_perf_full_features.py` / `scripts/tools/export_trace_features_to_excel.py`
  - Aggregates `report/*.trace_profile.json` into CSV/XLSX

- `src/intel_pt_trace_processing/tools/flatten.py`
  - Generic `trace-profile-v2` flattener.
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
  - `*.trace_profile.json` (perf canonical profile)
  - `*.sde.trace_profile.json` (only SDE vs perf)
  - `*.sde_vs_perf*.compare.json`
  - `*.perf.script.stderr.txt` and other logs/health info

### Cloud (perf-only)

- `outputs/cloud_trace/<service>.<config>/intermediate`
  - `*.perf.script.txt`, `*.perf.insn.trace.txt`, optional portrait temp files

- `outputs/cloud_trace/<service>.<config>/report`
  - `*.trace_profile.json`
  - stderr/logs

## 3) Build and run

```bash
cd Intel_PT_Trace_Processing
bash build_recover_mem_addrs_uc.sh
python3 scripts/collect/run_spec5_sde_perf_similarity.py --warmup-sweep 5,20
```

## 4) Notes

The older Python-based conversion / single-trace analysis chain (`sde_debugtrace_convert.py`, `analyze_mem_trace_profiles.py`, `reuse_distance.py`) has been removed and is no longer part of the current main workflow.
