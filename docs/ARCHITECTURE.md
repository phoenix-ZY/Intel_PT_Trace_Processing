# Architecture

This repository has four main responsibilities. The first three are the trace
processing pipeline; the fourth is an analytical performance-model backend that
consumes the extracted features.

## 1. Collect raw traces

This layer is responsible for producing input artifacts, especially `perf.data`.
It should not be the integration point for downstream feature consumers.

- `run_spec5_perf_trace_analysis.py`
  - SPEC CPU perf-only collection and post-processing.
- `run_cloud_perf_trace_analysis.py`
  - Docker/cloud workload orchestration, worker-thread selection, `perf record`,
    optional `perf stat`, and post-processing.
- `run_spec5_sde_perf_similarity.py`
  - SPEC collection for both SDE and perf when validation against SDE is needed.

Output of this layer:

- `perf.data` for Intel PT.
- SDE debugtrace files when the SDE validation workflow is enabled.
- Optional `perf stat` counter JSON/CSV files.

## 2. Convert one `perf.data` into one software-feature JSON

This is the main one-shot feature extraction path. The intended downstream entry
point is:

- `trace_feature_api.py`
  - Public API for downstream projects.
  - Input: one `perf.data`.
  - Output: one `trace-profile-v1` software-feature dictionary or JSON file.
  - It wraps `perf_pipeline.perf_postprocess_one()` and hides intermediate paths.

The lower-level implementation is:

- `perf_pipeline.py`
  - Shared perf-only post-processing:
    `perf.data -> perf script --insn-trace -> instruction trace -> recovered memory -> analysis JSON`.
- `recover_mem_addrs_uc.c`
  - Unicorn-based recovery from decoded instruction trace.
  - Emits recovered memory JSONL plus data/instruction locality analysis JSON.
- `trace_feature_core.c` / `trace_feature_core.h`
  - Shared RD/SDP/stride feature core.
- `analyze_insn_trace_portrait.py`
  - Optional instruction portrait from `perf script --xed` output.

There is also a newer experimental one-pass C processor:

- `trace_feature_processor.c`
  - Streams `perf script --insn-trace` text from stdin and emits a combined feature JSON.
  - Depends on XED headers and libraries.
  - Currently useful as a faster future direction, but `trace_feature_api.py` still uses
    the established `perf_pipeline.py + recover_mem_addrs_uc` path.

## 3. Validate recovered perf features against SDE ground truth

This layer answers: "How close are the recovered perf features to true memory
accesses from SDE?"

- `analyze_sde_trace_uc.c`
  - One-pass SDE debugtrace analyzer.
  - Emits real memory JSONL, SDE instruction trace, and data/instruction analysis JSON.
- `compare_mem_trace_metrics.py`
  - Compares SDE analysis JSON against perf-recovered analysis JSON.
- `align_insn_traces.py`
  - Checks or estimates alignment between PT and SDE instruction streams.
- `run_spec5_sde_perf_similarity.py`
  - Orchestrates the full validation workflow and writes summary reports.

This layer is validation/research infrastructure. It is not required when a
downstream system only wants software features from a known `perf.data`.

## 4. Predict performance from extracted software features

This layer is separate from trace extraction. It consumes the feature JSONs and
applies a configurable analytical model.

- `miic_interval_model.py`
  - MIIC-inspired interval model.
  - Uses data/instruction locality, instruction portrait, branch behavior, and
    configurable microarchitecture parameters.
- `run_miic_interval_backend.py`
  - Batch runner over existing `report/*.perf.recovered.data.analysis.json` outputs.

Important boundary:

- Trace extraction produces microarchitecture-independent software features.
- The interval model attaches hardware assumptions such as cache sizes, latencies,
  dispatch width, branch penalty, memory latency, and MLP.

## Support and experiment scripts

These scripts are useful for analysis, plotting, and export, but they are not
core pipeline entry points:

- `export_perf_full_features.py`
- `export_trace_features_to_excel.py`
- `analyze_cloud_vs_spec.py`
- `plot_data_feature_similarity.py`
- `analyze_insn_trace_with_xed.py`

## Recommended mental model

For downstream integration:

```text
perf.data
  -> trace_feature_api.py
  -> trace-profile-v1 JSON
  -> downstream project attaches hardware parameters or runs its own model
```

For validation:

```text
SDE debugtrace -> analyze_sde_trace_uc -> SDE truth features
perf.data      -> trace_feature_api/perf_pipeline -> recovered perf features
both           -> compare_mem_trace_metrics -> similarity report
```

For performance modeling:

```text
trace-profile / report JSONs
  -> miic_interval_model.py
  -> predicted CPI/IPC/cycle stack
```
