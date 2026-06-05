# Architecture

This repository has three current responsibilities: trace collection, one-shot
software feature extraction, and SDE validation. Analytical performance modeling
is a future stream-time extension point rather than a post-pass over completed
profiles.

## 1. Collect raw traces

This layer is responsible for producing input artifacts, especially `perf.data`.
It should not be the integration point for downstream feature consumers.

- `scripts/collect/run_spec5_perf_trace_analysis.py`
  - SPEC CPU perf-only collection and post-processing.
- `scripts/collect/run_cloud_perf_trace_analysis.py`
  - Docker/cloud workload orchestration, worker-thread selection, `perf record`,
    optional `perf stat`, and post-processing.
- `scripts/collect/run_spec5_sde_perf_similarity.py`
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
  - It wraps `intel_pt_trace_processing.perf.stream.process_perf_stream()` and hides intermediate paths.

The lower-level implementation is:

- `src/intel_pt_trace_processing/perf/processor.py`
  - New Python-facing one-shot processor for `perf.data`.
  - Returns the normalized `trace-profile-v1` shape.
- `src/intel_pt_trace_processing/perf/stream.py`
  - Shared perf-only post-processing:
    `perf.data -> perf script --insn-trace -> trace_feature_processor -> analysis JSON`.
- `csrc/trace_feature_processor.c`
  - Unicorn-based recovery from decoded instruction stream.
  - Emits recovered memory JSONL, data/instruction locality analysis, XED portrait statistics, and one combined JSON.
- `csrc/trace_feature_core.c` / `csrc/trace_feature_core.h`
  - Shared RD/SDP/stride feature core.
- `src/intel_pt_trace_processing/core/portrait_metrics.py`
  - Flattens the portrait JSON emitted by `trace_feature_processor`.

The normalized profile shape is:

```json
{
  "schema": "trace-profile-v1",
  "source": {"kind": "perf", "path": "..."},
  "features": {
    "data_memory": {},
    "instruction_memory": {},
    "instruction_portrait": {},
    "recovery": {}
  },
  "health": {},
  "artifacts": {},
  "metadata": {}
}
```

Legacy top-level keys such as `data_locality`, `inst_locality`, `insn_portrait`,
and `recover_report` are still emitted for compatibility. New code should prefer
the `features.*` namespace.

## 3. Validate recovered perf features against SDE ground truth

This layer answers: "How close are the recovered perf features to true memory
accesses from SDE?"

- `csrc/analyze_sde_trace_uc.c`
  - One-pass SDE debugtrace analyzer.
  - Emits real memory JSONL, SDE instruction trace, and data/instruction analysis JSON.
- `scripts/tools/compare_mem_trace_metrics.py`
  - Compares SDE analysis JSON against perf-recovered analysis JSON.
- `scripts/tools/align_insn_traces.py`
  - Checks or estimates alignment between PT and SDE instruction streams.
- `scripts/collect/run_spec5_sde_perf_similarity.py`
  - Orchestrates the full validation workflow and writes summary reports.

This layer is validation/research infrastructure. It is not required when a
downstream system only wants software features from a known `perf.data`.

## 4. Future Stream-Time Modeling

The old post-pass analytical backend has been removed. Future theoretical
calculation should be accumulated during the same per-instruction traversal that
recovers memory and extracts XED portrait features.

The intended direction is:

```text
perf script instruction stream
  -> trace_feature_processor
       -> recover memory/register state
       -> extract instruction/locality/portrait features
       -> accumulate theoretical model state per instruction
  -> final profile JSON
```

Until that exists, `trace-profile-v1` remains a software-feature artifact only.

## Support and experiment scripts

These scripts are useful for analysis, plotting, and export, but they are not
core pipeline entry points:

- `scripts/tools/export_perf_full_features.py`
- `scripts/tools/export_trace_features_to_excel.py`
- `scripts/tools/analyze_cloud_vs_spec.py`
- `scripts/tools/plot_data_feature_similarity.py`
- `scripts/tools/analyze_insn_trace_with_xed.py`

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
SDE debugtrace -> csrc/analyze_sde_trace_uc -> SDE truth features
perf.data      -> trace_feature_api/stream processor -> recovered perf features
both           -> scripts/tools/compare_mem_trace_metrics.py -> similarity report
```
