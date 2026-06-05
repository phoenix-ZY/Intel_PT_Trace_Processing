# Refactor Plan

This document captures the target structure after the trace-processing refactor.
The code has started migrating in this direction under `src/intel_pt_trace_processing`.

## Target Layout

```text
src/intel_pt_trace_processing/
  core/
    features.py        unified trace-profile schema helpers
    theory.py          optional theory-model hook and post-pass interface
  perf/
    processor.py       one perf.data -> one trace-profile-v1 JSON
  sde/
    processor.py       one SDE debugtrace -> SDE memory-feature profile
  collect/
    ...                SPEC/cloud/SDE collection orchestration
  tools/
    ...                compare/export/plot helpers
csrc/
  ...                  C recovery/analyzer/stream-processor sources
scripts/
  collect/             SPEC/cloud/SDE trace collection entry points
  model/               model runner CLIs
  tools/               compare/export/plot CLIs
```

The repository root keeps stable user-facing API/build files only:
`trace_feature_api.py` and `build_recover_mem_addrs_uc.sh`.

## Core Perf Processing

The intended downstream path is:

```text
perf.data
  -> perf script --insn-trace
  -> per-instruction processor
       -> Unicorn path: recover memory addresses and selected register state
       -> XED path: decode instruction category/mix/branch/syscall metadata
       -> feature sinks: locality, portrait, recovery health, optional theory
  -> trace-profile-v1 JSON
```

The key design point is that feature extraction should be organized around the
instruction traversal, not around multiple unrelated output files that are later
stitched together.

Current implementation status:

- `src/intel_pt_trace_processing/perf/processor.py` is the new Python-facing
  one-shot processor.
- It currently delegates instruction traversal to the existing mature path:
  `src/intel_pt_trace_processing/perf/pipeline.py + recover_mem_addrs_uc`.
- `csrc/trace_feature_processor.c` is the experimental future single-pass stream
  processor that already combines recovery, locality, and XED portrait data.
- `trace_feature_api.py` now delegates to the new processor package while keeping
  the public API stable.

## Unified Feature Shape

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
  "metadata": {},
  "theory": {}
}
```

During migration, legacy top-level keys are still emitted:

- `data_locality`
- `inst_locality`
- `insn_portrait`
- `recover_report`
- `health`

This keeps existing consumers working while new code can read
`features.<namespace>`.

## SDE Processing

SDE is a separate validation path:

```text
SDE debugtrace
  -> csrc/analyze_sde_trace_uc
  -> true data-memory access stream
  -> same data-memory locality feature schema
```

SDE does not need to produce instruction-memory features for the main validation
goal. Its job is to provide true data-memory features that can be compared
against perf-recovered data-memory features.

Current implementation status:

- `src/intel_pt_trace_processing/sde/processor.py` wraps `analyze_sde_trace_uc`.
- By default it emits data-memory features only.
- It can optionally emit SDE instruction trace/analysis for debugging.

## Collection Layer

SPEC/cloud traversal should only collect raw traces and then call the processing
layer.

Target responsibility:

- decide which workload/config/sample to run
- collect `perf.data` or SDE debugtrace
- call the perf/SDE processor
- write one row per returned feature profile to CSV

The CSV schema should be generated from the returned feature dictionary. Adding
or removing feature columns should not require editing each collector.

Current implementation status:

- Collection scripts now live under `scripts/collect/`.
- They already share `src/intel_pt_trace_processing/perf/pipeline.py`.
- `src/intel_pt_trace_processing/tools/flatten.py` can flatten returned
  `trace-profile-v1` dictionaries and write dynamic-column CSVs.
- Next migration step: replace direct `perf_postprocess_one()` calls in collectors
  with `process_perf_data()` and use one exporter for flattened profile rows.

## Tools Layer

Tools should consume already-produced profiles or analysis JSONs:

- compare SDE vs perf feature profiles
- plot feature distributions
- export flattened CSV/XLSX
- run quick research analyses

They should not know how to collect traces or decode `perf.data`.

## Theory Model Hook

The theory/model layer should be optional:

```text
per-instruction traversal
  -> feature sinks
  -> optional theory hook
```

Current implementation status:

- `src/intel_pt_trace_processing/core/theory.py` defines the hook shape and an
  initial post-pass MIIC interval prediction.
- `trace_feature_api.py --theory-model` attaches the initial prediction to the
  final profile when instruction portrait data is available.
- Future single-pass processors can update theory state per instruction through
  the same hook boundary.

## Migration Order

1. Keep `trace_feature_api.py` as the public stable entry point.
2. Move new processing logic into `src/intel_pt_trace_processing/perf`.
3. Route SDE through `src/intel_pt_trace_processing/sde`.
4. Convert SPEC/cloud scripts into thin collection wrappers.
5. Consolidate flatten/export logic so CSV columns come from returned profiles.
6. Route the remaining collector post-processing calls through
   `process_perf_data()` and `process_sde_debugtrace()` so collection scripts
   become thin orchestration wrappers.
