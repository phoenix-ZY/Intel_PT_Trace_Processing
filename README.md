# Intel_PT_Trace_Processing

Current workflow for comparing SPEC traces between:
- SDE real data accesses
- perf intel_pt recovered data accesses
- SDE instruction fetch stream
- perf instruction fetch stream

The project now uses one unified analysis pipeline:
1. `analyze_mem_trace_profiles.py` analyzes one trace.
2. `compare_mem_trace_metrics.py` compares two analyzed traces.

## Main scripts

- `run_spec5_sde_perf_similarity.py`  
  Batch runner for SPEC 5xx workloads and warmup sweeps. It orchestrates:
  - SDE attach and debugtrace collection
  - perf intel_pt collection
  - trace conversion/recovery
  - data + instruction locality comparison
  - `summary.json` / `summary.csv` output

- `sde_debugtrace_convert.py`  
  Converts SDE debugtrace into:
  - data mem JSONL (`*.sde.mem.real.jsonl`)
  - instruction trace (`*.sde.insn.trace.txt`)

- `recover_mem_addrs_uc.c` + `build_recover_mem_addrs_uc.sh`  
  Unicorn-based C recovery tool that reconstructs memory accesses from
  instruction trace (`<tid> <time>: <ip> insn: <bytes...>`).

- `analyze_mem_trace_profiles.py`  
  Single-trace analyzer (data or instruction stream):
  - Reuse distance histogram (RD)
  - Stack-distance / miss-ratio curve (SDP/MRC)
  - Stride distribution and metrics

- `compare_mem_trace_metrics.py`  
  Compares two analysis JSON files:
  - RD similarity (`r2`, `l1`, `topk_wmape`, cold-ratio diff)
  - SDP similarity (`r2`, `mean_abs_error`, `max_abs_error`)
  - Stride similarity (`r2`, `l1`, `jsd`)

- `align_insn_traces.py`  
  Unified instruction-trace alignment tool:
  - default: compute offset only (`offset = pt_idx - sde_idx`)
  - `--verify`: checkpoint-based same-segment validation

- `analyze_insn_trace_with_xed.py`  
  Optional helper for sampled ISA/category statistics via `xed`.

## Typical usage

### 1) Build recovery binary

```bash
cd Intel_PT_Trace_Processing
bash build_recover_mem_addrs_uc.sh
```

### 2) Run SPEC batch comparison

```bash
python3 run_spec5_sde_perf_similarity.py \
  --warmup-sweep 5,60,120 \
  --output-base outputs/spec5_sde_perf_subset
```

### 3) Inspect outputs

- Per-case directory:  
  `outputs/spec5_sde_perf_subset/<bench>/<warmup_tag>/`
- Final batch summary:
  - `outputs/spec5_sde_perf_subset/summary.json`
  - `outputs/spec5_sde_perf_subset/summary.csv`

## Standalone analysis usage

### Analyze one trace

```bash
python3 analyze_mem_trace_profiles.py \
  --input path/to/trace.jsonl \
  --trace-kind data \
  --json-out out.analysis.json
```

For instruction trace text:

```bash
python3 analyze_mem_trace_profiles.py \
  --input path/to/trace.insn.trace.txt \
  --input-format insn_trace \
  --trace-kind inst \
  --json-out out.inst.analysis.json
```

### Compare two analyzed traces

```bash
python3 compare_mem_trace_metrics.py \
  --ref-analysis ref.analysis.json \
  --test-analysis test.analysis.json \
  --json-out compare.json
```

## Notes / limitations

- Recovered perf memory addresses are virtualized by emulator state initialization.
  They are plausible under the configured virtual state, not guaranteed to match
  real runtime addresses.
- `recover_mem_addrs_uc` supports state controls like `--init-regs`,
  `--page-init`, and salvage options; these can significantly affect both
  speed and similarity quality.