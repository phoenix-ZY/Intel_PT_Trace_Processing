# Intel_PT_Trace_Processing

This repo collects and post-processes **Intel PT** traces (via `perf`), recovers **memory accesses**
from decoded instruction traces (via Unicorn), and produces **locality feature JSON reports**
that can be compared across sources (SDE vs perf) or consumed by downstream tools.

The repository is organized around three current responsibilities:
- **Collect raw traces** (`scripts/collect/run_spec5_perf_trace_analysis.py`, `scripts/collect/run_cloud_perf_trace_analysis.py`, `scripts/collect/run_spec5_sde_perf_similarity.py`)
- **Extract one software-feature JSON from one `perf.data`** (`trace_feature_api.py`)
- **Validate perf-recovered features against SDE ground truth** (`scripts/collect/run_spec5_sde_perf_similarity.py`, `csrc/analyze_sde_trace_uc.c`, `scripts/tools/compare_mem_trace_metrics.py`)

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the current architecture and
responsibility boundaries.

## Main scripts

- `scripts/collect/run_spec5_sde_perf_similarity.py`
  - Batch runner for SPEC CPU 5xx with warmup sweeps
  - Produces two reference paths per case:
    - SDE debugtrace (real memory accesses)
    - perf Intel PT (recovered memory accesses from decoded instruction trace)
  - Outputs: per-case SDE/perf analysis JSON + similarity compare JSON + batch `summary.json`/`summary.csv`

- `scripts/collect/run_spec5_perf_trace_analysis.py`
  - SPEC CPU 5xx **perf-only** (no SDE, no similarity compare)
  - Outputs: per-case recovered mem JSONL + `*.perf.*.analysis.json` + batch `summary.json`/`summary.csv`

- `scripts/collect/run_cloud_perf_trace_analysis.py`
  - Runs classic cloud services and benchmark clients in Docker (redis/nginx/haproxy/postgres/mysql/memcached, etc.)
  - Captures perf Intel PT from a single worker thread, then reuses the same perf-only stream processor
  - Outputs: `intermediate/`, `mem/`, `report/` under each `<service>.<config>/`

- `csrc/analyze_sde_trace_uc.c` + `build_recover_mem_addrs_uc.sh`
  One-pass SDE analyzer for debugtrace input. In a single scan, it can emit:
  - data mem JSONL (`*.sde.mem.real.jsonl`)
  - instruction trace (`*.sde.insn.trace.txt`)
  - SDE data analysis JSON
  - SDE instruction analysis JSON

- `csrc/recover_mem_addrs_uc.c` + `build_recover_mem_addrs_uc.sh`
  Unicorn-based C recovery tool that reconstructs memory accesses from
  instruction trace (`<tid> <time>: <ip> insn: <bytes...>`). It now also
  supports one-pass analysis output (instruction + recovered-data profiles).

- `src/intel_pt_trace_processing/perf/stream.py`
  - Reusable perf-only post-processing core:
    `perf.data -> perf script -> trace_feature_processor -> combined JSON`
  - Shared by the collectors under `scripts/collect/`

- `trace_feature_api.py` **(public software-feature API — recommended for downstream)**
  - One importable call that turns a single `perf.data` into a software-feature dict/JSON:
    `extract_software_features(perf_data) -> dict`
  - Delegates to `src/intel_pt_trace_processing/perf/processor.py`
  - Wraps the one-pass stream processor and hides the low-level parameter/path bookkeeping
  - Produces **software features only** (instruction-flow, data/instruction locality, optional
    instruction portrait); attaching hardware/microarchitecture parameters is left to the
    downstream consumer (e.g. ArchLens). See [Software-feature API](#software-feature-api-for-downstream) below.

- `csrc/trace_feature_processor.c` **(default one-pass stream processor)**
  - Reads `perf script --insn-trace` text from stdin and emits one combined feature JSON
  - Uses Unicorn for memory recovery and XED directly for instruction portrait statistics
  - Built by `build_recover_mem_addrs_uc.sh` when XED headers/libraries are available

- `scripts/tools/compare_mem_trace_metrics.py`
  Compares two analysis JSON files:
  - RD similarity (`r2`, `l1`, `topk_wmape`, cold-ratio diff)
  - SDP similarity (`r2`, `mean_abs_error`, `max_abs_error`)
  - Stride similarity (`r2`, `l1`, `jsd`)

- `scripts/tools/align_insn_traces.py`
  Unified instruction-trace alignment tool:
  - default: compute offset only (`offset = pt_idx - sde_idx`)
  - `--verify`: checkpoint-based same-segment validation

- `scripts/tools/analyze_insn_trace_with_xed.py`
  Optional helper for sampled ISA/category statistics via `xed`.

## Typical usage

### 1) Build recovery binary

```bash
cd Intel_PT_Trace_Processing
bash build_recover_mem_addrs_uc.sh
```

### 2) Run SPEC batch (SDE vs perf) comparison

```bash
python3 scripts/collect/run_spec5_sde_perf_similarity.py \
  --warmup-sweep 5,60,120 \
  --output-base outputs/spec5_sde_perf_subset
```

### 3) Run SPEC batch (perf-only)

```bash
python3 scripts/collect/run_spec5_perf_trace_analysis.py \
  --warmup-sweep 10,60 \
  --output-base outputs/spec5_perf_trace_only
```

### 4) Run cloud apps (perf-only)

> This script drives Docker and perf and often requires root privileges (depending on your host and `perf_event_paranoid`).

```bash
sudo python3 scripts/collect/run_cloud_perf_trace_analysis.py \
  --output-dir outputs/cloud_trace \
  --service redis \
  --samples-per-config 2
```

### 5) Inspect outputs

- Per-case directory:  
  `outputs/spec5_sde_perf_subset/<bench>/<warmup_tag>/`
- Final batch summary:
  - `outputs/spec5_sde_perf_subset/summary.json`
  - `outputs/spec5_sde_perf_subset/summary.csv`

Cloud layout:
- Per-config directory:
  `outputs/cloud_trace/<service>.<config>/`
- Under each config:
  - `intermediate/`: copied `*.perf.data` and optional temporary/debug files
  - `mem/`: `*.perf.mem.recovered.jsonl`
  - `report/`: `*.perf.*.analysis.json`, stderr/logs, optional portrait artifacts

## Software-feature API (for downstream)

`trace_feature_api.py` is the **recommended integration point** for downstream projects
(e.g. ArchLens). It abstracts the whole `perf.data → software features` pipeline behind a
single importable function, so callers do not need to manage intermediate files, the many
recover/analysis knobs, or the output directory layout.

**Scope / responsibility boundary**

- Input: a single raw Intel PT capture (`perf.data`).
- Output: a `trace-profile-v1` software-feature dictionary (or JSON file) containing
  `data_locality`, `inst_locality`, `recover_report`, optional `insn_portrait`, and processor
  `health` counters.
- It produces **software features only**. It intentionally does **not** attach any
  hardware/microarchitecture parameters — that is the downstream consumer's job (ArchLens
  joins these software features with its own architecture metadata).
- Trace collection (`perf record`) and SDE-based validation are **out of scope** here.

**Prerequisite**: build the C processors first (`bash build_recover_mem_addrs_uc.sh`),
since the API runs `trace_feature_processor`.

### As a Python import

```python
from trace_feature_api import extract_software_features, FeatureExtractionConfig

# Simplest form: defaults mirror the production stream processor.
features = extract_software_features("perf.data")
print(features["data_locality"])
print(features["inst_locality"])
print(features["insn_portrait"])   # None if portrait disabled/empty

# With custom knobs and an explicit work dir (kept on disk for inspection).
cfg = FeatureExtractionConfig(perf_max_insn_lines=1_000_000, insn_portrait=False)
features = extract_software_features(
    "perf.data", config=cfg, work_dir="outputs/_tmp_feat", keep_intermediate=True
)
```

### As a CLI

```bash
python3 trace_feature_api.py perf.data -o features.json
# keep intermediate artifacts for debugging:
python3 trace_feature_api.py perf.data -o features.json --work-dir outputs/_tmp_feat --keep-intermediate
```

The batch runners under `scripts/collect/` call the lower-level
`intel_pt_trace_processing.perf.stream.process_perf_stream()` directly.

## Standalone analysis usage

### Analyze SDE debugtrace in one pass (C)

```bash
./analyze_sde_trace_uc \
  -i path/to/sde.debugtrace.txt \
  --mem-out out.sde.mem.real.jsonl \
  --insn-out out.sde.insn.trace.txt \
  --data-analysis-out out.sde.data.analysis.json \
  --inst-analysis-out out.sde.inst.analysis.json
```

### Recover perf mem + analyze in one pass (C)

```bash
./recover_mem_addrs_uc \
  -i path/to/perf.insn.trace.txt \
  -o out.perf.mem.recovered.jsonl \
  --inst-analysis-out out.perf.inst.analysis.json \
  --data-analysis-out out.perf.recovered.data.analysis.json
```

### Compare two analyzed traces

```bash
python3 scripts/tools/compare_mem_trace_metrics.py \
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
