# Intel_PT_Trace_Processing

This repo collects and post-processes **Intel PT** traces (via `perf`), recovers **memory accesses**
from decoded instruction traces (via Unicorn), and produces **locality feature JSON reports**
that can be compared across sources (SDE vs perf) or consumed by downstream models.

There are three practical entry points today:
- **SPEC: SDE vs perf similarity** (`run_spec5_sde_perf_similarity.py`)
- **SPEC: perf-only feature extraction** (`run_spec5_perf_trace_analysis.py`)
- **Cloud apps (Docker): perf-only collection + feature extraction** (`run_cloud_perf_trace_analysis.py`)

Downstream (optional):
- **MIIC-inspired interval model backend** (`run_miic_interval_backend.py`) consumes the perf-only outputs.

## Main scripts

- `run_spec5_sde_perf_similarity.py`
  - SPEC 5xx 批量跑 warmup sweep
  - 采集/生成两条参考链路：SDE debugtrace（真实 mem 访问）与 perf Intel PT（recover 后 mem 访问）
  - 产出：每个 case 的 SDE/perf 分析 JSON + 相似度 compare JSON + 批量 `summary.json`/`summary.csv`

- `run_spec5_perf_trace_analysis.py`
  - SPEC 5xx **仅 perf**（不跑 SDE、不做相似度对比）
  - 产出：每个 case 的 perf recovered mem JSONL + `*.perf.*.analysis.json` + 批量 `summary.json`/`summary.csv`

- `run_cloud_perf_trace_analysis.py`
  - 在 Docker 中启动典型 cloud 服务与压测客户端（redis/nginx/haproxy/postgres/mysql/memcached 等）
  - 对单 worker 线程采集 perf Intel PT，随后复用同一条 perf-only 后处理管线
  - 产出：每个 `<service>.<config>/` 下的 `intermediate/`、`mem/`、`report/`

- `analyze_sde_trace_uc.c` + `build_recover_mem_addrs_uc.sh`  
  One-pass SDE analyzer for debugtrace input. In a single scan, it can emit:
  - data mem JSONL (`*.sde.mem.real.jsonl`)
  - instruction trace (`*.sde.insn.trace.txt`)
  - SDE data analysis JSON
  - SDE instruction analysis JSON

- `recover_mem_addrs_uc.c` + `build_recover_mem_addrs_uc.sh`  
  Unicorn-based C recovery tool that reconstructs memory accesses from
  instruction trace (`<tid> <time>: <ip> insn: <bytes...>`). It now also
  supports one-pass analysis output (instruction + recovered-data profiles).

- `perf_pipeline.py`
  - 复用的 perf-only 后处理核心：`perf.data → perf script → insn trace → recover_mem_addrs_uc → analysis JSON`
  - 被 `run_spec5_*` 与 `run_cloud_perf_trace_analysis.py` 共用

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

### 2) Run SPEC batch (SDE vs perf) comparison

```bash
python3 run_spec5_sde_perf_similarity.py \
  --warmup-sweep 5,60,120 \
  --output-base outputs/spec5_sde_perf_subset
```

### 3) Run SPEC batch (perf-only)

```bash
python3 run_spec5_perf_trace_analysis.py \
  --warmup-sweep 10,60 \
  --output-base outputs/spec5_perf_trace_only
```

### 4) Run cloud apps (perf-only)

> 该脚本会操作 Docker 与 perf，通常需要 root 权限（取决于机器配置与 `perf_event_paranoid`）。

```bash
sudo python3 run_cloud_perf_trace_analysis.py \
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
  - `intermediate/`: `*.perf.insn.trace.txt`, `*.perf.script.txt`（可能会被清理/截断）
  - `mem/`: `*.perf.mem.recovered.jsonl`
  - `report/`: `*.perf.*.analysis.json`、stderr/logs、可选 portrait 产物

## MIIC interval model backend (optional)

`run_miic_interval_backend.py` consumes existing analysis JSONs produced by the perf-only pipeline:
- `*.perf.recovered.data.analysis.json`
- `*.perf.inst.analysis.json` (if present)
- `*.insn.portrait.json` (if present; enabled by default in perf pipeline)

Example:

```bash
python3 run_miic_interval_backend.py \
  --output-base outputs/cloud_trace \
  --out-csv outputs/cloud_trace/miic_interval_predictions.csv
```

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