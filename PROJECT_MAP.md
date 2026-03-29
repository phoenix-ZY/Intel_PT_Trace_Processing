# Intel_PT_Trace_Processing 项目结构（当前）

当前主链路是“Python 编排 + C 处理核心”：

- 编排：`run_spec5_sde_perf_similarity.py`
- C 处理前端：`analyze_sde_trace_uc`、`recover_mem_addrs_uc`
- C 共用特征核心：`trace_feature_core.*`
- 比较器：`compare_mem_trace_metrics.py`

## 1) 主流程与职责

- `run_spec5_sde_perf_similarity.py`
  - 对 SPEC 5xx 批量跑 warmup sweep
  - SDE 路径：调用 `analyze_sde_trace_uc`（一趟输出 SDE mem/insn + data/inst analysis）
  - perf 路径：调用 `recover_mem_addrs_uc`（一趟恢复 mem + 输出 data/inst analysis）
  - 最后调用 `compare_mem_trace_metrics.py` 产出相似度 JSON，并汇总 `summary.json/csv`

- `analyze_sde_trace_uc.c`
  - 输入：SDE debugtrace
  - 输出（可选组合）：
    - `*.sde.mem.real.jsonl`
    - `*.sde.insn.trace.txt`
    - `*.sde.data.analysis.json`
    - `*.sde.inst.analysis.json`

- `recover_mem_addrs_uc.c`
  - 输入：perf instruction trace（`<tid> <time>: <ip> insn: ...`）
  - 输出：
    - `*.perf.mem.recovered.jsonl`
    - `*.perf.recovered.data.analysis.json`
    - `*.perf.inst.analysis.json`

- `trace_feature_core.h` / `trace_feature_core.c`
  - 统一事件统计内核（RD/SDP/stride）
  - SDE/perf 两条链路共用

## 2) 常见输出目录

- `outputs/spec5_sde_perf_subset/<bench>/<warmup>/inputs`
  - SDE debugtrace 原始输入

- `outputs/spec5_sde_perf_subset/<bench>/<warmup>/intermediate`
  - perf.data、perf.insn.trace 等中间文件

- `outputs/spec5_sde_perf_subset/<bench>/<warmup>/mem`
  - `*.sde.mem.real.jsonl`
  - `*.perf.mem.recovered.jsonl`

- `outputs/spec5_sde_perf_subset/<bench>/<warmup>/report`
  - `*.sde.data.analysis.json`
  - `*.sde.inst.analysis.json`
  - `*.perf.recovered.data.analysis.json`
  - `*.perf.inst.analysis.json`
  - `*.sde_vs_perf*.compare.json`

## 3) 构建与运行

```bash
cd Intel_PT_Trace_Processing
bash build_recover_mem_addrs_uc.sh
python3 run_spec5_sde_perf_similarity.py --warmup-sweep 5,20
```

## 4) 说明

旧的 Python 转换/单 trace 分析链路（`sde_debugtrace_convert.py`、`analyze_mem_trace_profiles.py`、`reuse_distance.py`）已移除，不再是当前主链路的一部分。
