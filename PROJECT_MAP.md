# Intel_PT_Trace_Processing 项目结构（当前）

当前主链路是“Python 编排 + C 处理核心”，并且 perf-only 的后处理逻辑已抽成可复用模块（`perf_pipeline.py`）。

入口脚本（你大概率会从这里开始）：
- **SPEC：SDE vs perf 对比**：`run_spec5_sde_perf_similarity.py`
- **SPEC：perf-only 特征提取**：`run_spec5_perf_trace_analysis.py`
- **Cloud：Docker 服务采集 + perf-only 特征提取**：`run_cloud_perf_trace_analysis.py`
- **下游模型（可选）**：`run_miic_interval_backend.py`

## 1) 主流程与职责

- `run_spec5_sde_perf_similarity.py`
  - 对 SPEC 5xx 批量跑 warmup sweep
  - SDE 路径：调用 `analyze_sde_trace_uc`（一趟输出 SDE mem/insn + data/inst analysis）
  - perf 路径：调用 `recover_mem_addrs_uc`（一趟恢复 mem + 输出 data/inst analysis）
  - 最后调用 `compare_mem_trace_metrics.py` 产出相似度 JSON，并汇总 `summary.json/csv`

- `run_spec5_perf_trace_analysis.py`
  - SPEC 5xx 批量跑 warmup sweep，但 **不启用 SDE**、也不生成相似度 compare
  - perf 路径复用 `perf_pipeline.perf_postprocess_one`
  - 适合做“仅 perf 的特征导出 / 训练数据生成 / cloud 与 SPEC 的统一格式对齐”

- `run_cloud_perf_trace_analysis.py`
  - 在 Docker 中跑典型 cloud 服务与压测客户端
  - 采集：`perf record`（Intel PT）针对单线程（busiest tid）
  - 后处理：复用 `perf_pipeline.perf_postprocess_one`，输出与 SPEC perf-only 相同 schema 的分析 JSON

- `run_miic_interval_backend.py`
  - 遍历已有输出目录（SPEC 或 cloud layout），寻找 `report/*.perf.recovered.data.analysis.json`
  - 读取 data/inst locality feature + 可选 portrait，运行 interval-style 周期栈模型并导出 CSV/JSON
  - 模型实现见 `miic_interval_model.py`

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

- `perf_pipeline.py`
  - perf-only 后处理复用层：`perf.data → perf script → insn trace → recover_mem_addrs_uc → analysis JSON`
  - 关键函数：
    - `add_perf_postprocess_args()` / `validate_perf_postprocess_args()`
    - `perf_postprocess_one()`：返回 aux_lost / trace_errors / insn_lines 与各输出路径

- `trace_feature_core.h` / `trace_feature_core.c`
  - 统一事件统计内核（RD/SDP/stride）
  - SDE/perf 两条链路共用

- `compare_mem_trace_metrics.py`
  - 输入：两个 analysis JSON（通常一个来自 SDE，一个来自 perf recovered）
  - 输出：相似度指标 JSON（RD/SDP/stride 等）

- `analyze_insn_trace_portrait.py`
  - 对 instruction trace 做“画像”统计（mix / branch / 频率等），并提供 flatten 工具函数
  - perf-only 链路可选启用（默认开启）用于产出 `*.insn.portrait.json`

- `export_perf_full_features.py` / `export_trace_features_to_excel.py`
  - 从 `report/*.analysis.json` 汇总导出 CSV/XLSX（用于快速分析/画图）

- `plot_data_feature_similarity.py`
  - 对比/可视化 similarity 或 feature 分布（研究/实验用脚本）

## 2) 常见输出目录

### SPEC（SDE vs perf / perf-only）

- `outputs/<spec_out>/<bench>/<warmup>/inputs`
  - SDE debugtrace 原始输入（仅 SDE vs perf 链路会有）

- `outputs/<spec_out>/<bench>/<warmup>/intermediate`
  - `perf.data`、`*.perf.script.txt`、`*.perf.insn.trace.txt`、可选 portrait 临时文件

- `outputs/<spec_out>/<bench>/<warmup>/mem`
  - `*.sde.mem.real.jsonl`（仅 SDE vs perf）
  - `*.perf.mem.recovered.jsonl`

- `outputs/<spec_out>/<bench>/<warmup>/report`
  - `*.sde.data.analysis.json`
  - `*.sde.inst.analysis.json`
  - `*.perf.recovered.data.analysis.json`
  - `*.perf.inst.analysis.json`
  - `*.sde_vs_perf*.compare.json`
  - `*.perf.script.stderr.txt` / `*.perf.recover.report.json` 等日志与健康信息

### Cloud（perf-only）

- `outputs/cloud_trace/<service>.<config>/intermediate`
  - `*.perf.script.txt`、`*.perf.insn.trace.txt`、可选 portrait 临时文件

- `outputs/cloud_trace/<service>.<config>/mem`
  - `*.perf.mem.recovered.jsonl`

- `outputs/cloud_trace/<service>.<config>/report`
  - `*.perf.recovered.data.analysis.json`
  - `*.perf.inst.analysis.json`
  - `*.insn.portrait.json`（若启用 `--insn-portrait`）
  - stderr/logs

## 3) 构建与运行

```bash
cd Intel_PT_Trace_Processing
bash build_recover_mem_addrs_uc.sh
python3 run_spec5_sde_perf_similarity.py --warmup-sweep 5,20
```

## 4) 说明

旧的 Python 转换/单 trace 分析链路（`sde_debugtrace_convert.py`、`analyze_mem_trace_profiles.py`、`reuse_distance.py`）已移除，不再是当前主链路的一部分。
