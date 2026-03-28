# Intel_PT_Trace_Processing 整理说明

这份文档用于回答三个问题：

1. 运行哪些代码？
2. 输入的 trace 是哪些？
3. 最终得到哪些结果？

---

## 一、主流程（从采集到结果）

推荐按这个顺序理解：

1. `run_sde_spec_rd_experiment.sh`
   - 一键流程入口（采集 + 转换 + 恢复 + 统计）。
2. `sde_debugtrace_convert.py`
   - 把 SDE debugtrace 转成：
     - 真实内存访问流（JSONL）
     - 指令字节流（给 Unicorn 恢复器）
3. `recover_mem_addrs.py`
   - 从指令字节流推断（虚拟）内存访问地址，输出 JSONL。
4. `reuse_distance.py`
   - 对内存访问流计算 reuse distance（可对 real/virtual 分别算）。

---

## 二、运行代码（脚本职责）

- `run_sde_spec_rd_experiment.sh`
  - 一次性完成 5 步实验，默认 benchmark 是 `505.mcf_r`。
  - 输出文件名由 `--out-prefix` 控制（默认 `mcf`）。

- `sde_debugtrace_convert.py`
  - 输入：SDE debugtrace 文本（含 `Read/Write/INS`）。
  - 输出：
    - `*.mem.real.jsonl`（真实地址流）
    - `*.insn.trace.txt`（`<tid> <time>: <ip> insn: ...`）

- `recover_mem_addrs.py`
  - 输入：`*.insn.trace.txt` 或同格式 `trace.txt`。
  - 输出：`*.mem.virtual.jsonl`（虚拟恢复地址流）

- `reuse_distance.py`
  - 输入：`*.mem.real.jsonl` 或 `*.mem.virtual.jsonl`
  - 输出：`*.rd.*.txt`（统计报告）

---

## 三、输入 trace（你目录里常见的）

- `inputs/trace.txt`
  - perf/PT 风格指令 trace（行内有 `insn: xx xx ...`）
  - 可直接喂给 `recover_mem_addrs.py`

- `inputs/sde_mcf.debugtrace.txt`
  - SDE debugtrace（`Read/Write/INS` 交织）
  - 可喂给 `sde_debugtrace_convert.py`

- `inputs/sde_mcf.slice.txt`
  - 同类 SDE 采样/切片 trace（用于局部分析）

- `outputs/disasm/trace.xed.txt`
  - 由 `trace.txt` 反汇编得到（便于人工看汇编）

---

## 四、结果文件（你现在目录里的）

- 内存访问流
  - `outputs/mem/mcf.mem.real.jsonl`：从 SDE 直接提取的真实访问
  - `outputs/mem/mcf.mem.virtual.jsonl`：从指令流恢复出的虚拟访问
  - `outputs/mem/mem_access.final.jsonl`：恢复结果大文件（历史产物）

- reuse distance 报告
  - `outputs/rd/mcf.rd.real.txt`
  - `outputs/rd/mcf.rd.virtual.txt`
  - `outputs/rd/reuse_distance.final.txt`（历史报告）

- 中间产物
  - `intermediate/mcf.insn.trace.txt`：给恢复器的指令输入

---

## 五、最小可复现实验命令

### A) 已有 `inputs/sde_mcf.debugtrace.txt` 时（不重新跑 SPEC/SDE）

```bash
python3 sde_debugtrace_convert.py \
  -i inputs/sde_mcf.debugtrace.txt \
  --mem-out outputs/mem/mcf.mem.real.jsonl \
  --insn-out intermediate/mcf.insn.trace.txt

python3 recover_mem_addrs.py \
  -i intermediate/mcf.insn.trace.txt \
  -o outputs/mem/mcf.mem.virtual.jsonl \
  --minimal --salvage-invalid-mem --salvage-fill-writes --salvage-fill-seed 1

python3 reuse_distance.py -i outputs/mem/mcf.mem.real.jsonl --line-size 64 --top 10 --report-out outputs/rd/mcf.rd.real.txt
python3 reuse_distance.py -i outputs/mem/mcf.mem.virtual.jsonl --line-size 64 --top 10 --report-out outputs/rd/mcf.rd.virtual.txt
```

### B) 一键全流程（重新跑 benchmark）

```bash
bash run_sde_spec_rd_experiment.sh --out-prefix mcf
```

---

## 六、建议的命名约定（后续不容易乱）

对每次实验统一用一个前缀，例如 `mcf_win1`，固定产出：

- `inputs/mcf_win1.sde.slice.txt`
- `outputs/mem/mcf_win1.mem.real.jsonl`
- `intermediate/mcf_win1.insn.trace.txt`
- `outputs/mem/mcf_win1.mem.virtual.jsonl`
- `outputs/rd/mcf_win1.rd.real.txt`
- `outputs/rd/mcf_win1.rd.virtual.txt`

这样你只看前缀就能知道一整套输入/中间件/结果是否成对齐全。
