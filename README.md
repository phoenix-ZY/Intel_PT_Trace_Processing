# Intel_PT_Trace_Processing

## Recover memory access addresses from `perf --insn-trace`

This directory includes a small emulator utility that takes a decoded Intel PT
instruction stream like:

```
<tid> <time>:      <ip> insn: <hex bytes...>
```

and **recovers memory read/write addresses** by emulating each instruction with
Unicorn (x86_64), using virtual initial registers + a virtual memory space.

### Install

```bash
python3 -m pip install -r Intel_PT_Trace_Processing/requirements.txt
```

### Run

```bash
python3 Intel_PT_Trace_Processing/recover_mem_addrs.py \
  -i Intel_PT_Trace_Processing/inputs/trace.txt \
  -o Intel_PT_Trace_Processing/outputs/mem/mem_access.jsonl \
  --max-insns 100000
```

### Recommended folder layout

- `inputs/`: source traces (`trace.txt`, `*.debugtrace.txt`, `*.slice.txt`)
- `intermediate/`: generated instruction traces (`*.insn.trace.txt`)
- `outputs/mem/`: memory streams (`*.mem.real.jsonl`, `*.mem.virtual.jsonl`)
- `outputs/rd/`: reuse distance reports (`*.rd.real.txt`, `*.rd.virtual.txt`)
- `outputs/disasm/`: decoded/disassembly artifacts (`trace.xed.txt`, etc.)

### Output format

JSON Lines (`.jsonl`), one event per line. Example fields:

- `ip`: original trace IP (string like `0x...`)
- `access`: `"read"` or `"write"`
- `addr`: memory address accessed
- `size`: access size in bytes
- `read_value` / `write_value`: best-effort values (may be `null` for some reads)

### Notes / limitations

- The trace does not include real runtime register/memory state. This tool uses
  **virtual** state (zero or deterministic pseudo-random). So recovered
  addresses are *plausible under that virtual state*, not guaranteed identical
  to the real run.
- Control-flow is forced to follow the trace: after each instruction executes,
  RIP is overwritten to the next trace IP. This allows running through indirect
  branches/returns even with incomplete code context.