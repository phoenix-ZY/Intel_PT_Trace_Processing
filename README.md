# Intel_PT_Trace_Processing

Turn one Intel PT `perf.data` file into **software-feature JSON** (`trace-profile-v2`):
instruction mix, recovered data/instruction memory locality, branches, syscalls,
register dependencies, and IPC.

**Workload launch and PT collection** live in **colocation-bench-suite**
(`experiments/intel_pt/`, `PROFILE_INTEL_PT=1` offline profiling).
This repo is the **processing API only** — `perf.data` in, features out.

CBS integration details: `colocation-bench-suite/docs/CBS_IPT_ALIGNMENT.md`.

## Inputs and output

| | What |
|---|------|
| **Required** | `perf.data` recorded with **Intel PT** (e.g. `intel_pt/cyc,...`; not PMU-only `perf stat`) |
| **Required** | `trace_feature_processor` binary at repo root (`bash build_trace_tools.sh`) |
| **Required** | Linux `perf` with PT support (for `perf script --insn-trace`) |
| **Optional** | `--symfs DIR` — decode off-host with workload binaries at matching paths |
| **Optional** | `--pid` + `--pid-tree` — decode only a process and its descendants |
| **Output** | `trace-profile-v2` JSON; modeling uses `features.*` only (`metadata` is health/debug) |

Output feature groups: `instruction_mix`, `data_memory`, `instruction_memory`, `branch`,
`syscall`, `register_dependency`, `ipc`.

## Public API

```bash
# XED example: XED_PREFIX=/path/to/xed/obj/wkit bash build_trace_tools.sh
bash build_trace_tools.sh

python3 trace_feature_api.py perf.data -o features.json
# optional: --pid 12345 --symfs /path/to/rootfs
```

```python
from trace_feature_api import extract_software_features

profile = extract_software_features("perf.data")
# profile["features"]["data_memory"], profile["features"]["instruction_mix"], ...
```

CBS calls the same API via `colocation-bench-suite/tools/intel_pt_features.py` and
flattens `features.*` into modeling CSVs (`pt_*` columns).

## Pipeline

```text
perf.data
  → perf script --insn-trace (pipe)
  → trace_feature_processor (C, stdin)
  → Python build_trace_profile()
  → trace-profile-v2 JSON
```

| Layer | Path | Role |
|-------|------|------|
| Public API | `trace_feature_api.py` | `extract_software_features(perf.data)` |
| Wrapper | `src/.../perf/processor.py` | Config, temp dirs, one-shot entry |
| Stream | `src/.../perf/stream.py` | `perf script` → C processor → JSON |
| PID filter | `src/.../perf/selection.py` | `discover_process_tree_pids()` when `--pid` is set |
| Feature schema | `src/.../core/feature_groups.py` | Seven `features.*` groups |
| C processor | `csrc/trace_feature_processor.c` | Unicorn recovery + XED portrait + memory stats |

`build_trace_tools.sh` also builds `analyze_sde_trace_uc` for SDE validation only;
the main line needs **`trace_feature_processor`** only.

Build deps: Linux `perf` (Intel PT), Unicorn, XED (`XED_PREFIX` if not in default paths).

## Repository layout

```text
trace_feature_api.py              # stable downstream entry
build_trace_tools.sh
trace_feature_processor           # main-line binary (after build)
csrc/
  trace_feature_core.c            # shared RD/stride/SDP statistics
  recover_mem_addrs_uc.c          # Unicorn recovery (library inside processor)
  trace_feature_processor.c       # PT one-pass processor
  analyze_sde_trace_uc.c          # SDE analyzer (validation only)
src/intel_pt_trace_processing/
  perf/                           # perf.data → trace-profile-v2
  core/                           # feature group builders
validation/                       # SDE vs perf experiments (see validation/README.md)
```

`core/commands.py` and `selection` sidecar helpers are used by validation batch
collection only; the API path does not require them.

## SDE validation (off main line)

Host-native SPEC + Intel SDE debugtrace comparison for memory-recovery quality.
Not used in CBS colocation experiments.

```bash
python3 validation/run_spec5_sde_perf_similarity.py \
  --warmup-sweep 5,60,120 \
  --output-base outputs/spec5_sde_perf_subset
```

See [`validation/README.md`](validation/README.md).

## Limitation

Recovered memory addresses are plausible under Unicorn emulation, not guaranteed to
match runtime addresses. Use SDE validation (`validation/`) to assess recovery quality.
