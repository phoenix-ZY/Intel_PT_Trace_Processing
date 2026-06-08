# Cloud workload config

**Canonical file:** `colocation-bench-suite/cloud_bench_configs/workloads.cloud.json`

Intel PT and CBS interference both load that JSON by default (via
`COLOCATION_BENCH_SUITE_DIR` / `CBS_ROOT`). Startup orchestration is shared in
`colocation-bench-suite/scripts/cloud_workload_lib.py` (`cloud_workload_ctl.py`
CLI for shell experiments).

**Service tuning** (memory, threads, QPS, DB sizes) lives only in CBS
`conf/profiles/cloud_realistic.env`. The JSON wires:

- container names, helpers, ready checks, prepare steps
- thin `start_cmd` / `load_cmd` → CBS `online/*` launchers
- cpusets / warmup / bench duration overrides for a specific machine

Optional: copy the canonical JSON to `workloads.machine.json` (gitignored) and
pass `--workload-config …/workloads.machine.json` to override placement or
durations without editing the CBS copy.

TaoBench and Feedsim use split/host-network DCPerf containers; tuning is still
only in `cloud_realistic.env`.
