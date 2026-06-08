from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

from intel_pt_trace_processing.collect.cloud_perf_collect import collect_traces_for_config
from intel_pt_trace_processing.collect.perf_targets import cpu_perf_target
from intel_pt_trace_processing.workloads.cloud_runtime import (
    docker_inspect_pid,
    docker_perf_event_cgroup,
    log,
    pid_alive,
)


def _import_cbs_offline_lib(cbs_root: Path):
    scripts = cbs_root / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import offline_workload_lib as owl

    return owl


def run_single_condition(
    *,
    condition,
    cbs_root: Path,
    output_dir: Path,
    perf_tool: Path,
    offline_cpuset: str,
    offline_mems: str | None,
    offline_container: str | None,
    warmup_duration: int,
    interval: float,
    record_duration: float,
    max_samples: int,
    perf_mmap_pages: str,
    perf_pt_noretcomp: int,
    sudo_perf: bool,
    collect_mode: str = "pt",
    perf_stat_events: str = "cycles,instructions",
    run_tag: str | None = None,
) -> int:
    owl = _import_cbs_offline_lib(cbs_root)
    ctx = owl.resolve_context(
        cbs_root_path=cbs_root,
        cpuset=offline_cpuset,
        mems=offline_mems,
        container_name=offline_container,
    )
    run_tag = run_tag or output_dir.name
    log_path = owl.container_log_path(ctx, condition, run_tag)
    bench_name = condition.condition_id
    sample_count = 0

    if owl.container_running(ctx.container_name):
        owl.stop_container(ctx)

    owl.ensure_container(ctx)
    try:
        owl.start_condition(ctx, condition, log_path)
        owl.wait_for_workload(ctx)
        log("🔥", f"Warming up {bench_name} for {warmup_duration}s...")
        time.sleep(float(warmup_duration))

        main_pid = docker_inspect_pid(ctx.container_name)
        if main_pid is None:
            log("❌", f"Cannot get PID for {ctx.container_name}")
            return 0

        try:
            Path(f"/proc/{main_pid}/maps").read_text(encoding="utf-8", errors="replace")
            maps_readable = True
        except (OSError, PermissionError):
            maps_readable = False
        if not maps_readable and not sudo_perf:
            log(
                "❌",
                f"Cannot read /proc/{main_pid}/maps; rerun with --sudo-perf",
            )
            return 0

        perf_cgroup = docker_perf_event_cgroup(main_pid)
        if perf_cgroup is None:
            log("❌", f"Cannot resolve perf_event cgroup for {ctx.container_name} (PID {main_pid})")
            return 0

        perf_target = cpu_perf_target(offline_cpuset)
        log(
            "🚀",
            f"Tracing {bench_name} on CPU(s) {perf_target.cpu} with perf -C -G {perf_cgroup}",
        )

        keeper = subprocess.Popen(["sleep", "86400"])
        try:
            pt_event = f"intel_pt/cyc,noretcomp={int(perf_pt_noretcomp)}/u"
            sample_count = collect_traces_for_config(
                perf_tool=perf_tool,
                bench_name=bench_name,
                perf_target=perf_target,
                monitor_pid=main_pid,
                output_dir=output_dir,
                interval=interval,
                record_duration=record_duration,
                max_samples=max_samples,
                bench_process=keeper,
                perf_mmap_pages=perf_mmap_pages,
                intel_pt_event=pt_event,
                perf_cgroup=perf_cgroup,
                perf_command_prefix=("sudo", "-n") if sudo_perf else (),
                collect_mode=collect_mode,
                perf_stat_events=perf_stat_events,
            )
        finally:
            if keeper.poll() is None:
                keeper.kill()
                keeper.wait()
    finally:
        owl.stop_container(ctx)

    if not pid_alive(main_pid):
        log("ℹ️", f"{bench_name}: container main PID exited during collection")
    log("✅", f"{bench_name} done — {sample_count} samples collected.")
    return int(sample_count)
