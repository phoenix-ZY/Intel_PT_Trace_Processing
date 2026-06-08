from __future__ import annotations

import argparse
import copy
import os
import sys
import time
from pathlib import Path

from intel_pt_trace_processing.collect.cloud_perf_collect import collect_traces_for_config
from intel_pt_trace_processing.collect.cloud_postprocess import (
    cloud_postprocess_reports_complete,
    iter_perf_data_files,
)
from intel_pt_trace_processing.collect.perf_targets import cpu_perf_target
from intel_pt_trace_processing.perf.selection import load_selection_sidecar
from intel_pt_trace_processing.workloads.cloud_runtime import (
    docker_inspect_pid,
    docker_perf_event_cgroup,
    docker_stop_rm,
    log,
    pid_alive,
)

DEFAULT_WARMUP_DURATION = 20
DEFAULT_PERF_MMAP_PAGES = "2048,16384"


def _import_cbs_workload_lib(cbs_root: Path):
    scripts = cbs_root / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import cloud_workload_lib as cwl

    return cwl


def _cbs_root_from_args(cli_args: argparse.Namespace | None) -> Path:
    if cli_args is not None and getattr(cli_args, "colocation_bench_suite_dir", None):
        return Path(cli_args.colocation_bench_suite_dir)
    for key in ("COLOCATION_BENCH_SUITE_DIR", "CBS_ROOT"):
        value = os.environ.get(key, "").strip()
        if value:
            return Path(value)
    return Path.home() / "colocation-bench-suite"


def _target_role(config: dict) -> dict:
    return config.get(
        "target_role",
        {
            "name": "server",
            "container_name": config["container_name"],
            "start_cmd": config["server_cmd"],
            "ready_checks": [],
        },
    )


def _helper_roles(config: dict) -> list[dict]:
    return list(config.get("helper_roles", []))


def _cleanup_helpers(helper_roles: list[dict]) -> None:
    for role in reversed(helper_roles):
        docker_stop_rm(str(role["container_name"]))


def run_single_config(
    config: dict,
    perf_tool: Path,
    output_dir: Path,
    project_dir: Path,
    interval: float,
    record_duration: float,
    bench_duration: int,
    max_samples: int,
    warmup_duration: int = DEFAULT_WARMUP_DURATION,
    cli_args: argparse.Namespace | None = None,
):
    """Run one service config via CBS cloud_workload_lib and collect PT samples."""
    del project_dir
    service_type = config["service_type"]
    config_name = config["config_name"]
    bench_name = f"{service_type}.{config_name}"
    runtime_args = copy.copy(cli_args)
    if runtime_args is not None:
        for name in ("target_cpuset", "bench_cpuset", "helper_cpuset"):
            if name in config:
                setattr(runtime_args, name, str(config[name]))
    effective_warmup = int(config.get("warmup_duration_s", warmup_duration))
    effective_bench_duration = int(config.get("bench_duration_s", bench_duration))
    runtime_target_cpuset = (
        str(getattr(runtime_args, "target_cpuset", ""))
        if runtime_args is not None
        else ""
    )
    default_perf_cpus = 6
    if runtime_args is not None:
        default_perf_cpus = getattr(runtime_args, "perf_cpus", None) or getattr(
            runtime_args, "perf_cpu", 6
        )
    runtime_perf_cpus = str(config.get("perf_cpus", default_perf_cpus))

    for _idx, p in list(iter_perf_data_files(output_dir, bench_name)):
        try:
            if p.is_file() and p.stat().st_size == 0:
                try:
                    p.unlink()
                except FileNotFoundError:
                    pass
        except OSError:
            pass

    existing_samples = iter_perf_data_files(output_dir, bench_name)
    existing_n = len(existing_samples)
    has_perf = existing_n > 0
    post_complete = cloud_postprocess_reports_complete(output_dir, bench_name)
    selections_verified = has_perf and all(
        bool((load_selection_sidecar(path) or {}).get("buildid_cache_verified", False))
        for _, path in existing_samples
    )
    skip_collect = has_perf and selections_verified and existing_n >= max_samples
    if skip_collect:
        log(
            "⏭️",
            f"Skipping {bench_name} trace collection (verified perf samples={existing_n})",
        )
    else:
        if has_perf and not selections_verified:
            log("♻️", f"{bench_name}: perf.data cache ownership is unverified — re-collecting PT")
        elif has_perf and post_complete and existing_n < max_samples:
            log(
                "➕",
                f"{bench_name}: have {existing_n} sample(s), need {max_samples}; collecting more samples…",
            )
        print(f"\n{'─' * 60}")
        print(f"  🧪  {bench_name}")
        print(f"{'─' * 60}")
        log(
            "🧭",
            f"target_cpuset={runtime_target_cpuset} perf_cpus={runtime_perf_cpus} "
            f"warmup={effective_warmup}s load_duration={effective_bench_duration}s",
        )

    if not skip_collect:
        target_role = _target_role(config)
        helper_roles = _helper_roles(config)
        container_name = str(target_role["container_name"])
        cbs_root = _cbs_root_from_args(runtime_args)
        cwl = _import_cbs_workload_lib(cbs_root)
        ctx = cwl.resolve_context(
            config,
            cbs_root_path=cbs_root,
            target_cpuset=runtime_target_cpuset,
            helper_cpuset=str(
                getattr(runtime_args, "helper_cpuset", "")
                or config.get("helper_cpuset", config.get("bench_cpuset", ""))
            ),
            bench_cpuset=str(
                getattr(runtime_args, "bench_cpuset", "")
                or config.get("bench_cpuset", "")
            ),
            config_name=config_name,
        )
        try:
            cwl.start_service(service_type, ctx, config=config)
        except RuntimeError as exc:
            log("❌", str(exc))
            return

        bench_process = cwl.popen_load(config, ctx, effective_bench_duration)

        log("🔥", f"Warming up for {effective_warmup}s before tracing...")
        warmup_deadline = time.monotonic() + effective_warmup
        while time.monotonic() < warmup_deadline:
            if bench_process.poll() is not None:
                log(
                    "❌",
                    f"Load exited during warmup (rc={bench_process.returncode}); "
                    f"skipping {bench_name}",
                )
                docker_stop_rm(container_name)
                _cleanup_helpers(helper_roles)
                return
            time.sleep(min(1.0, max(0.0, warmup_deadline - time.monotonic())))

        main_pid = docker_inspect_pid(container_name)
        if main_pid is None:
            log("❌", f"Cannot get PID for {container_name}")
            bench_process.kill()
            docker_stop_rm(container_name)
            _cleanup_helpers(helper_roles)
            return

        perf_target = cpu_perf_target(runtime_perf_cpus)
        monitor_pid = main_pid
        use_sudo_perf = (
            bool(getattr(runtime_args, "sudo_perf", False))
            if runtime_args is not None
            else False
        )
        try:
            Path(f"/proc/{main_pid}/maps").read_text(encoding="utf-8", errors="replace")
            maps_readable = True
        except (OSError, PermissionError):
            maps_readable = False
        if not maps_readable and not use_sudo_perf:
            log(
                "❌",
                f"Cannot read /proc/{main_pid}/maps; rerun with --sudo-perf so perf can record container mmap data",
            )
            bench_process.kill()
            bench_process.wait()
            docker_stop_rm(container_name)
            _cleanup_helpers(helper_roles)
            return
        perf_cgroup = docker_perf_event_cgroup(main_pid)
        if perf_cgroup is None:
            log("❌", f"Cannot resolve perf_event cgroup for {container_name} (PID {main_pid})")
            bench_process.kill()
            bench_process.wait()
            docker_stop_rm(container_name)
            _cleanup_helpers(helper_roles)
            return
        log(
            "🚀",
            f"Tracing CPU(s) {perf_target.cpu} with perf -C -G {perf_cgroup} "
            f"(container main PID {main_pid})",
        )

        if monitor_pid is not None and not pid_alive(monitor_pid):
            log("⚠️", "Perf monitor target is not alive — skipping.")
            bench_process.kill()
            docker_stop_rm(container_name)
            _cleanup_helpers(helper_roles)
            return

        mmap_pages = (
            runtime_args.perf_mmap_pages
            if runtime_args is not None
            else DEFAULT_PERF_MMAP_PAGES
        )
        nrc = (
            int(runtime_args.perf_pt_noretcomp)
            if runtime_args is not None
            else 0
        )
        pt_event = f"intel_pt/cyc,noretcomp={nrc}/u"
        try:
            sample_count = collect_traces_for_config(
                perf_tool=perf_tool,
                bench_name=bench_name,
                perf_target=perf_target,
                monitor_pid=monitor_pid,
                output_dir=output_dir,
                interval=interval,
                record_duration=record_duration,
                max_samples=max_samples,
                bench_process=bench_process,
                perf_mmap_pages=mmap_pages,
                intel_pt_event=pt_event,
                perf_cgroup=perf_cgroup,
                perf_command_prefix=("sudo", "-n") if use_sudo_perf else (),
                collect_mode=str(getattr(runtime_args, "collect_mode", "pt")) if runtime_args is not None else "pt",
                perf_stat_events=str(getattr(runtime_args, "perf_stat_events", "cycles,instructions,branches,branch-misses,cache-references,cache-misses,stalled-cycles-frontend,stalled-cycles-backend,ref-cycles,task-clock,context-switches,cpu-migrations,page-faults")) if runtime_args is not None else "cycles,instructions,branches,branch-misses,cache-references,cache-misses,stalled-cycles-frontend,stalled-cycles-backend,ref-cycles,task-clock,context-switches,cpu-migrations,page-faults",
                start_index=existing_n if (has_perf and selections_verified and existing_n < max_samples) else 0,
            )
        finally:
            if bench_process.poll() is None:
                bench_process.kill()
            bench_process.wait()
            docker_stop_rm(container_name)
            _cleanup_helpers(helper_roles)

        log("✅", f"{bench_name} done — {sample_count} samples collected.\n")
