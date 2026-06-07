from __future__ import annotations

import argparse
import copy
import subprocess
import time
from pathlib import Path

from intel_pt_trace_processing.collect.cloud_perf_collect import collect_traces_for_config
from intel_pt_trace_processing.collect.cloud_postprocess import (
    cloud_postprocess_reports_complete,
    iter_perf_data_files,
)
from intel_pt_trace_processing.collect.perf_targets import cpu_perf_target
from intel_pt_trace_processing.perf.selection import load_selection_sidecar
from intel_pt_trace_processing.workloads.cloud import docker_cpuset_arg
from intel_pt_trace_processing.workloads.cloud_runtime import (
    docker_exec,
    docker_inspect_pid,
    docker_perf_event_cgroup,
    docker_stop_rm,
    log,
    mysql_ready_from_bench_client,
    nginx_ready_from_bench_client,
    pid_alive,
    run_cmd,
    sysbench_output_looks_failed,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_DIR = REPO_ROOT
DEFAULT_WARMUP_DURATION = 20
DEFAULT_PERF_MMAP_PAGES = "2048,16384"


def _render_workload_cmd(
    cmd: str,
    *,
    bench_duration: int | None = None,
    cli_args: argparse.Namespace | None = None,
    project_dir: Path | None = None,
    output_dir: Path | None = None,
    bench_name: str | None = None,
    service_type: str | None = None,
    config_name: str | None = None,
) -> str:
    rendered = cmd
    target_cpuset = str(getattr(cli_args, "target_cpuset", "") if cli_args is not None else "")
    bench_cpuset = str(getattr(cli_args, "bench_cpuset", "") if cli_args is not None else "")
    helper_cpuset = str(getattr(cli_args, "helper_cpuset", "") if cli_args is not None else "")
    replacements = {
        "bench_duration": "" if bench_duration is None else str(bench_duration),
        "target_cpuset": target_cpuset,
        "bench_cpuset": bench_cpuset,
        "helper_cpuset": helper_cpuset,
        "target_cpuset_arg": docker_cpuset_arg(target_cpuset or None),
        "bench_cpuset_arg": docker_cpuset_arg(bench_cpuset or None),
        "helper_cpuset_arg": docker_cpuset_arg(helper_cpuset or None),
        "project_dir": "" if project_dir is None else str(project_dir),
        "output_dir": "" if output_dir is None else str(output_dir),
        "bench_name": "" if bench_name is None else bench_name,
        "service_type": "" if service_type is None else service_type,
        "config_name": "" if config_name is None else config_name,
        "colocation_bench_suite_dir": str(
            getattr(
                cli_args,
                "colocation_bench_suite_dir",
                "/home/huangtianhao/colocation-bench-suite",
            )
            if cli_args is not None
            else "/home/huangtianhao/colocation-bench-suite"
        ),
    }
    for key, value in replacements.items():
        rendered = rendered.replace("{" + key + "}", value)
    return rendered


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


def _run_ready_check(
    check: dict,
    *,
    target_container_name: str,
    cli_args: argparse.Namespace | None = None,
    project_dir: Path | None = None,
    output_dir: Path | None = None,
    bench_name: str | None = None,
    service_type: str | None = None,
    config_name: str | None = None,
) -> bool:
    check_type = check.get("type")
    if check_type == "nginx_http":
        host = str(check["host"])
        path = str(check.get("path", "/index.html"))
        timeout_s = int(check.get("timeout_s", 60))
        if nginx_ready_from_bench_client(host, path, timeout_s=timeout_s):
            return True
        log("❌", f"Nginx HTTP endpoint not reachable from bench-client: {host}{path}")
        return False

    if check_type == "mysql_container":
        container_name = str(check.get("container_name", target_container_name))
        timeout_s = int(check.get("timeout_s", 90))
        log("⏳", "Waiting for MySQL to accept connections...")
        for _ in range(timeout_s):
            ping = docker_exec(container_name, "mysqladmin ping -ppassword --silent")
            if ping.returncode == 0:
                return True
            time.sleep(1)
        log("❌", "MySQL did not become ready in time")
        return False

    if check_type == "mysql_bench_client":
        host = str(check["host"])
        timeout_s = int(check.get("timeout_s", 120))
        if mysql_ready_from_bench_client(host, timeout_s=timeout_s):
            return True
        log("❌", "MySQL not reachable from bench-client (network/connectivity)")
        return False

    if check_type == "shell":
        timeout_s = int(check.get("timeout_s", 60))
        interval_s = float(check.get("interval_s", 1))
        cmd = _render_workload_cmd(
            str(check["cmd"]),
            cli_args=cli_args,
            project_dir=project_dir,
            output_dir=output_dir,
            bench_name=bench_name,
            service_type=service_type,
            config_name=config_name,
        )
        deadline = time.monotonic() + float(timeout_s)
        while time.monotonic() < deadline:
            pr = run_cmd(cmd, shell=True)
            if pr.returncode == 0:
                return True
            time.sleep(interval_s)
        log("❌", f"Shell ready check failed after {timeout_s}s: {cmd}")
        return False

    log("❌", f"Unknown ready check type: {check_type!r}")
    return False


def _run_prepare_step(
    step: dict,
    *,
    cli_args: argparse.Namespace | None,
    project_dir: Path,
    output_dir: Path,
    bench_name: str,
    service_type: str,
    config_name: str,
) -> bool:
    step_type = step.get("type")
    if step_type == "sysbench_mysql_prepare":
        cmd = _render_workload_cmd(
            str(step["cmd"]),
            cli_args=cli_args,
            project_dir=project_dir,
            output_dir=output_dir,
            bench_name=bench_name,
            service_type=service_type,
            config_name=config_name,
        )
        live = cli_args is not None and cli_args.verbose_sysbench_prepare
        log(
            "📊",
            "Running sysbench oltp_read_write prepare …"
            + (" (live output on stdout/stderr)" if live else ""),
        )
        t_prep = time.monotonic()
        if live:
            pr = subprocess.run(
                cmd,
                shell=True,
                text=True,
            )
        else:
            pr = run_cmd(cmd, shell=True)
        prep_elapsed = time.monotonic() - t_prep
        if pr.returncode != 0:
            err = (pr.stderr or "").strip() if pr.stderr is not None else ""
            if live and not err:
                err = "(see messages above)"
            log("❌", f"sysbench prepare failed (rc={pr.returncode}): {err}")
            return False
        if not live and sysbench_output_looks_failed(pr.stdout or "", pr.stderr or ""):
            log("❌", "sysbench prepare reported FATAL/connection errors (treat as failure)")
            if pr.stdout and pr.stdout.strip():
                for line in pr.stdout.strip().splitlines()[-12:]:
                    log("📋", f"  prepare out: {line}")
            if pr.stderr and pr.stderr.strip():
                for line in pr.stderr.strip().splitlines()[-12:]:
                    log("📋", f"  prepare err: {line}")
            return False
        log("✅", f"sysbench prepare done in {prep_elapsed:.1f}s")
        if not live and pr.stdout and pr.stdout.strip():
            for line in pr.stdout.strip().splitlines()[-8:]:
                log("📋", f"  prepare out: {line}")
        if not live and pr.stderr and pr.stderr.strip():
            for line in pr.stderr.strip().splitlines()[-8:]:
                log("📋", f"  prepare err: {line}")
        return True

    if step_type == "pgbench_init":
        container_name = str(step.get("container_name", "target-postgres"))
        cmd = str(step.get("cmd", "pgbench -i -s 2 -U postgres postgres"))
        log("🗄️", "Initializing pgbench database...")
        init_result = docker_exec(container_name, cmd)
        if init_result.returncode != 0:
            detail = (init_result.stderr or init_result.stdout or "").strip()
            log(
                "❌",
                f"pgbench init failed (rc={init_result.returncode}): "
                f"{detail or '(no output)'}",
            )
            return False
        time.sleep(int(step.get("settle_s", 3)))
        return True

    if step_type == "shell":
        cmd = _render_workload_cmd(
            str(step["cmd"]),
            cli_args=cli_args,
            project_dir=project_dir,
            output_dir=output_dir,
            bench_name=bench_name,
            service_type=service_type,
            config_name=config_name,
        )
        label = str(step.get("name", "shell prepare"))
        log("🧩", f"Running {label}...")
        pr = run_cmd(cmd, shell=True)
        if pr.returncode != 0:
            log("❌", f"{label} failed (rc={pr.returncode}): {(pr.stderr or '').strip()}")
            return False
        return True

    log("❌", f"Unknown prepare step type: {step_type!r}")
    return False


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
    """Run one service config and collect its perf samples."""
    service_type = config["service_type"]
    config_name = config["config_name"]
    container_name = config["container_name"]
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

    # If previous runs left 0-byte perf.data files, they will poison re-runs (existence-based skipping).
    # Clean them up before deciding whether to collect more.
    for idx, p in list(iter_perf_data_files(output_dir, bench_name)):
        try:
            if p.is_file() and p.stat().st_size == 0:
                try:
                    p.unlink()
                except FileNotFoundError:
                    pass
        except OSError:
            # If we can't stat it reliably, leave it; perf record will handle/overwrite via deletion path above.
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

        for helper_role in helper_roles:
            helper_name = str(helper_role["container_name"])
            docker_stop_rm(helper_name)
            helper_cmd = _render_workload_cmd(
                str(helper_role["start_cmd"]),
                cli_args=runtime_args,
                project_dir=project_dir,
                output_dir=output_dir,
                bench_name=bench_name,
                service_type=service_type,
                config_name=config_name,
            )
            log("⚙️", f"Starting helper {helper_name}...")
            result = run_cmd(helper_cmd, shell=True)
            if result.returncode != 0:
                log("❌", f"Failed to start helper {helper_name}: {result.stderr.strip()}")
                _cleanup_helpers(helper_roles)
                return
            for check in helper_role.get("ready_checks", []):
                if not _run_ready_check(
                    check,
                    target_container_name=helper_name,
                    cli_args=runtime_args,
                    project_dir=project_dir,
                    output_dir=output_dir,
                    bench_name=bench_name,
                    service_type=service_type,
                    config_name=config_name,
                ):
                    _cleanup_helpers(helper_roles)
                    return

        docker_stop_rm(container_name)
        server_cmd = _render_workload_cmd(
            str(target_role["start_cmd"]),
            cli_args=runtime_args,
            project_dir=project_dir,
            output_dir=output_dir,
            bench_name=bench_name,
            service_type=service_type,
            config_name=config_name,
        )
        log("⚙️", f"Starting {container_name}...")
        result = run_cmd(server_cmd, shell=True)
        if result.returncode != 0:
            log("❌", f"Failed to start {container_name}: {result.stderr.strip()}")
            _cleanup_helpers(helper_roles)
            return

        time.sleep(int(config.get("startup_wait_s", 5)))

        for check in list(target_role.get("ready_checks", [])) + list(config.get("ready_checks", [])):
            if not _run_ready_check(
                check,
                target_container_name=container_name,
                cli_args=runtime_args,
                project_dir=project_dir,
                output_dir=output_dir,
                bench_name=bench_name,
                service_type=service_type,
                config_name=config_name,
            ):
                docker_stop_rm(container_name)
                _cleanup_helpers(helper_roles)
                return

        for step in config.get("prepare_steps", []):
            if not _run_prepare_step(
                step,
                cli_args=runtime_args,
                project_dir=project_dir,
                output_dir=output_dir,
                bench_name=bench_name,
                service_type=service_type,
                config_name=config_name,
            ):
                docker_stop_rm(container_name)
                _cleanup_helpers(helper_roles)
                return

        # ── Start the benchmark load ────────────────────────────────────
        bench_cmd = _render_workload_cmd(
            str(config.get("load_cmd", config["bench_cmd"])),
            bench_duration=effective_bench_duration,
            cli_args=runtime_args,
            project_dir=project_dir,
            output_dir=output_dir,
            bench_name=bench_name,
            service_type=service_type,
            config_name=config_name,
        )
        log("🔨", f"Starting load: {bench_cmd}")
        bench_process = subprocess.Popen(
            bench_cmd, shell=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        # Wait for load to warm up before tracing
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

        # ── Find the worker PID to trace ─────────────────────────────────
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

        # ── Collect PT traces ─────────────────────────────────────────────
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
