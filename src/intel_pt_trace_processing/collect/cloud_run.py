from __future__ import annotations

import argparse
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
    SERVICE_IPS,
    docker_exec,
    docker_inspect_pid,
    docker_perf_event_cgroup,
    docker_run,
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

    if not skip_collect:
        # ── Start nginx backend for HAProxy ─────────────────────────────
        if config.get("needs_nginx_backend"):
            docker_stop_rm("target-nginx-helper")
            nginx_conf = project_dir / "cloud_bench_configs" / "nginx-http.conf"
            helper_cpuset = docker_cpuset_arg(getattr(cli_args, "helper_cpuset", None) if cli_args is not None else None)
            docker_run(
                f"-d --name target-nginx-helper "
                f"{helper_cpuset}"
                f"--network {NETWORK_NAME} --ip {SERVICE_IPS['nginx']} "
                f"-v {nginx_conf}:/etc/nginx/nginx.conf:ro "
                f"nginx:alpine"
            )
            time.sleep(2)
            if not nginx_ready_from_bench_client(SERVICE_IPS["nginx"], "/index.html", timeout_s=30):
                log("❌", "Nginx backend (target-nginx-helper) not reachable from bench-client (HTTP)")
                docker_stop_rm("target-nginx-helper")
                return

        # ── Start the target service ─────────────────────────────────────
        docker_stop_rm(container_name)
        server_cmd = config["server_cmd"]
        log("⚙️", f"Starting {container_name}...")
        result = run_cmd(server_cmd, shell=True)
        if result.returncode != 0:
            log("❌", f"Failed to start {container_name}: {result.stderr.strip()}")
            return

        # Wait for service to be ready
        startup_wait = 5
        if config.get("needs_pgbench_init"):
            startup_wait = 10  # PostgreSQL needs more time
        time.sleep(startup_wait)

        # ── Wait for Nginx to serve HTTP (avoids immediate-exit / not-ready cases) ──
        if service_type == "nginx":
            if not nginx_ready_from_bench_client(SERVICE_IPS["nginx"], "/index.html", timeout_s=60):
                log("❌", "Nginx not reachable from bench-client (HTTP)")
                docker_stop_rm(container_name)
                return

        # ── Wait for MySQL to accept connections ──────────────────────────
        if config.get("needs_mysql_ready"):
            log("⏳", "Waiting for MySQL to accept connections...")
            mysql_ready = False
            for _ in range(90):
                ping = docker_exec(container_name, "mysqladmin ping -ppassword --silent")
                if ping.returncode == 0:
                    mysql_ready = True
                    break
                time.sleep(1)
            if not mysql_ready:
                log("❌", "MySQL did not become ready in time")
                docker_stop_rm(container_name)
                return
            # Critical: verify bench-client can actually reach mysqld.
            if not mysql_ready_from_bench_client(SERVICE_IPS["mysql"], timeout_s=120):
                log("❌", "MySQL not reachable from bench-client (network/connectivity)")
                docker_stop_rm(container_name)
                return

        # ── sysbench prepare (MySQL): must finish before run+warmup+PT ─────────
        if config.get("sysbench_mysql_prepare_cmd"):
            live = cli_args is not None and cli_args.verbose_sysbench_prepare
            log(
                "📊",
                "Running sysbench oltp_read_write prepare …"
                + (" (live output on stdout/stderr)" if live else ""),
            )
            t_prep = time.monotonic()
            if live:
                pr = subprocess.run(
                    config["sysbench_mysql_prepare_cmd"],
                    shell=True,
                    text=True,
                )
            else:
                pr = run_cmd(config["sysbench_mysql_prepare_cmd"], shell=True)
            prep_elapsed = time.monotonic() - t_prep
            if pr.returncode != 0:
                err = (pr.stderr or "").strip() if pr.stderr is not None else ""
                if live and not err:
                    err = "(see messages above)"
                log("❌", f"sysbench prepare failed (rc={pr.returncode}): {err}")
                docker_stop_rm(container_name)
                return
            if not live and sysbench_output_looks_failed(pr.stdout or "", pr.stderr or ""):
                log("❌", "sysbench prepare reported FATAL/connection errors (treat as failure)")
                if pr.stdout and pr.stdout.strip():
                    for line in pr.stdout.strip().splitlines()[-12:]:
                        log("📋", f"  prepare out: {line}")
                if pr.stderr and pr.stderr.strip():
                    for line in pr.stderr.strip().splitlines()[-12:]:
                        log("📋", f"  prepare err: {line}")
                docker_stop_rm(container_name)
                return
            log("✅", f"sysbench prepare done in {prep_elapsed:.1f}s")
            if not live and pr.stdout and pr.stdout.strip():
                for line in pr.stdout.strip().splitlines()[-8:]:
                    log("📋", f"  prepare out: {line}")
            if not live and pr.stderr and pr.stderr.strip():
                for line in pr.stderr.strip().splitlines()[-8:]:
                    log("📋", f"  prepare err: {line}")

        # ── Initialize PostgreSQL if needed ───────────────────────────────
        if config.get("needs_pgbench_init"):
            log("🗄️", "Initializing pgbench database...")
            init_result = docker_exec(
                "target-postgres",
                "pgbench -i -s 2 -U postgres postgres",
            )
            if init_result.returncode != 0:
                log("⚠️", f"pgbench init warning: {init_result.stderr.strip()}")
            time.sleep(3)

        # ── Start the benchmark load ────────────────────────────────────
        bench_cmd = config["bench_cmd"].format(bench_duration=bench_duration)
        log("🔨", f"Starting load: {bench_cmd}")
        bench_process = subprocess.Popen(
            bench_cmd, shell=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        # Wait for load to warm up before tracing
        log("🔥", f"Warming up for {warmup_duration}s before tracing...")
        time.sleep(warmup_duration)

        # ── Find the worker PID to trace ─────────────────────────────────
        main_pid = docker_inspect_pid(container_name)
        if main_pid is None:
            log("❌", f"Cannot get PID for {container_name}")
            bench_process.kill()
            docker_stop_rm(container_name)
            return

        perf_target = cpu_perf_target(int(getattr(cli_args, "perf_cpu", 6) if cli_args is not None else 6))
        monitor_pid = main_pid
        use_sudo_perf = bool(getattr(cli_args, "sudo_perf", False)) if cli_args is not None else False
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
            return
        perf_cgroup = docker_perf_event_cgroup(main_pid)
        if perf_cgroup is None:
            log("❌", f"Cannot resolve perf_event cgroup for {container_name} (PID {main_pid})")
            bench_process.kill()
            bench_process.wait()
            docker_stop_rm(container_name)
            return
        log(
            "🚀",
            f"Tracing CPU {perf_target.cpu} with perf -C -G {perf_cgroup} "
            f"(container main PID {main_pid})",
        )

        if monitor_pid is not None and not pid_alive(monitor_pid):
            log("⚠️", "Perf monitor target is not alive — skipping.")
            bench_process.kill()
            docker_stop_rm(container_name)
            return

        # ── Collect PT traces ─────────────────────────────────────────────
        mmap_pages = (
            cli_args.perf_mmap_pages
            if cli_args is not None
            else DEFAULT_PERF_MMAP_PAGES
        )
        nrc = (
            int(cli_args.perf_pt_noretcomp)
            if cli_args is not None
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
                collect_mode=str(getattr(cli_args, "collect_mode", "pt")) if cli_args is not None else "pt",
                perf_stat_events=str(getattr(cli_args, "perf_stat_events", "cycles,instructions,branches,branch-misses,cache-references,cache-misses,stalled-cycles-frontend,stalled-cycles-backend,ref-cycles,task-clock,context-switches,cpu-migrations,page-faults")) if cli_args is not None else "cycles,instructions,branches,branch-misses,cache-references,cache-misses,stalled-cycles-frontend,stalled-cycles-backend,ref-cycles,task-clock,context-switches,cpu-migrations,page-faults",
                start_index=existing_n if (has_perf and selections_verified and existing_n < max_samples) else 0,
            )
        finally:
            if bench_process.poll() is None:
                bench_process.kill()
            bench_process.wait()
            docker_stop_rm(container_name)
            if config.get("needs_nginx_backend"):
                docker_stop_rm("target-nginx-helper")

        log("✅", f"{bench_name} done — {sample_count} samples collected.\n")
