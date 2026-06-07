#!/usr/bin/env python3
"""
Cloud Application Intel PT Trace Collector + perf post-analysis.

Cloud-specific workload setup lives in workloads.cloud_runtime/cloud_run; this
module is the batch driver that parses CLI args, prepares Docker state, launches
each service config, and optionally runs batch post-processing.
"""

from __future__ import annotations

import concurrent.futures
import os
import subprocess
import sys
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SRC_DIR = REPO_ROOT / "src"
for _path in (REPO_ROOT, SRC_DIR):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from intel_pt_trace_processing.collect.cloud_args import parse_cloud_args
from intel_pt_trace_processing.collect.cloud_postprocess import cloud_run_perf_postprocess
from intel_pt_trace_processing.collect.cloud_run import run_single_config
from intel_pt_trace_processing.workloads.cloud_runtime import (
    BENCH_CONTAINER,
    NETWORK_NAME,
    cleanup_all,
    docker_stop_rm,
    ensure_bench_client,
    ensure_network,
    ensure_static_files,
    load_workload_config_file,
    log,
    merge_config_matrix,
    run_cmd,
    workload_container_names,
)

SCRIPT_DIR = REPO_ROOT


def _services_to_run(service: str, available_services: list[str]) -> list[str]:
    if service == "all":
        return available_services
    if service not in available_services:
        sys.exit(
            f"service {service!r} was not found. Available services: {', '.join(available_services)}"
        )
    return [service]


def _start_sudo_keepalive() -> threading.Event:
    stop = threading.Event()

    def refresh() -> None:
        while not stop.wait(60.0):
            subprocess.run(
                ["sudo", "-n", "-v"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

    threading.Thread(target=refresh, name="sudo-keepalive", daemon=True).start()
    return stop


def main():
    args = parse_cloud_args()

    output_dir = args.output_dir.resolve()
    perf_tool = args.perf_tool.resolve()
    project_dir = SCRIPT_DIR

    if not perf_tool.is_file() or not os.access(perf_tool, os.X_OK):
        sys.exit(f"❌ perf tool not executable: {perf_tool}")
    if args.sudo_perf:
        try:
            subprocess.run(["sudo", "-v"], check=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            sys.exit(f"sudo authorization failed: {exc}")
    sudo_keepalive = _start_sudo_keepalive() if args.sudo_perf else None

    output_dir.mkdir(parents=True, exist_ok=True)

    all_configs = load_workload_config_file(args.default_workload_config.resolve(), project_dir)
    for config_path in args.workload_config:
        extra_configs = load_workload_config_file(config_path.resolve(), project_dir)
        merge_config_matrix(all_configs, extra_configs)

    ensure_static_files(project_dir)
    cleanup_all(workload_container_names(all_configs))
    ensure_network()
    ensure_bench_client(project_dir, cpuset=args.bench_cpuset)

    services_to_run = _services_to_run(args.service, list(all_configs))
    if args.config_name:
        for service_name in services_to_run:
            all_configs[service_name] = [
                config
                for config in all_configs[service_name]
                if config["config_name"] == args.config_name
            ]
        if not any(all_configs[service_name] for service_name in services_to_run):
            sys.exit(
                f"config_name {args.config_name!r} was not found in service selection {args.service!r}"
            )

    total_configs = sum(len(all_configs[s]) for s in services_to_run)
    print(f"\n📁 Output dir : {output_dir}")
    print(f"🔍 Services   : {', '.join(services_to_run)}")
    print(f"📦 Configs    : {total_configs} total (one classic profile per service)")
    print(f"⏱️  Interval   : {args.interval}s between samples")
    print(f"🕐 Bench dur  : {args.bench_duration}s default (JSON may override)")
    print(f"🔥 Warmup     : {args.warmup_duration}s default (JSON may override)")
    print(f"🔬 perf -m    : {args.perf_mmap_pages} (data,aux mmap pages)")
    print(f"🔬 intel_pt   : noretcomp={args.perf_pt_noretcomp}")
    print(
        f"🎯 perf target: cpus={args.perf_cpus or args.perf_cpu} "
        f"target_cpuset={args.target_cpuset}"
    )
    print(f"🧰 bench CPU  : bench_cpuset={args.bench_cpuset} helper_cpuset={args.helper_cpuset}")
    print(f"📊 Post-process: {'off' if args.no_post_process else 'perf script + trace_feature_processor'}\n")

    config_index = 0
    benches_for_post: set[str] = set()
    for service_name in services_to_run:
        service_configs = all_configs[service_name]
        log("📦", f"=== Service: {service_name} ({len(service_configs)} configs) ===")

        for config in service_configs:
            config_index += 1
            log("📋", f"Config {config_index}/{total_configs}: {config['service_type']}.{config['config_name']}")

            run_single_config(
                config=config,
                perf_tool=perf_tool,
                output_dir=output_dir,
                project_dir=project_dir,
                interval=args.interval,
                record_duration=args.record_duration,
                bench_duration=args.bench_duration,
                max_samples=args.samples_per_config,
                warmup_duration=args.warmup_duration,
                cli_args=args,
            )
            if not args.no_post_process:
                benches_for_post.add(f"{config['service_type']}.{config['config_name']}")

    docker_stop_rm(BENCH_CONTAINER)
    run_cmd(["docker", "network", "rm", NETWORK_NAME])

    if benches_for_post:
        workers = min(int(args.post_workers), len(benches_for_post))
        log("🧰", f"Batch post-process: benches={len(benches_for_post)} workers={workers}")
        futures: dict[concurrent.futures.Future[None], str] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            for bench_name in sorted(benches_for_post):
                future = executor.submit(
                    cloud_run_perf_postprocess,
                    script_dir=SCRIPT_DIR,
                    output_dir=output_dir,
                    bench_name=bench_name,
                    perf_tool=perf_tool,
                    args=args,
                )
                futures[future] = bench_name
            for future in concurrent.futures.as_completed(futures):
                bench_name = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    log("❌", f"Post-process failed for {bench_name}: {exc}")
                    if args.stop_on_post_error:
                        raise

    if sudo_keepalive is not None:
        sudo_keepalive.set()

    print(f"\n🎉 All cloud benchmarks finished! Data saved to: {output_dir}")
    if args.export_full_features:
        exporter = (SCRIPT_DIR / "scripts/tools/export_perf_full_features.py").resolve()
        try:
            subprocess.run(
                [sys.executable, str(exporter), "--output-base", str(output_dir)],
                check=True,
                text=True,
            )
        except Exception as e:
            print(f"[warn] export full features failed: {e}")


if __name__ == "__main__":
    main()
