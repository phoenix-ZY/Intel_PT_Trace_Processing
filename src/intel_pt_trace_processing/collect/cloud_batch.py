#!/usr/bin/env python3
"""
Cloud Application Intel PT Trace Collector + perf post-analysis.

Cloud-specific workload setup lives in workloads.cloud_runtime/cloud_run; this
module is the batch driver that parses CLI args, prepares Docker state, launches
each service config, and optionally runs batch post-processing.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import subprocess
import sys
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
    build_config_matrix,
    cleanup_all,
    docker_stop_rm,
    ensure_bench_client,
    ensure_network,
    ensure_static_files,
    log,
    run_cmd,
)

SCRIPT_DIR = REPO_ROOT


def _services_to_run(service: str) -> list[str]:
    if service == "all":
        return ["redis", "nginx", "haproxy", "postgres", "mysql", "memcached"]
    return [service]


def main():
    args = parse_cloud_args()

    output_dir = args.output_dir.resolve()
    perf_tool = args.perf_tool.resolve()
    project_dir = SCRIPT_DIR

    if not perf_tool.is_file() or not os.access(perf_tool, os.X_OK):
        sys.exit(f"❌ perf tool not executable: {perf_tool}")

    output_dir.mkdir(parents=True, exist_ok=True)

    ensure_static_files(project_dir)
    cleanup_all()
    ensure_network()
    ensure_bench_client(project_dir, cpuset=args.bench_cpuset)

    all_configs = build_config_matrix(project_dir, target_cpuset=args.target_cpuset)
    services_to_run = _services_to_run(args.service)

    total_configs = sum(len(all_configs[s]) for s in services_to_run)
    print(f"\n📁 Output dir : {output_dir}")
    print(f"🔍 Services   : {', '.join(services_to_run)}")
    print(f"📦 Configs    : {total_configs} total (one classic profile per service)")
    print(f"⏱️  Interval   : {args.interval}s between samples")
    print(f"🕐 Bench dur  : {args.bench_duration}s per config")
    print(f"🔬 perf -m    : {args.perf_mmap_pages} (data,aux mmap pages)")
    print(f"🔬 intel_pt   : noretcomp={args.perf_pt_noretcomp}")
    print(f"🎯 perf target: cpu={args.perf_cpu} target_cpuset={args.target_cpuset}")
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
                inline_postprocess=(args.post_process_mode == "inline"),
            )
            if not args.no_post_process and args.post_process_mode == "batch":
                benches_for_post.add(f"{config['service_type']}.{config['config_name']}")

    if not args.no_post_process and args.post_process_mode == "batch" and benches_for_post:
        workers = max(1, int(getattr(args, "post_workers", 8)))
        log("🧰", f"Batch post-process: benches={len(benches_for_post)} workers={workers}")
        fut_map: dict[concurrent.futures.Future[None], str] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(benches_for_post))) as ex:
            for bench_name in sorted(benches_for_post):
                fut = ex.submit(
                    cloud_run_perf_postprocess,
                    script_dir=SCRIPT_DIR,
                    output_dir=output_dir,
                    bench_name=bench_name,
                    perf_tool=perf_tool,
                    args=args,
                )
                fut_map[fut] = bench_name
            for fut in concurrent.futures.as_completed(fut_map):
                bench_name = fut_map[fut]
                try:
                    fut.result()
                except Exception as e:
                    log("❌", f"Post-process failed for {bench_name}: {e}")
                    if args.stop_on_post_error:
                        raise

    docker_stop_rm(BENCH_CONTAINER)
    run_cmd(["docker", "network", "rm", NETWORK_NAME])

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
