#!/usr/bin/env python3
"""
Offline workload Intel PT trace collector (batch driver).

Workload startup is delegated to colocation-bench-suite/scripts/offline_workload_lib.py;
this module selects matrix conditions and runs perf record + optional post-processing.
"""

from __future__ import annotations

import concurrent.futures
import os
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SRC_DIR = REPO_ROOT / "src"
for _path in (REPO_ROOT, SRC_DIR):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from intel_pt_trace_processing.collect.cloud_postprocess import (  # noqa: E402
    cloud_postprocess_reports_complete,
    cloud_run_perf_postprocess,
    iter_perf_data_files,
)
from intel_pt_trace_processing.collect.offline_args import parse_offline_args
from intel_pt_trace_processing.collect.offline_run import run_single_condition
from intel_pt_trace_processing.workloads.cbs_images import ensure_cbs_image_env
from intel_pt_trace_processing.workloads.cloud_runtime import log


def _import_cbs_offline_lib(cbs_root: Path):
    scripts = cbs_root / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import offline_workload_lib as owl

    return owl


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


def _conditions_to_run(condition_arg: str, matrix_file: Path, owl) -> list:
    conditions = owl.load_matrix(matrix_file)
    if condition_arg == "all":
        return conditions
    return [owl.get_condition(matrix_file, condition_arg)]


def main(argv: list[str] | None = None) -> int:
    args = parse_offline_args(argv)
    cbs_root = args.cbs_root.resolve()
    ensure_cbs_image_env()
    owl = _import_cbs_offline_lib(cbs_root)

    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    run_tag = output_dir.name or datetime.now().strftime("%Y%m%d_%H%M%S")

    matrix_file = args.matrix_file
    if matrix_file is None:
        matrix_file = output_dir / "workload_matrix.csv"
        if not matrix_file.is_file():
            owl.write_matrix(
                matrix_file,
                args.mode,
                variant=args.matrix_variant,
                cpuset=args.offline_cpuset,
                cbs_root_path=cbs_root,
            )
    else:
        matrix_file = matrix_file.resolve()

    perf_tool = args.perf_tool.resolve()
    if not perf_tool.is_file() or not os.access(perf_tool, os.X_OK):
        print(f"perf tool not executable: {perf_tool}", file=sys.stderr)
        return 1

    if args.sudo_perf:
        try:
            subprocess.run(["sudo", "-v"], check=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            print(f"sudo authorization failed: {exc}", file=sys.stderr)
            return 1
    sudo_keepalive = _start_sudo_keepalive() if args.sudo_perf else None

    conditions = _conditions_to_run(args.condition, matrix_file, owl)
    if not conditions:
        print("no conditions selected", file=sys.stderr)
        return 1

    print(f"\nOutput dir   : {output_dir}")
    print(f"Matrix file  : {matrix_file}")
    print(f"Conditions   : {len(conditions)}")
    print(f"Offline CPUs : {args.offline_cpuset}")
    print(f"Warmup       : {args.warmup_duration}s")
    print(f"Record dur   : {args.record_duration}s x {args.samples_per_condition} samples\n")

    benches_for_post: set[str] = set()
    failed = 0
    for index, condition in enumerate(conditions, start=1):
        log("📋", f"Condition {index}/{len(conditions)}: {condition.condition_id}")
        try:
            sample_count = run_single_condition(
                condition=condition,
                cbs_root=cbs_root,
                output_dir=output_dir,
                perf_tool=perf_tool,
                offline_cpuset=str(args.offline_cpuset),
                offline_mems=args.offline_mems,
                offline_container=args.offline_container,
                warmup_duration=int(args.warmup_duration),
                interval=float(args.interval),
                record_duration=float(args.record_duration),
                max_samples=int(args.samples_per_condition),
                perf_mmap_pages=str(args.perf_mmap_pages),
                perf_pt_noretcomp=int(args.perf_pt_noretcomp),
                sudo_perf=bool(args.sudo_perf),
                collect_mode=str(args.collect_mode),
                perf_stat_events=str(args.perf_stat_events),
                run_tag=run_tag,
            )
        except Exception as exc:
            failed += 1
            log("❌", f"{condition.condition_id} failed: {exc}")
            if args.stop_on_post_error:
                return 1
            continue
        if sample_count <= 0:
            failed += 1
        elif not args.no_post_process:
            benches_for_post.add(condition.condition_id)

    if benches_for_post:
        workers = min(int(args.post_workers), len(benches_for_post))
        log("🧰", f"Batch post-process: conditions={len(benches_for_post)} workers={workers}")
        futures: dict[concurrent.futures.Future[None], str] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for bench_name in sorted(benches_for_post):
                if cloud_postprocess_reports_complete(output_dir, bench_name):
                    log("⏭️", f"Skipping post-process for {bench_name} (reports complete)")
                    continue
                if not iter_perf_data_files(output_dir, bench_name):
                    log("⚠️", f"No perf.data for {bench_name}; skipping post-process")
                    continue
                futures[
                    pool.submit(
                        cloud_run_perf_postprocess,
                        script_dir=REPO_ROOT,
                        output_dir=output_dir,
                        bench_name=bench_name,
                        perf_tool=perf_tool,
                        args=args,
                    )
                ] = bench_name
            for future in concurrent.futures.as_completed(futures):
                bench_name = futures[future]
                try:
                    future.result()
                    log("✅", f"Post-process done: {bench_name}")
                except Exception as exc:
                    failed += 1
                    log("❌", f"Post-process failed for {bench_name}: {exc}")
                    if args.stop_on_post_error:
                        return 1

    if sudo_keepalive is not None:
        sudo_keepalive.set()

    if failed:
        log("⚠️", f"Finished with {failed} failed condition(s)")
        return 1
    log("🏁", "Offline trace collection complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
