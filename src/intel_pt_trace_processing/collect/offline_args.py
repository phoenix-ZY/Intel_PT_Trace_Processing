from __future__ import annotations

import argparse
import sys
from pathlib import Path

from intel_pt_trace_processing.collect.cloud_args import normalize_perf_mmap_pages
from intel_pt_trace_processing.collect.perf_targets import (
    add_perf_target_args,
    normalize_cpu_spec,
    validate_perf_target_args,
)
from intel_pt_trace_processing.perf.stream import (
    add_perf_postprocess_args,
    validate_perf_postprocess_args,
)
from intel_pt_trace_processing.workloads.cbs_images import default_cbs_root

DEFAULT_OUTPUT_DIR = Path.cwd() / "outputs" / "offline_trace"
DEFAULT_PERF_TOOL = Path("/usr/bin/perf")
DEFAULT_INTERVAL = 30
DEFAULT_RECORD_DURATION = 0.1
DEFAULT_SAMPLES_PER_CONDITION = 2
DEFAULT_WARMUP_DURATION = 30


def build_offline_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect Intel PT traces from CBS offline workloads (single-copy / narrow cpuset)."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Directory for PT data files (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--perf-tool",
        type=Path,
        default=DEFAULT_PERF_TOOL,
        help=f"Path to perf binary (default: {DEFAULT_PERF_TOOL})",
    )
    parser.add_argument(
        "--sudo-perf",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Run perf record/stat/script through sudo (recommended for Docker cgroup PT)",
    )
    parser.add_argument(
        "--cbs-root",
        type=Path,
        default=default_cbs_root(),
        help="Path to colocation-bench-suite (offline launchers + matrix)",
    )
    parser.add_argument(
        "--matrix-file",
        type=Path,
        default=None,
        help="Workload matrix CSV (default: generate under output-dir via CBS offline_matrix.sh)",
    )
    parser.add_argument(
        "--mode",
        type=str,
        default="smoke",
        help="Matrix mode when --matrix-file is omitted (smoke, ibench, spec, all, ...)",
    )
    parser.add_argument(
        "--matrix-variant",
        type=str,
        choices=["sweep", "single_copy"],
        default="single_copy",
        help="Matrix variant when generating CSV (default: single_copy for PT feature library)",
    )
    parser.add_argument(
        "--condition",
        type=str,
        default="all",
        help="Run one condition_id from the matrix, or 'all'",
    )
    parser.add_argument(
        "--offline-cpuset",
        type=str,
        default=None,
        help="Docker --cpuset-cpus and perf -C target (defaults to CBS PROFILE_CPUSET/OFFLINE_CPUSET)",
    )
    parser.add_argument(
        "--offline-mems",
        type=str,
        default=None,
        help="Docker --cpuset-mems (default: CBS PROFILE_MEMS/OFFLINE_MEMS)",
    )
    parser.add_argument(
        "--offline-container",
        type=str,
        default=None,
        help="Offline container name (default: CBS OFFLINE_CONTAINER)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL,
        help=f"Seconds between PT samples (default: {DEFAULT_INTERVAL})",
    )
    parser.add_argument(
        "--record-duration",
        type=float,
        default=DEFAULT_RECORD_DURATION,
        help=f"Seconds of PT recording per sample (default: {DEFAULT_RECORD_DURATION})",
    )
    parser.add_argument(
        "--samples-per-condition",
        type=int,
        default=DEFAULT_SAMPLES_PER_CONDITION,
        help=f"Max PT samples per condition (default: {DEFAULT_SAMPLES_PER_CONDITION})",
    )
    parser.add_argument(
        "--warmup-duration",
        type=int,
        default=DEFAULT_WARMUP_DURATION,
        help=f"Seconds to warm up workload before first sample (default: {DEFAULT_WARMUP_DURATION})",
    )
    parser.add_argument(
        "--no-post-process",
        action="store_true",
        help="Skip perf script / trace_feature_processor after collection",
    )
    parser.add_argument(
        "--stop-on-post-error",
        action="store_true",
        help="Abort if post-processing fails for one condition",
    )
    parser.add_argument(
        "--post-workers",
        type=int,
        default=4,
        help="Parallel post-processing workers after collection",
    )
    parser.add_argument(
        "--verbose-post",
        action="store_true",
        help="Print post-process subprocess commands",
    )
    parser.add_argument(
        "--collect-mode",
        type=str,
        choices=["pt", "stat"],
        default="pt",
        help="Collection mode: pt = Intel PT via perf record; stat = PMU via perf stat",
    )
    add_perf_target_args(parser, default_cpu=32)
    parser.add_argument(
        "--perf-cpus",
        type=str,
        default=None,
        help="CPU list for perf -C (defaults to --offline-cpuset or --perf-cpu)",
    )
    parser.add_argument(
        "--perf-stat-events",
        type=str,
        default="cycles,instructions,branches,branch-misses,cache-references,cache-misses",
        help="perf stat events when --collect-mode=stat",
    )
    add_perf_postprocess_args(parser)
    parser.add_argument(
        "--perf-mmap-pages",
        type=str,
        default="2048,16384",
        help="perf record -m DATA,AUX mmap page counts (powers of two)",
    )
    parser.add_argument(
        "--perf-pt-noretcomp",
        type=int,
        choices=[0, 1],
        default=0,
        help="intel_pt noretcomp flag",
    )
    return parser


def parse_offline_args(argv: list[str] | None = None) -> argparse.Namespace:
    args = build_offline_arg_parser().parse_args(argv)
    validate_perf_target_args(args)
    if args.offline_cpuset is None:
        args.offline_cpuset = str(args.perf_cpus or args.perf_cpu)
    if args.perf_cpus is None:
        args.perf_cpus = normalize_cpu_spec(args.offline_cpuset)
    else:
        try:
            args.perf_cpus = normalize_cpu_spec(args.perf_cpus)
        except ValueError as exc:
            sys.exit(f"--perf-cpus: {exc}")
    try:
        args.perf_mmap_pages = normalize_perf_mmap_pages(args.perf_mmap_pages)
    except ValueError as exc:
        sys.exit(f"--perf-mmap-pages: {exc}")
    validate_perf_postprocess_args(args)
    if args.post_workers <= 0:
        sys.exit("--post-workers must be > 0")
    if args.samples_per_condition <= 0:
        sys.exit("--samples-per-condition must be > 0")
    return args
