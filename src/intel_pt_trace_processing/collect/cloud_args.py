from __future__ import annotations

import argparse
import sys
from pathlib import Path

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
from intel_pt_trace_processing.workloads.cloud_runtime import default_workload_config_path

DEFAULT_OUTPUT_DIR = Path.cwd() / "outputs" / "cloud_trace"
DEFAULT_PERF_TOOL = Path("/usr/bin/perf")
DEFAULT_INTERVAL = 30
DEFAULT_RECORD_DURATION = 0.001
DEFAULT_BENCH_DURATION = 120
DEFAULT_SAMPLES_PER_CONFIG = 2
DEFAULT_WARMUP_DURATION = 20
DEFAULT_PERF_MMAP_PAGES = "2048,16384"


def normalize_perf_mmap_pages(spec: str) -> str:
    """
    Build perf record -m argument: data_pages[,aux_pages]. One number applies to both.
    Each count must be a positive power of two (Linux perf mmap page units).
    """
    parts = [p.strip() for p in spec.strip().split(",") if p.strip()]
    if len(parts) == 1:
        parts = [parts[0], parts[0]]
    if len(parts) != 2:
        raise ValueError("expected PAGES or DATA_PAGES,AUX_PAGES")
    out: list[str] = []
    for p in parts:
        n = int(p, 10)
        if n <= 0 or (n & (n - 1)) != 0:
            raise ValueError(f"each value must be a positive power of two (got {p!r})")
        out.append(str(n))
    return f"{out[0]},{out[1]}"


def build_cloud_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect Intel PT traces from cloud apps and run perf script + trace_feature_processor."
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
        default=False,
        help="Run perf record/stat/script and build-id cache checks through sudo",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL,
        help=f"Seconds between samples (default: {DEFAULT_INTERVAL})",
    )
    parser.add_argument(
        "--record-duration",
        type=float,
        default=DEFAULT_RECORD_DURATION,
        help=f"Seconds of PT recording per sample (default: {DEFAULT_RECORD_DURATION})",
    )
    parser.add_argument(
        "--bench-duration",
        type=int,
        default=DEFAULT_BENCH_DURATION,
        help=f"Seconds to run each benchmark load (default: {DEFAULT_BENCH_DURATION})",
    )
    parser.add_argument(
        "--samples-per-config",
        type=int,
        default=DEFAULT_SAMPLES_PER_CONFIG,
        help=f"Max samples per config (default: {DEFAULT_SAMPLES_PER_CONFIG})",
    )
    parser.add_argument(
        "--warmup-duration",
        type=int,
        default=DEFAULT_WARMUP_DURATION,
        help=f"Seconds to warm up before first sample (default: {DEFAULT_WARMUP_DURATION})",
    )
    parser.add_argument(
        "--service",
        type=str,
        default="all",
        help=(
            "Run only a specific service (default: all services in the loaded workload config)."
        ),
    )
    parser.add_argument(
        "--default-workload-config",
        type=Path,
        default=None,
        help="CBS workloads.cloud.json (default: $CBS_ROOT/cloud_bench_configs/workloads.cloud.json)",
    )
    parser.add_argument(
        "--workload-config",
        type=Path,
        action="append",
        default=[],
        help="Additional JSON workload config file to merge/override. Can be passed multiple times.",
    )
    parser.add_argument(
        "--colocation-bench-suite-dir",
        type=Path,
        default=None,
        help="Path to colocation-bench-suite (default: CBS_ROOT / COLOCATION_BENCH_SUITE_DIR).",
    )
    parser.add_argument(
        "--config-name",
        type=str,
        default=None,
        help="Run only this config_name within the selected service",
    )
    parser.add_argument(
        "--no-post-process",
        action="store_true",
        help="Skip batch perf script / trace_feature_processor after collection",
    )
    parser.add_argument(
        "--stop-on-post-error",
        action="store_true",
        help="Abort the whole run if post-processing fails for one config",
    )
    parser.add_argument(
        "--post-workers",
        type=int,
        default=8,
        help="Parallel perf-script post-processing workers after all collection finishes",
    )
    parser.add_argument(
        "--verbose-post",
        action="store_true",
        help="Print post-process subprocess commands (perf script, trace_feature_processor)",
    )
    parser.add_argument(
        "--verbose-sysbench-prepare",
        action="store_true",
        help="Stream MySQL sysbench oltp_read_write prepare to terminal (default: capture, log last lines + duration)",
    )
    parser.add_argument(
        "--collect-mode",
        type=str,
        choices=["pt", "stat"],
        default="pt",
        help="Collection mode: 'pt' = Intel PT via perf record; 'stat' = PMU counters via perf stat (no PT).",
    )
    add_perf_target_args(parser, default_cpu=6)
    parser.add_argument(
        "--perf-cpus",
        type=str,
        default=None,
        help=(
            "CPU list recorded with perf -C, for example 0-7 or 0-3,8-11. "
            "Overrides --perf-cpu for cloud workloads."
        ),
    )
    parser.add_argument(
        "--target-cpuset",
        type=str,
        default=None,
        help="Docker --cpuset-cpus for target service containers. Defaults to --perf-cpu in CPU mode.",
    )
    parser.add_argument(
        "--bench-cpuset",
        type=str,
        default="7-10",
        help="Docker --cpuset-cpus for bench-client. Use a different core range from --perf-cpu.",
    )
    parser.add_argument(
        "--helper-cpuset",
        type=str,
        default="7-10",
        help="Docker --cpuset-cpus for helper backend containers such as HAProxy's nginx backend.",
    )
    parser.add_argument(
        "--perf-stat",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Alias of --collect-mode=stat (kept for compatibility).",
    )
    parser.add_argument(
        "--perf-stat-events",
        type=str,
        default=(
            "cycles,instructions,branches,branch-misses,cache-references,cache-misses,"
            "stalled-cycles-frontend,stalled-cycles-backend,ref-cycles,task-clock,"
            "context-switches,cpu-migrations,page-faults"
        ),
        help="perf stat events (comma-separated). Must include cycles/instructions if you want IPC.",
    )
    parser.add_argument(
        "--perf-stat-topdown",
        action=argparse.BooleanOptionalAction,
        default=False,
        help=(
            "In collect-mode=stat, also request Intel topdown events if supported by this CPU/perf: "
            "slots,topdown-retiring,topdown-bad-spec,topdown-fe-bound,topdown-be-bound."
        ),
    )
    parser.add_argument(
        "--export-full-features",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="After the full run, export perf_full_features.(csv/xlsx) under output dir.",
    )
    add_perf_postprocess_args(parser)
    parser.add_argument(
        "--perf-mmap-pages",
        type=str,
        default=DEFAULT_PERF_MMAP_PAGES,
        help=(
            "perf record -m: DATA[,AUX] mmap page counts (powers of two); "
            "one value sets both. Larger AUX cuts intel_pt 'lost chunks' on hot threads."
        ),
    )
    parser.add_argument(
        "--perf-pt-noretcomp",
        type=int,
        choices=[0, 1],
        default=0,
        help="intel_pt noretcomp flag (1 reduces PT bandwidth vs 0; may help if AUX still overflows).",
    )
    return parser


def parse_cloud_args(argv: list[str] | None = None) -> argparse.Namespace:
    args = build_cloud_arg_parser().parse_args(argv)
    if args.colocation_bench_suite_dir is None:
        args.colocation_bench_suite_dir = default_cbs_root()
    if args.default_workload_config is None:
        args.default_workload_config = default_workload_config_path()
    if bool(getattr(args, "perf_stat", False)):
        args.collect_mode = "stat"
    validate_perf_target_args(args)
    if args.perf_cpus is not None:
        try:
            args.perf_cpus = normalize_cpu_spec(args.perf_cpus)
        except ValueError as exc:
            sys.exit(f"--perf-cpus: {exc}")
    if args.target_cpuset is None:
        args.target_cpuset = str(args.perf_cpus or args.perf_cpu)
    if str(getattr(args, "collect_mode", "pt")) == "stat" and bool(getattr(args, "perf_stat_topdown", False)):
        td = "slots,topdown-retiring,topdown-bad-spec,topdown-fe-bound,topdown-be-bound"
        args.perf_stat_events = f"{args.perf_stat_events},{td}"
    if str(getattr(args, "collect_mode", "pt")) == "stat":
        try:
            if abs(float(args.record_duration) - float(DEFAULT_RECORD_DURATION)) < 1e-12:
                args.record_duration = 1.0
        except Exception:
            pass

    try:
        args.perf_mmap_pages = normalize_perf_mmap_pages(args.perf_mmap_pages)
    except ValueError as e:
        sys.exit(f"❌ --perf-mmap-pages: {e}")
    validate_perf_postprocess_args(args)
    if args.post_workers <= 0:
        sys.exit("--post-workers must be > 0")
    return args
