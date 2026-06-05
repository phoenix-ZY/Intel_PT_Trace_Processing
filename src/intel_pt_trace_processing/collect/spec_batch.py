#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SRC_DIR = REPO_ROOT / "src"
for _path in (REPO_ROOT, SRC_DIR):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from intel_pt_trace_processing.compare.similarity import (
    warmup_cross_similarity,
)
from intel_pt_trace_processing.collect.spec_postprocess import run_post_phase
from intel_pt_trace_processing.collect.spec_layout import (
    CaseLayout,
    PreparedCase,
    RunCase,
    make_case_layout,
)
from intel_pt_trace_processing.collect.spec_trace import (
    run_trace_phase,
    run_trace_phase_perf_stream,
)
from intel_pt_trace_processing.collect.perf_targets import (
    add_perf_target_args,
    validate_perf_target_args,
)
from intel_pt_trace_processing.perf.stream import (
    add_perf_postprocess_args,
    validate_perf_postprocess_args,
)
from intel_pt_trace_processing.workloads.spec_runtime import (
    parse_run_list_entry,
)

DEFAULT_REPRESENTATIVE_BENCHES = [
    "505.mcf_r",  # memory-latency sensitive / pointer-chasing
    "520.omnetpp_r",  # discrete-event / branch-heavy control flow
    "523.xalancbmk_r",  # XML transform style server-side processing
    "541.leela_r",  # game-tree search style branching behavior
    "548.exchange2_r",  # integer numeric kernels
    "531.deepsjeng_r",  # alpha-beta search / irregular access
    "557.xz_r",  # compression / cache pressure
    "500.perlbench_r",  # scripting-like interpreter behavior
    "525.x264_r",  # media encode style workload
    "502.gcc_r",  # compiler-style control/data mix
]
















def parse_warmups(s: str) -> list[float]:
    vals: list[float] = []
    for tok in s.split(","):
        tok = tok.strip()
        if not tok:
            continue
        vals.append(float(tok))
    if not vals:
        raise SystemExit("--warmup-sweep parsed empty list")
    for v in vals:
        if v < 0:
            raise SystemExit("warmup must be >= 0")
    return vals


def print_case_ok(case: RunCase) -> None:
    if not case.metrics:
        return
    # load_compare_metrics names overall block metrics data_all_overall_<k> (e.g. overall_score -> data_all_overall_overall_score).
    has_sde_compare = (
        "data_all_overall_score" in case.metrics
        or "inst_all_overall_score" in case.metrics
        or "data_all_overall_overall_score" in case.metrics
        or "inst_all_overall_overall_score" in case.metrics
    )
    if has_sde_compare:
        d_score = float(
            case.metrics.get(
                "data_all_overall_overall_score", case.metrics.get("data_all_overall_score", 0.0)
            )
        )
        i_score = float(
            case.metrics.get(
                "inst_all_overall_overall_score", case.metrics.get("inst_all_overall_score", 0.0)
            )
        )
        print(
            "  ok:",
            f"data_all_score={d_score:.4f}",
            f"data_all_r2={case.metrics.get('data_all_overall_r2', 0.0):.4f}",
            f"data_top3={case.metrics.get('data_all_overall_top3_dims', '')}",
            f"inst_all_score={i_score:.4f}",
            f"inst_all_r2={case.metrics.get('inst_all_overall_r2', 0.0):.4f}",
            f"inst_top3={case.metrics.get('inst_all_overall_top3_dims', '')}",
            f"pt_aux_lost={case.metrics.get('perf_aux_lost', 0)}",
            f"pt_trace_err={case.metrics.get('perf_trace_errors', 0)}",
            f"portrait_insns={case.metrics.get('portrait_parsed_instructions', '')}",
            f"merged={case.metrics.get('trace_profile_merged_json', '')}",
            f"out={case.out_dir}",
        )
        return
    extra = []
    if case.metrics.get("portrait_parsed_instructions") is not None:
        extra.append(f"portrait_insns={case.metrics.get('portrait_parsed_instructions')}")
    if case.metrics.get("trace_profile_merged_json"):
        extra.append(f"merged={case.metrics.get('trace_profile_merged_json')}")
    print(
        "  ok:",
        "mode=perf-only",
        f"perf_insn_lines={case.metrics.get('perf_insn_lines', 0)}",
        f"pt_aux_lost={case.metrics.get('perf_aux_lost', 0)}",
        f"pt_trace_err={case.metrics.get('perf_trace_errors', 0)}",
        f"inst_analysis={case.metrics.get('perf_inst_analysis_json', '')}",
        f"data_analysis={case.metrics.get('perf_data_analysis_json', '')}",
        *extra,
        f"out={case.out_dir}",
    )










def _validate_spec_batch_common_args(args: argparse.Namespace) -> None:
    if args.total_insns <= 0:
        raise SystemExit("--total-insns must be > 0")
    if args.perf_record_seconds <= 0:
        raise SystemExit("--perf-record-seconds must be > 0")
    if args.perf_mmap_pages <= 0:
        raise SystemExit("--perf-mmap-pages must be > 0")
    if args.recover_progress_every < 0:
        raise SystemExit("--recover-progress-every must be >= 0")
    if args.post_workers <= 0:
        raise SystemExit("--post-workers must be > 0")
    validate_perf_target_args(args)
    if getattr(args, "spec_cpuset", None) is None:
        args.spec_cpuset = str(getattr(args, "perf_cpu", 6))

    # Perf permission preflight: on many systems kernel.perf_event_paranoid defaults to a
    # restrictive value (e.g. 4) that prevents *all* CPU PMU events for unprivileged users.
    # Intel PT (and even cycles:u) will fail with exit code 255 in that case.
    try:
        paranoid_txt = Path("/proc/sys/kernel/perf_event_paranoid").read_text(encoding="utf-8").strip()
        paranoid = int(paranoid_txt)
        if paranoid >= 2:
            raise SystemExit(
                "perf is blocked by kernel.perf_event_paranoid="
                + str(paranoid)
                + ".\n"
                + "Fix (temporary):  sudo sysctl -w kernel.perf_event_paranoid=1\n"
                + "Fix (permanent):  add 'kernel.perf_event_paranoid = 1' to /etc/sysctl.conf\n"
                + "Alternatively run the collector under sudo/root, or grant CAP_PERFMON to perf."
            )
    except FileNotFoundError:
        pass
    except ValueError:
        pass


def run_spec_batch_main(args: argparse.Namespace, *, script_dir: Path | None = None) -> int:
    """
    Run the SPEC × warmup batch: trace collection (optional SDE) + post-process + summary.

    Shared by this module's CLI and `run_spec5_perf_trace_analysis.py` (perf-only).
    """
    _validate_spec_batch_common_args(args)
    validate_perf_postprocess_args(args)
    spec_cpu = args.spec_root / "benchspec" / "CPU"
    if not spec_cpu.is_dir():
        raise SystemExit(f"not found: {spec_cpu}")
    if args.enable_sde and not args.sde.exists():
        raise SystemExit(f"sde not found: {args.sde}")

    use_stream = bool(getattr(args, "perf_stream_sampling", False)) and not bool(
        getattr(args, "enable_sde", False)
    )
    collect_mode = str(getattr(args, "collect_mode", "pt"))
    warmups = [] if use_stream else parse_warmups(args.warmup_sweep)
    all_benches = sorted(p.name for p in spec_cpu.iterdir() if p.is_dir() and p.name.startswith("5") and p.name.endswith("_r"))
    bm = str(getattr(args, "benchmarks", "")).strip()
    if bm:
        if bm.lower() == "representative":
            benches = [b for b in DEFAULT_REPRESENTATIVE_BENCHES if b in all_benches]
            if not benches:
                benches = all_benches
        else:
            benches = [x.strip() for x in bm.split(",") if x.strip()]
    else:
        benches = all_benches
    if args.bench_limit > 0:
        benches = benches[: args.bench_limit]
    if not benches:
        raise SystemExit("no benchmarks selected")

    root = script_dir if script_dir is not None else REPO_ROOT
    summary: list[RunCase] = []
    if use_stream:
        print(
            f"[batch] benches={len(benches)} perf_stream_sampling=true "
            f"interval={getattr(args,'perf_stream_interval',10.0)}s "
            f"first_after={getattr(args,'perf_stream_first_after',getattr(args,'perf_stream_interval',10.0))}s "
            f"max_samples={getattr(args,'perf_stream_max_samples',0)}"
        )
    else:
        print(f"[batch] benches={len(benches)} warmups={warmups}")
    print(
        f"[target] perf_cpu={getattr(args,'perf_cpu',6)} spec_cpuset={getattr(args,'spec_cpuset',None)}"
    )
    bench_run_dirs: dict[str, Path] = {}
    for bench in benches:
        bench_dir = spec_cpu / bench
        run_list = bench_dir / "run" / "list"
        try:
            _, run_dir = parse_run_list_entry(run_list)
        except Exception as e:
            msg = f"skip {bench}: {e}"
            print("[warn]", msg)
            summary.append(RunCase(bench=bench, warmup=-1, status="error", out_dir="", error=msg))
            if args.stop_on_error:
                break
            continue
        bench_run_dirs[bench] = run_dir

    total_cases = sum(len(warmups) for b in benches if b in bench_run_dirs) if not use_stream else sum(
        1 for b in benches if b in bench_run_dirs
    )
    print(f"[plan] runnable_cases={total_cases}")

    prepared_cases: list[PreparedCase] = []
    seq = 0
    trace_idx = 0
    stop_now = False

    def _parse_warmup_tag(tag: str) -> float:
        t = tag.strip()
        if not t.endswith("s"):
            raise ValueError(f"bad warmup tag: {tag!r}")
        core = t[:-1].replace("p", ".")
        return float(core)

    def _bench_existing_perf_layouts(bench: str) -> list[CaseLayout]:
        """
        Stream mode resume helper: if a bench already has any perf.data(s) under
        <output-base>/<bench>/<tag>/intermediate/*.perf.data, reuse them instead of re-tracing.
        """
        bench_dir = args.output_base / bench
        if not bench_dir.is_dir():
            return []
        layouts: list[CaseLayout] = []
        seen_tags: set[str] = set()
        for perf_path in bench_dir.rglob("*.perf.data"):
            # Expected shape:
            #   <output-base>/<bench>/<tag>/intermediate/<prefix>.perf.data
            if not perf_path.is_file():
                continue
            try:
                if perf_path.stat().st_size == 0:
                    continue
            except OSError:
                continue
            try:
                tag = perf_path.parent.parent.name
            except Exception:
                continue
            if not tag or tag == "_stream" or tag in seen_tags:
                continue
            try:
                warmup_seconds = _parse_warmup_tag(tag)
            except Exception:
                continue
            layouts.append(make_case_layout(bench=bench, warmup_seconds=warmup_seconds, output_base=args.output_base))
            seen_tags.add(tag)
        layouts.sort(key=lambda l: l.warmup)
        return layouts
    for bench in benches:
        run_dir = bench_run_dirs.get(bench)
        if run_dir is None:
            continue
        if use_stream:
            trace_idx += 1
            print(f"[trace {trace_idx}/{total_cases}] bench={bench} mode=stream")
            try:
                existing_layouts = (
                    _bench_existing_perf_layouts(bench) if bool(getattr(args, "skip_existing", True)) else []
                )
                if existing_layouts:
                    prepared_list = [PreparedCase(seq=seq + i, layout=l) for i, l in enumerate(existing_layouts)]
                    print(f"  skip trace: existing perf.data samples={len(prepared_list)} out={args.output_base / bench}")
                else:
                    prepared_list = run_trace_phase_perf_stream(
                        seq_base=seq,
                        bench=bench,
                        script_dir=root,
                        spec_root=args.spec_root,
                        run_dir=run_dir,
                        args=args,
                    )
                prepared_cases.extend(prepared_list)
                seq += len(prepared_list)
                print(f"  traced: samples={len(prepared_list)} out={args.output_base / bench}")
            except Exception as e:
                msg = str(e)
                print(f"  error: {msg}")
                summary.append(RunCase(bench=bench, warmup=-1, status="error", out_dir="", error=msg))
                if args.stop_on_error:
                    stop_now = True
        else:
            for w in warmups:
                trace_idx += 1
                print(f"[trace {trace_idx}/{total_cases}] bench={bench} warmup={w:g}s")
                try:
                    layout = make_case_layout(bench=bench, warmup_seconds=w, output_base=args.output_base)
                    # If post-process outputs already exist, skip trace collection and just schedule post phase
                    # (which will reuse existing outputs when --skip-existing is on).
                    if collect_mode == "stat":
                        if bool(getattr(args, "skip_existing", True)) and layout.perf_stat_json.is_file() and layout.perf_stat_json.stat().st_size > 0:
                            prepared_cases.append(PreparedCase(seq=seq, layout=layout))
                            seq += 1
                            print(f"  skip trace: existing perf stat out={layout.out_dir}")
                            continue
                    elif bool(getattr(args, "skip_existing", True)) and layout.perf_data_analysis_json.is_file() and layout.perf_inst_analysis_json.is_file():
                        prepared_cases.append(PreparedCase(seq=seq, layout=layout))
                        seq += 1
                        print(f"  skip trace: existing analysis json out={layout.out_dir}")
                        continue
                    prepared = run_trace_phase(
                        seq=seq,
                        layout=layout,
                        script_dir=root,
                        spec_root=args.spec_root,
                        sde_path=args.sde,
                        run_dir=run_dir,
                        args=args,
                    )
                    prepared_cases.append(prepared)
                    seq += 1
                    if collect_mode == "stat":
                        print(f"  traced: perf_stat=ok out={layout.out_dir}")
                    else:
                        print(f"  traced: perf_data=ok out={layout.out_dir}")
                except Exception as e:
                    msg = str(e)
                    print(f"  error: {msg}")
                    summary.append(RunCase(bench=bench, warmup=w, status="error", out_dir="", error=msg))
                    if args.stop_on_error:
                        stop_now = True
                        break
        if stop_now:
            break
    if prepared_cases:
        workers = min(args.post_workers, len(prepared_cases))
        print(f"[post] cases={len(prepared_cases)} workers={workers}")
        if workers <= 1:
            done = 0
            for prepared in sorted(prepared_cases, key=lambda x: x.seq):
                done += 1
                print(f"[post {done}/{len(prepared_cases)}] bench={prepared.layout.bench} warmup={prepared.layout.warmup:g}s")
                try:
                    case = run_post_phase(script_dir=root, prepared=prepared, args=args)
                    summary.append(case)
                    print_case_ok(case)
                except Exception as e:
                    msg = str(e)
                    print(f"  error: {msg}")
                    summary.append(
                        RunCase(bench=prepared.layout.bench, warmup=prepared.layout.warmup, status="error", out_dir="", error=msg)
                    )
                    if args.stop_on_error:
                        break
        else:
            ordered_ok: dict[int, RunCase] = {}
            ordered_err: dict[int, RunCase] = {}
            done = 0
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
                fut_map = {
                    ex.submit(run_post_phase, script_dir=root, prepared=prepared, args=args): prepared
                    for prepared in prepared_cases
                }
                for fut in concurrent.futures.as_completed(fut_map):
                    prepared = fut_map[fut]
                    done += 1
                    print(
                        f"[post {done}/{len(prepared_cases)}] "
                        f"bench={prepared.layout.bench} warmup={prepared.layout.warmup:g}s"
                    )
                    try:
                        case = fut.result()
                        ordered_ok[prepared.seq] = case
                        print_case_ok(case)
                    except Exception as e:
                        msg = str(e)
                        print(f"  error: {msg}")
                        ordered_err[prepared.seq] = RunCase(
                            bench=prepared.layout.bench,
                            warmup=prepared.layout.warmup,
                            status="error",
                            out_dir="",
                            error=msg,
                        )
            for prepared in sorted(prepared_cases, key=lambda x: x.seq):
                case = ordered_ok.get(prepared.seq) or ordered_err.get(prepared.seq)
                if case is not None:
                    summary.append(case)

    summary_json = args.output_base / "summary.json"
    summary_csv = args.output_base / "summary.csv"
    args.output_base.mkdir(parents=True, exist_ok=True)
    json_obj = [
        {
            "bench": x.bench,
            "warmup_seconds": x.warmup,
            "status": x.status,
            "out_dir": x.out_dir,
            "error": x.error,
            "metrics": x.metrics or {},
        }
        for x in summary
    ]
    summary_json.write_text(json.dumps(json_obj, indent=2, ensure_ascii=False), encoding="utf-8")

    metric_keys: set[str] = set()
    for x in summary:
        if x.metrics:
            metric_keys.update(x.metrics.keys())
    csv_keys = ["bench", "warmup_seconds", "status", "out_dir", "error"] + sorted(metric_keys)
    lines = [",".join(csv_keys)]
    for x in summary:
        m = x.metrics or {}
        row = [x.bench, f"{x.warmup:g}", x.status, x.out_dir, x.error or ""]
        for k in csv_keys[5:]:
            row.append(str(m.get(k, "")))
        lines.append(",".join(v.replace(",", ";") for v in row))
    summary_csv.write_text("\n".join(lines) + "\n", encoding="utf-8")

    warmup_pair = warmup_cross_similarity(summary, args.output_base)

    ok = sum(1 for x in summary if x.status == "ok")
    err = sum(1 for x in summary if x.status != "ok")
    print(f"\n[done] ok={ok} error={err}")
    print(f"  summary json: {summary_json}")
    print(f"  summary csv:  {summary_csv}")
    if warmup_pair is not None:
        print(f"  warmup pairwise json: {warmup_pair[0]}")
        print(f"  warmup pairwise csv:  {warmup_pair[1]}")

    if getattr(args, "export_full_features", True):
        exporter = (root / "scripts/tools/export_perf_full_features.py").resolve()
        try:
            subprocess.run(
                [sys.executable, str(exporter), "--output-base", str(args.output_base)],
                check=True,
                text=True,
            )
        except Exception as e:
            print("[warn] export full features failed:", e)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Simplified SPEC5 batch: data + inst locality similarity (SDE vs perf path)"
    )
    ap.add_argument(
        "--spec-root",
        type=Path,
        default=Path("/home/huangtianhao/speccpu2017"),
        help="SPEC CPU root",
    )
    ap.add_argument(
        "--sde",
        type=Path,
        default=Path("/home/huangtianhao/ali/sde-external-9.53.0-2025-03-16-lin/sde64"),
        help="sde64 path",
    )
    ap.add_argument(
        "--enable-sde",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="enable SDE trace and SDE-vs-perf comparison; for perf-only SPEC batch prefer run_spec5_perf_trace_analysis.py",
    )
    ap.add_argument("--warmup-sweep", type=str, default="60,120", help="comma list, e.g. 60,120")
    ap.add_argument("--total-insns", type=int, default=5_000_000)
    # Perf post-process args (shared with cloud stream processor)
    add_perf_postprocess_args(ap)
    ap.add_argument("--stride-top-k", type=int, default=20)
    # Too-short windows often yield no decoded insn trace from Intel PT.
    ap.add_argument("--perf-record-seconds", type=float, default=0.1)
    # Intel PT AUX buffers are mlock()'d; keep default conservative to avoid
    # "Permission error mapping pages" on systems with low memlock limits.
    ap.add_argument("--perf-mmap-pages", type=int, default=64, help="perf record -m pages (PT buffer size)")
    ap.add_argument("--perf-event", type=str, default="intel_pt/cyc,noretcomp=0/u")
    add_perf_target_args(ap, default_cpu=6)
    ap.add_argument(
        "--spec-cpuset",
        type=str,
        default=None,
        help="Run SPEC benchmark under taskset -c CPUSET. Defaults to --perf-cpu in CPU mode.",
    )
    ap.add_argument("--trace-post-sde-sleep", type=float, default=8.0)
    ap.add_argument("--trace-settle-timeout", type=float, default=300.0)
    ap.add_argument("--trace-settle-interval", type=float, default=1.0)
    ap.add_argument("--trace-stable-rounds", type=int, default=4)
    # NOTE: other perf post-process args are added by add_perf_postprocess_args(ap)
    ap.add_argument(
        "--write-feature-bundle",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="write per-case combined feature bundle JSON (default: true)",
    )
    ap.add_argument(
        "--output-base",
        type=Path,
        default=Path("/home/huangtianhao/Intel_PT_Trace_Processing/outputs/spec5_sde_perf_subset"),
    )
    ap.add_argument(
        "--benchmarks",
        type=str,
        default="",
        help="comma list of bench dirs, or the keyword 'representative' for the small default subset; "
        "empty runs every benchspec/CPU/*5*_r (integer + FP rate builds)",
    )
    ap.add_argument("--bench-limit", type=int, default=0, help="for quick test, limit benchmark count")
    ap.add_argument(
        "--post-workers",
        type=int,
        default=8,
        help="number of workers for parallel post-processing (default: 8)",
    )
    ap.add_argument("--stop-on-error", action="store_true", help="stop batch immediately on first failure")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument(
        "--skip-existing",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Skip trace/post when analysis outputs already exist (default: true).",
    )
    ap.add_argument(
        "--perf-stream-sampling",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Perf-only: run benchmark once and sample perf.data periodically until exit (incompatible with SDE).",
    )
    ap.add_argument(
        "--perf-stream-interval",
        type=float,
        default=10.0,
        help="Perf-only stream sampling interval seconds (default: 10).",
    )
    ap.add_argument(
        "--perf-stream-first-after",
        type=float,
        default=10.0,
        help="First sample time offset in seconds since benchmark start (default: 10).",
    )
    ap.add_argument(
        "--perf-stream-max-samples",
        type=int,
        default=0,
        help="Max samples per benchmark in stream mode (0 = unlimited until exit).",
    )
    ap.add_argument(
        "--export-full-features",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="After run, export perf_full_features.(csv/xlsx) by concatenating recovered data features + portrait (+recover report).",
    )
    args = ap.parse_args()
    return run_spec_batch_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
