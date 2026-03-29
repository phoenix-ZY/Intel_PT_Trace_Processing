#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shlex
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


def ts_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def pid_alive(pid: int) -> bool:
    return (Path("/proc") / str(pid)).exists()


def read_proc_exe(pid: int) -> str:
    try:
        return str((Path("/proc") / str(pid) / "exe").resolve())
    except OSError:
        return ""


def children_of(pid: int) -> list[int]:
    children_file = Path("/proc") / str(pid) / "task" / str(pid) / "children"
    try:
        raw = children_file.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return []
    if not raw:
        return []
    out: list[int] = []
    for tok in raw.split():
        try:
            out.append(int(tok))
        except ValueError:
            continue
    return out


def cleanup_pid(pid: int | None) -> None:
    if not pid or not pid_alive(pid):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return
    deadline = time.time() + 5.0
    while time.time() < deadline:
        if not pid_alive(pid):
            return
        time.sleep(0.1)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def resolve_target_pid(launcher_pid: int, exe_basename: str, timeout_s: float = 8.0) -> int:
    end = time.time() + timeout_s
    while time.time() <= end:
        if pid_alive(launcher_pid):
            exe = read_proc_exe(launcher_pid)
            if exe and Path(exe).name == exe_basename:
                return launcher_pid
            for cpid in children_of(launcher_pid):
                cexe = read_proc_exe(cpid)
                if cexe and Path(cexe).name == exe_basename:
                    return cpid
        time.sleep(0.02)
    return launcher_pid


def wait_trace_settle(
    trace_path: Path,
    *,
    post_sde_sleep: float,
    settle_timeout: float,
    interval: float,
    stable_rounds: int,
) -> tuple[int, bool]:
    if post_sde_sleep > 0:
        time.sleep(post_sde_sleep)
    start = time.time()
    last = -1
    stable = 0
    while time.time() - start <= settle_timeout:
        cur = trace_path.stat().st_size if trace_path.exists() else 0
        if cur == last and cur > 0:
            stable += 1
            if stable >= stable_rounds:
                return cur, True
        else:
            stable = 0
        last = cur
        time.sleep(interval)
    cur = trace_path.stat().st_size if trace_path.exists() else 0
    return cur, False


def run_step(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    verbose: bool = False,
    stdout_path: Path | None = None,
    stderr_path: Path | None = None,
    append_logs: bool = False,
) -> None:
    if verbose:
        print("[cmd]", " ".join(shlex.quote(x) for x in cmd))
    out_fp = None
    err_fp = None
    try:
        if stdout_path is not None:
            stdout_path.parent.mkdir(parents=True, exist_ok=True)
            out_fp = stdout_path.open("a" if append_logs else "w", encoding="utf-8")
        if stderr_path is not None:
            stderr_path.parent.mkdir(parents=True, exist_ok=True)
            err_fp = stderr_path.open("a" if append_logs else "w", encoding="utf-8")
        subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            check=True,
            text=True,
            stdout=out_fp if out_fp is not None else (None if verbose else subprocess.DEVNULL),
            stderr=err_fp if err_fp is not None else (None if verbose else subprocess.DEVNULL),
        )
    finally:
        if out_fp is not None:
            out_fp.close()
        if err_fp is not None:
            err_fp.close()


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


def warmup_tag(v: float) -> str:
    if abs(v - round(v)) < 1e-9:
        return f"{int(round(v))}s"
    return f"{v:g}s".replace(".", "p")


def parse_run_list_entry(run_list: Path) -> tuple[str, Path]:
    if not run_list.is_file():
        raise FileNotFoundError(f"missing run/list: {run_list}")
    for line in run_list.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line == "__END__":
            continue
        parts = line.split()
        run_id = parts[0]
        run_dir = None
        for p in parts[1:]:
            if p.startswith("dir="):
                run_dir = Path(p[len("dir=") :])
                break
        if run_dir is None:
            continue
        return run_id, run_dir
    raise RuntimeError(f"no usable entry in {run_list}")


def extract_cmd_line(spec_root: Path, bench_run_dir: Path) -> str:
    shrc = spec_root / "shrc"
    specinvoke = shutil_which_or_spec(spec_root)
    cmd = [specinvoke, "-n"]
    env = os.environ.copy()
    if shrc.exists():
        shell_cmd = (
            f"source {shlex.quote(str(shrc))} >/dev/null 2>&1 || true; "
            + " ".join(shlex.quote(x) for x in cmd)
        )
        out = subprocess.check_output(
            ["bash", "-lc", shell_cmd],
            cwd=bench_run_dir,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
    else:
        out = subprocess.check_output(
            cmd,
            cwd=bench_run_dir,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("../run_base"):
            return line
    raise RuntimeError(f"failed to extract command in {bench_run_dir}")


def shutil_which_or_spec(spec_root: Path) -> str:
    path = subprocess.run(
        ["bash", "-lc", "command -v specinvoke"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ).stdout.strip()
    if path:
        return path
    candidate = spec_root / "bin" / "specinvoke"
    if candidate.exists() and os.access(candidate, os.X_OK):
        return str(candidate)
    raise RuntimeError("specinvoke not found")


def extract_perf_insn_trace(perf_script_txt: Path, perf_insn_trace: Path, max_lines: int) -> int:
    n = 0
    with perf_script_txt.open("r", encoding="utf-8", errors="replace") as src, perf_insn_trace.open(
        "w", encoding="utf-8"
    ) as dst:
        for line in src:
            if " insn:" not in line:
                continue
            dst.write(line)
            n += 1
            if max_lines > 0 and n >= max_lines:
                break
    return n


def load_compare_metrics(path: Path, metric_prefix: str = "") -> dict:
    obj = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, float] = {}
    accesses = obj.get("accesses") or list(obj.get("per_access", {}).keys())
    for access in accesses:
        pa = obj["per_access"][access]
        p = f"{metric_prefix}{access}_"
        out[f"{p}rd_r2"] = pa["metrics"]["r2"]
        out[f"{p}rd_l1"] = pa["metrics"]["l1_prob_distance"]
        out[f"{p}cold_abs_diff"] = pa["metrics"]["cold_ratio_abs_diff"]
        out[f"{p}sdp_r2"] = pa["sdp"]["metrics"]["r2"]
        out[f"{p}sdp_mae"] = pa["sdp"]["metrics"]["mean_abs_error"]
        stride = pa.get("stride", {})
        sm = stride.get("metrics", {})
        out[f"{p}stride_r2"] = sm.get("r2", 0.0)
        out[f"{p}stride_l1"] = sm.get("l1_prob_distance", 0.0)
        out[f"{p}stride_jsd"] = sm.get("jsd", 0.0)
    return out


@dataclass
class RunCase:
    bench: str
    warmup: float
    status: str
    out_dir: str
    error: str | None = None
    metrics: dict | None = None


def run_one_case(
    *,
    script_dir: Path,
    spec_root: Path,
    sde_path: Path,
    bench: str,
    run_dir: Path,
    warmup_seconds: float,
    args: argparse.Namespace,
) -> RunCase:
    tag = warmup_tag(warmup_seconds)
    out_dir = args.output_base / bench / tag
    inputs_dir = out_dir / "inputs"
    intermediate_dir = out_dir / "intermediate"
    mem_dir = out_dir / "mem"
    report_dir = out_dir / "report"
    for d in (inputs_dir, intermediate_dir, mem_dir, report_dir):
        d.mkdir(parents=True, exist_ok=True)

    prefix = f"{bench.replace('.', '_')}_{tag}"
    sde_trace = inputs_dir / f"{prefix}.sde.debugtrace.txt"
    sde_mem = mem_dir / f"{prefix}.sde.mem.real.jsonl"
    sde_insn = intermediate_dir / f"{prefix}.sde.insn.trace.txt"
    perf_data = intermediate_dir / f"{prefix}.perf.data"
    perf_script = intermediate_dir / f"{prefix}.perf.script.txt"
    perf_script_stderr = report_dir / f"{prefix}.perf.script.stderr.txt"
    perf_record_stderr = report_dir / f"{prefix}.perf.record.stderr.txt"
    perf_insn = intermediate_dir / f"{prefix}.perf.insn.trace.txt"
    perf_rec_mem = mem_dir / f"{prefix}.perf.mem.recovered.jsonl"
    sde_data_analysis_json = report_dir / f"{prefix}.sde.data.analysis.json"
    perf_data_analysis_json = report_dir / f"{prefix}.perf.recovered.data.analysis.json"
    data_sim_json = report_dir / f"{prefix}.sde_vs_perf_recovered.data.locality.compare.json"
    sde_inst_analysis_json = report_dir / f"{prefix}.sde.inst.analysis.json"
    perf_inst_analysis_json = report_dir / f"{prefix}.perf.inst.analysis.json"
    inst_sim_json = report_dir / f"{prefix}.sde_vs_perf.inst.locality.compare.json"
    sde_log = report_dir / f"{prefix}.sde.attach.log"

    cmd_line = extract_cmd_line(spec_root, run_dir)
    exe_basename = Path(shlex.split(cmd_line)[0]).name

    # ---- SDE phase ----
    with (report_dir / f"{prefix}.spec.sde.stdout.txt").open("w", encoding="utf-8") as out_fp, (
        report_dir / f"{prefix}.spec.sde.stderr.txt"
    ).open("w", encoding="utf-8") as err_fp:
        launcher = subprocess.Popen(
            ["bash", "-lc", f"exec {cmd_line}"],
            cwd=run_dir,
            stdout=out_fp,
            stderr=err_fp,
            text=True,
        )
    launcher_pid = int(launcher.pid)
    time.sleep(1.0)
    if not pid_alive(launcher_pid):
        raise RuntimeError("SDE phase launcher failed to start")
    target_pid = resolve_target_pid(launcher_pid, exe_basename, timeout_s=8.0)
    target_exe = read_proc_exe(target_pid)
    if not target_exe or Path(target_exe).name != exe_basename:
        cleanup_pid(launcher_pid)
        raise RuntimeError("cannot resolve benchmark pid for SDE phase")
    if warmup_seconds > 0:
        time.sleep(warmup_seconds)
    if not pid_alive(target_pid):
        cleanup_pid(launcher_pid)
        raise RuntimeError("benchmark exited before SDE attach")

    sde_cmd = [
        str(sde_path),
        "-attach-pid",
        str(target_pid),
        "-debugtrace",
        "-dt_rawinst",
        "1",
        "-dt_print_tid",
        "1",
        "-dt_out",
        str(sde_trace),
        "-control",
        f"start:icount:0,stop:icount:{args.total_insns}",
        "-length",
        str(args.total_insns),
    ]
    sde_log.write_text("", encoding="utf-8")
    with sde_log.open("a", encoding="utf-8") as fp:
        fp.write(f"=== SDE prologue {ts_now()} ===\n")
        fp.write(f"bench={bench} warmup={warmup_seconds}\n")
        fp.write("cmd: " + " ".join(sde_cmd) + "\n")
    run_step(
        sde_cmd,
        verbose=args.verbose,
        stdout_path=sde_log if not args.verbose else None,
        append_logs=True,
    )
    wait_trace_settle(
        sde_trace,
        post_sde_sleep=args.trace_post_sde_sleep,
        settle_timeout=args.trace_settle_timeout,
        interval=args.trace_settle_interval,
        stable_rounds=args.trace_stable_rounds,
    )
    cleanup_pid(target_pid)
    if target_pid != launcher_pid:
        cleanup_pid(launcher_pid)
    try:
        launcher.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        pass
    if not sde_trace.exists() or sde_trace.stat().st_size == 0:
        raise RuntimeError("empty SDE trace")

    sde_analyzer = script_dir / "analyze_sde_trace_uc"
    if not sde_analyzer.exists():
        raise RuntimeError(f"missing {sde_analyzer}; run build_recover_mem_addrs_uc.sh first")
    run_step(
        [
            str(sde_analyzer),
            "-i",
            str(sde_trace),
            "--mem-out",
            str(sde_mem),
            "--insn-out",
            str(sde_insn),
            "--inst-analysis-out",
            str(sde_inst_analysis_json),
            "--data-analysis-out",
            str(sde_data_analysis_json),
            "--analysis-line-size",
            str(args.line_size),
            "--analysis-sdp-max-lines",
            "262144",
            "--analysis-rd-definition",
            "stack_depth",
            "--analysis-rd-hist-cap-lines",
            str(args.analysis_rd_hist_cap_lines),
            "--analysis-stride-bin-cap-lines",
            str(args.analysis_stride_bin_cap_lines),
        ],
        verbose=args.verbose,
    )
    # ---- perf phase ----
    with (report_dir / f"{prefix}.spec.perf.stdout.txt").open("w", encoding="utf-8") as out_fp, (
        report_dir / f"{prefix}.spec.perf.stderr.txt"
    ).open("w", encoding="utf-8") as err_fp:
        perf_launcher = subprocess.Popen(
            ["bash", "-lc", f"exec {cmd_line}"],
            cwd=run_dir,
            stdout=out_fp,
            stderr=err_fp,
            text=True,
        )
    perf_launcher_pid = int(perf_launcher.pid)
    time.sleep(1.0)
    if not pid_alive(perf_launcher_pid):
        raise RuntimeError("perf phase launcher failed to start")
    perf_target_pid = resolve_target_pid(perf_launcher_pid, exe_basename, timeout_s=8.0)
    if warmup_seconds > 0:
        time.sleep(warmup_seconds)
    if not pid_alive(perf_target_pid):
        cleanup_pid(perf_launcher_pid)
        raise RuntimeError("benchmark exited before perf attach")

    run_step(
        [
            "perf",
            "record",
            "-q",
            "-e",
            args.perf_event,
            "-o",
            str(perf_data),
            "-p",
            str(perf_target_pid),
            "--",
            "sleep",
            str(args.perf_record_seconds),
        ],
        verbose=args.verbose,
        stderr_path=perf_record_stderr,
    )
    cleanup_pid(perf_target_pid)
    if perf_target_pid != perf_launcher_pid:
        cleanup_pid(perf_launcher_pid)
    try:
        perf_launcher.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        pass
    if not perf_data.exists() or perf_data.stat().st_size == 0:
        raise RuntimeError("empty perf.data")

    run_step(
        ["perf", "script", "--insn-trace", "-F", "tid,time,ip,insn", "-i", str(perf_data)],
        verbose=args.verbose,
        stdout_path=perf_script,
        stderr_path=perf_script_stderr,
    )
    perf_insn_lines = extract_perf_insn_trace(perf_script, perf_insn, args.perf_max_insn_lines)
    try:
        perf_script.unlink()
    except FileNotFoundError:
        pass
    if perf_insn_lines < 1:
        raise RuntimeError("no perf insn lines extracted")

    recover_cmd = [
        str(script_dir / "recover_mem_addrs_uc"),
        "-i",
        str(perf_insn),
        "-o",
        str(perf_rec_mem),
        "--init-regs",
        args.recover_init_regs,
        "--seed",
        str(args.recover_fill_seed),
        "--page-init",
        args.recover_page_init,
        "--page-init-seed",
        str(args.recover_page_init_seed),
        "--progress-every",
        str(args.recover_progress_every),
        "--inst-analysis-out",
        str(perf_inst_analysis_json),
        "--data-analysis-out",
        str(perf_data_analysis_json),
        "--analysis-line-size",
        str(args.line_size),
        "--analysis-sdp-max-lines",
        "262144",
        "--analysis-rd-definition",
        "stack_depth",
        "--analysis-rd-hist-cap-lines",
        str(args.analysis_rd_hist_cap_lines),
        "--analysis-stride-bin-cap-lines",
        str(args.analysis_stride_bin_cap_lines),
    ]
    if args.recover_salvage_invalid_mem:
        recover_cmd.append("--salvage-invalid-mem")
        if args.recover_salvage_reads:
            recover_cmd.append("--salvage-reads")
    run_step(recover_cmd, verbose=args.verbose)

    if not sde_data_analysis_json.exists() or not sde_inst_analysis_json.exists():
        raise RuntimeError("analyze_sde_trace_uc did not produce SDE analysis JSON outputs")
    run_step(
        [
            sys.executable,
            str(script_dir / "compare_mem_trace_metrics.py"),
            "--ref-analysis",
            str(sde_data_analysis_json),
            "--test-analysis",
            str(perf_data_analysis_json),
            "--top-k",
            str(max(1, args.stride_top_k)),
            "--max-error-bins",
            "20",
            "--sdp-max-lines",
            "262144",
            "--json-out",
            str(data_sim_json),
        ],
        verbose=args.verbose,
    )
    if not perf_data_analysis_json.exists() or not perf_inst_analysis_json.exists():
        raise RuntimeError("recover_mem_addrs_uc did not produce perf analysis JSON outputs")
    run_step(
        [
            sys.executable,
            str(script_dir / "compare_mem_trace_metrics.py"),
            "--ref-analysis",
            str(sde_inst_analysis_json),
            "--test-analysis",
            str(perf_inst_analysis_json),
            "--top-k",
            str(max(1, args.stride_top_k)),
            "--max-error-bins",
            "20",
            "--sdp-max-lines",
            "262144",
            "--json-out",
            str(inst_sim_json),
        ],
        verbose=args.verbose,
    )

    metrics = {}
    metrics.update(load_compare_metrics(data_sim_json, metric_prefix="data_"))
    metrics.update(load_compare_metrics(inst_sim_json, metric_prefix="inst_"))
    # Keep backward-compatible unprefixed keys mapped to data metrics.
    for access in ("all", "read", "write"):
        for suffix in (
            "rd_r2",
            "rd_l1",
            "cold_abs_diff",
            "sdp_r2",
            "sdp_mae",
            "stride_r2",
            "stride_l1",
            "stride_jsd",
        ):
            k = f"{access}_{suffix}"
            metrics[k] = metrics.get(f"data_{k}", 0.0)
    metrics["perf_insn_lines"] = perf_insn_lines
    return RunCase(bench=bench, warmup=warmup_seconds, status="ok", out_dir=str(out_dir), metrics=metrics)


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
    ap.add_argument("--warmup-sweep", type=str, default="60,120", help="comma list, e.g. 60,120")
    ap.add_argument("--total-insns", type=int, default=2_000_000)
    ap.add_argument("--line-size", type=int, default=64)
    ap.add_argument("--stride-top-k", type=int, default=20)
    ap.add_argument("--perf-record-seconds", type=float, default=0.001)
    ap.add_argument("--perf-event", type=str, default="intel_pt//u")
    ap.add_argument("--perf-max-insn-lines", type=int, default=500_000)
    ap.add_argument("--trace-post-sde-sleep", type=float, default=8.0)
    ap.add_argument("--trace-settle-timeout", type=float, default=300.0)
    ap.add_argument("--trace-settle-interval", type=float, default=1.0)
    ap.add_argument("--trace-stable-rounds", type=int, default=4)
    ap.add_argument("--recover-init-regs", choices=["zero", "random"], default="random")
    ap.add_argument("--recover-fill-seed", type=int, default=1)
    ap.add_argument(
        "--recover-page-init",
        choices=["zero", "random", "stable"],
        default="stable",
        help="page initialization policy for recover_mem_addrs_uc (default: stable)",
    )
    ap.add_argument(
        "--recover-page-init-seed",
        type=int,
        default=1,
        help="seed for page random initialization (used when --recover-page-init=random)",
    )
    ap.add_argument("--recover-salvage-invalid-mem", action=argparse.BooleanOptionalAction, default=True)
    ap.add_argument("--recover-salvage-reads", action=argparse.BooleanOptionalAction, default=True)
    ap.add_argument("--recover-progress-every", type=int, default=0)
    ap.add_argument(
        "--analysis-rd-hist-cap-lines",
        type=int,
        default=262144,
        help="cap RD histogram bins above this line distance (0 disables cap)",
    )
    ap.add_argument(
        "--analysis-stride-bin-cap-lines",
        type=int,
        default=262144,
        help="cap stride |delta| bins above this line distance into tail bucket (0 disables cap)",
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
        help="optional comma list like 505.mcf_r,510.parest_r; empty means all 5*_r",
    )
    ap.add_argument("--bench-limit", type=int, default=0, help="for quick test, limit benchmark count")
    ap.add_argument("--stop-on-error", action="store_true", help="stop batch immediately on first failure")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if args.total_insns <= 0:
        raise SystemExit("--total-insns must be > 0")
    if args.line_size <= 0 or (args.line_size & (args.line_size - 1)) != 0:
        raise SystemExit("--line-size must be positive power-of-two")
    if args.perf_record_seconds <= 0:
        raise SystemExit("--perf-record-seconds must be > 0")
    if args.perf_max_insn_lines < 0:
        raise SystemExit("--perf-max-insn-lines must be >= 0")
    if args.recover_page_init_seed < 0:
        raise SystemExit("--recover-page-init-seed must be >= 0")
    if args.analysis_rd_hist_cap_lines < 0:
        raise SystemExit("--analysis-rd-hist-cap-lines must be >= 0")
    if args.analysis_stride_bin_cap_lines < 0:
        raise SystemExit("--analysis-stride-bin-cap-lines must be >= 0")
    if args.recover_progress_every < 0:
        raise SystemExit("--recover-progress-every must be >= 0")

    spec_cpu = args.spec_root / "benchspec" / "CPU"
    if not spec_cpu.is_dir():
        raise SystemExit(f"not found: {spec_cpu}")
    if not args.sde.exists():
        raise SystemExit(f"sde not found: {args.sde}")

    warmups = parse_warmups(args.warmup_sweep)
    if args.benchmarks.strip():
        benches = [x.strip() for x in args.benchmarks.split(",") if x.strip()]
    else:
        benches = sorted(p.name for p in spec_cpu.iterdir() if p.is_dir() and p.name.startswith("5") and p.name.endswith("_r"))
    if args.bench_limit > 0:
        benches = benches[: args.bench_limit]
    if not benches:
        raise SystemExit("no benchmarks selected")

    script_dir = Path(__file__).resolve().parent
    summary: list[RunCase] = []
    print(f"[batch] benches={len(benches)} warmups={warmups}")
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

        for w in warmups:
            print(f"[run] bench={bench} warmup={w:g}s")
            try:
                case = run_one_case(
                    script_dir=script_dir,
                    spec_root=args.spec_root,
                    sde_path=args.sde,
                    bench=bench,
                    run_dir=run_dir,
                    warmup_seconds=w,
                    args=args,
                )
                summary.append(case)
                if case.metrics:
                    print(
                        "  ok:",
                        f"data_all_rd_r2={case.metrics.get('data_all_rd_r2', 0.0):.4f}",
                        f"data_all_sdp_r2={case.metrics.get('data_all_sdp_r2', 0.0):.4f}",
                        f"data_all_stride_r2={case.metrics.get('data_all_stride_r2', 0.0):.4f}",
                        f"inst_all_rd_r2={case.metrics.get('inst_all_rd_r2', 0.0):.4f}",
                        f"inst_all_sdp_r2={case.metrics.get('inst_all_sdp_r2', 0.0):.4f}",
                        f"inst_all_stride_r2={case.metrics.get('inst_all_stride_r2', 0.0):.4f}",
                        f"out={case.out_dir}",
                    )
            except Exception as e:
                msg = str(e)
                print(f"  error: {msg}")
                summary.append(RunCase(bench=bench, warmup=w, status="error", out_dir="", error=msg))
                if args.stop_on_error:
                    break
        if args.stop_on_error and summary and summary[-1].status == "error":
            break

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

    csv_keys = [
        "bench",
        "warmup_seconds",
        "status",
        "out_dir",
        "error",
        "all_rd_r2",
        "all_sdp_r2",
        "read_rd_r2",
        "read_sdp_r2",
        "write_rd_r2",
        "write_sdp_r2",
        "all_stride_r2",
        "all_stride_l1",
        "all_stride_jsd",
        "all_rd_l1",
        "all_cold_abs_diff",
        "data_all_rd_r2",
        "data_all_sdp_r2",
        "data_all_stride_r2",
        "inst_all_rd_r2",
        "inst_all_sdp_r2",
        "inst_all_stride_r2",
        "perf_insn_lines",
    ]
    lines = [",".join(csv_keys)]
    for x in summary:
        m = x.metrics or {}
        row = [
            x.bench,
            f"{x.warmup:g}",
            x.status,
            x.out_dir,
            x.error or "",
            str(m.get("all_rd_r2", "")),
            str(m.get("all_sdp_r2", "")),
            str(m.get("read_rd_r2", "")),
            str(m.get("read_sdp_r2", "")),
            str(m.get("write_rd_r2", "")),
            str(m.get("write_sdp_r2", "")),
            str(m.get("all_stride_r2", "")),
            str(m.get("all_stride_l1", "")),
            str(m.get("all_stride_jsd", "")),
            str(m.get("all_rd_l1", "")),
            str(m.get("all_cold_abs_diff", "")),
            str(m.get("data_all_rd_r2", "")),
            str(m.get("data_all_sdp_r2", "")),
            str(m.get("data_all_stride_r2", "")),
            str(m.get("inst_all_rd_r2", "")),
            str(m.get("inst_all_sdp_r2", "")),
            str(m.get("inst_all_stride_r2", "")),
            str(m.get("perf_insn_lines", "")),
        ]
        lines.append(",".join(v.replace(",", ";") for v in row))
    summary_csv.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok = sum(1 for x in summary if x.status == "ok")
    err = sum(1 for x in summary if x.status != "ok")
    print(f"\n[done] ok={ok} error={err}")
    print(f"  summary json: {summary_json}")
    print(f"  summary csv:  {summary_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
