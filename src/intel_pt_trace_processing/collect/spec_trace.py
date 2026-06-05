from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from intel_pt_trace_processing.collect.perf_targets import PerfTarget, cpu_perf_target, perf_record_cmd, perf_stat_cmd
from intel_pt_trace_processing.collect.perf_stats import parse_perf_stat_csv, parse_perf_stat_unsupported
from intel_pt_trace_processing.collect.spec_layout import CaseLayout, PreparedCase, make_case_layout
from intel_pt_trace_processing.core.commands import run_step
from intel_pt_trace_processing.workloads.spec import build_spec_shell_command
from intel_pt_trace_processing.workloads.spec_runtime import (
    cleanup_pid,
    extract_cmd_line,
    pick_spec_benchmark_pid,
    pid_alive,
    read_proc_argv0_basename,
    read_proc_exe,
)

def ts_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def terminate_process(proc: subprocess.Popen | None, *, timeout: float = 5.0) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.terminate()
    except OSError:
        return
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            pass


def finalize_perf_stat(
    *,
    stat_proc: subprocess.Popen | None,
    layout: "CaseLayout",
    args: argparse.Namespace,
    bench: str,
    phase: str,
    perf_target: PerfTarget,
    duration_s: float,
) -> None:
    if stat_proc is None:
        return
    events = str(getattr(args, "perf_stat_events", "cycles,instructions"))
    st_out, st_err = stat_proc.communicate()
    raw = (st_err or "") + (("\n" + st_out) if st_out else "")
    layout.perf_stat_csv.write_text(raw, encoding="utf-8", errors="replace")
    payload = {
        "schema": "perf-stat-v1",
        "bench": bench,
        "phase": phase,
        "warmup_s": float(layout.warmup),
        "duration_s": float(duration_s),
        "events": events,
        "target": perf_target.to_json(),
        "perf_flag": perf_target.flag,
        "perf_id": int(perf_target.cpu),
        "returncode": int(stat_proc.returncode),
        "metrics": parse_perf_stat_csv(raw),
        "unsupported_events": parse_perf_stat_unsupported(raw),
        "raw_path": str(layout.perf_stat_csv),
    }
    layout.perf_stat_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def log_spec_perf_core(
    *,
    bench: str,
    phase: str,
    perf_target: PerfTarget,
    cpuset: str | None,
    sample_label: str = "",
) -> None:
    sfx = f" {sample_label}" if sample_label else ""
    print(
        f"[spec-pt]{sfx} bench={bench} phase={phase} "
        f"perf_record {perf_target.flag} {perf_target.cpu} target_kind=cpu "
        f"spec_cpuset={cpuset or ''}",
        flush=True,
    )

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

def run_trace_phase(
    *,
    seq: int,
    layout: CaseLayout,
    script_dir: Path,
    spec_root: Path,
    sde_path: Path,
    run_dir: Path,
    args: argparse.Namespace,
) -> PreparedCase:
    cmd_line = extract_cmd_line(spec_root, run_dir)
    exe_basename = Path(shlex.split(cmd_line)[0]).name

    # ---- SDE phase (optional) ----
    if args.enable_sde:
        sde_shell_cmd = build_spec_shell_command(
            cmd_line=cmd_line,
            shrc=spec_root / "shrc",
            cpuset=getattr(args, "spec_cpuset", None),
        )
        with (layout.report_dir / f"{layout.prefix}.spec.sde.stdout.txt").open("w", encoding="utf-8") as out_fp, (
            layout.report_dir / f"{layout.prefix}.spec.sde.stderr.txt"
        ).open("w", encoding="utf-8") as err_fp:
            launcher = subprocess.Popen(
                ["bash", "-lc", sde_shell_cmd],
                cwd=run_dir,
                stdout=out_fp,
                stderr=err_fp,
                text=True,
            )
        launcher_pid = int(launcher.pid)
        time.sleep(1.0)
        if not pid_alive(launcher_pid):
            raise RuntimeError("SDE phase launcher failed to start")
        target_pid = pick_spec_benchmark_pid(launcher_pid, run_dir, exe_basename, resolve_timeout=8.0)
        target_exe = read_proc_exe(target_pid)
        argv0_ok = read_proc_argv0_basename(target_pid) == exe_basename
        exe_ok = bool(target_exe) and Path(target_exe).name == exe_basename
        if not target_exe or (not exe_ok and not argv0_ok):
            cleanup_pid(launcher_pid)
            raise RuntimeError("cannot resolve benchmark pid for SDE phase")
        if layout.warmup > 0:
            time.sleep(layout.warmup)
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
            str(layout.sde_trace),
            "-control",
            f"start:icount:0,stop:icount:{args.total_insns}",
            "-length",
            str(args.total_insns),
        ]
        layout.sde_log.write_text("", encoding="utf-8")
        with layout.sde_log.open("a", encoding="utf-8") as fp:
            fp.write(f"=== SDE prologue {ts_now()} ===\n")
            fp.write(f"bench={layout.bench} warmup={layout.warmup}\n")
            fp.write("cmd: " + " ".join(sde_cmd) + "\n")
        run_step(
            sde_cmd,
            verbose=args.verbose,
            stdout_path=layout.sde_log if not args.verbose else None,
            append_logs=True,
        )
        wait_trace_settle(
            layout.sde_trace,
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
        if not layout.sde_trace.exists() or layout.sde_trace.stat().st_size == 0:
            raise RuntimeError("empty SDE trace")

    # ---- perf phase ----
    shrc = spec_root / "shrc"
    perf_shell_cmd = build_spec_shell_command(
        cmd_line=cmd_line,
        shrc=shrc,
        cpuset=getattr(args, "spec_cpuset", None),
    )
    with (layout.report_dir / f"{layout.prefix}.spec.perf.stdout.txt").open("w", encoding="utf-8") as out_fp, (
        layout.report_dir / f"{layout.prefix}.spec.perf.stderr.txt"
    ).open("w", encoding="utf-8") as err_fp:
        perf_launcher = subprocess.Popen(
            ["bash", "-lc", perf_shell_cmd],
            cwd=run_dir,
            stdout=out_fp,
            stderr=err_fp,
            text=True,
        )
    time.sleep(1.0)
    if perf_launcher.poll() is not None:
        raise RuntimeError("perf phase launcher failed to start")
    if layout.warmup > 0:
        time.sleep(layout.warmup)
    if perf_launcher.poll() is not None:
        raise RuntimeError("benchmark exited before perf collect")
    perf_target = cpu_perf_target(int(getattr(args, "perf_cpu", 6)))
    log_spec_perf_core(
        bench=layout.bench,
        phase="perf_once",
        perf_target=perf_target,
        cpuset=getattr(args, "spec_cpuset", None),
    )

    collect_mode = str(getattr(args, "collect_mode", "pt"))
    try:
        if collect_mode == "stat":
            # PMU-only mode: do NOT run perf record / intel_pt, only perf stat.
            events = str(getattr(args, "perf_stat_events", "cycles,instructions"))
            stat_proc = subprocess.Popen(
                perf_stat_cmd(
                    perf_tool="perf",
                    events=events,
                    target=perf_target,
                    duration_s=float(args.perf_record_seconds),
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            finalize_perf_stat(
                stat_proc=stat_proc,
                layout=layout,
                args=args,
                bench=layout.bench,
                phase="perf_once",
                perf_target=perf_target,
                duration_s=float(args.perf_record_seconds),
            )
        else:
            run_step(
                perf_record_cmd(
                    perf_tool="perf",
                    mmap_pages=args.perf_mmap_pages,
                    event=args.perf_event,
                    output=layout.perf_data,
                    target=perf_target,
                    duration_s=float(args.perf_record_seconds),
                    quiet=True,
                ),
                verbose=args.verbose,
                stderr_path=layout.perf_record_stderr,
            )
    finally:
        terminate_process(perf_launcher)
    if not layout.perf_data.exists() or layout.perf_data.stat().st_size == 0:
        if collect_mode != "stat":
            raise RuntimeError("empty perf.data")
    return PreparedCase(seq=seq, layout=layout)

def run_trace_phase_perf_stream(
    *,
    seq_base: int,
    bench: str,
    script_dir: Path,
    spec_root: Path,
    run_dir: Path,
    args: argparse.Namespace,
) -> list[PreparedCase]:
    """
    Perf-only stream sampling mode:
      run benchmark once, then take perf.data samples every interval seconds until it exits.

    Each sample is materialized as its own CaseLayout under <output-base>/<bench>/<t>s/.
    This mode is incompatible with SDE (which requires restarting for each warmup).
    """
    if getattr(args, "enable_sde", False):
        raise RuntimeError("perf stream sampling mode does not support --enable-sde")
    interval = float(getattr(args, "perf_stream_interval", 10.0))
    first_after = float(getattr(args, "perf_stream_first_after", interval))
    max_samples = int(getattr(args, "perf_stream_max_samples", 0))
    if interval <= 0:
        raise RuntimeError("--perf-stream-interval must be > 0")
    if first_after < 0:
        raise RuntimeError("--perf-stream-first-after must be >= 0")
    if max_samples < 0:
        raise RuntimeError("--perf-stream-max-samples must be >= 0")

    cmd_line = extract_cmd_line(spec_root, run_dir)

    # Put the benchmark stdout/stderr into a stable location (not per-sample).
    stream_dir = args.output_base / bench / "_stream"
    stream_report = stream_dir / "report"
    stream_report.mkdir(parents=True, exist_ok=True)
    out_path = stream_report / f"{bench.replace('.', '_')}.spec.perf.stdout.txt"
    err_path = stream_report / f"{bench.replace('.', '_')}.spec.perf.stderr.txt"

    shrc = spec_root / "shrc"
    stream_shell_cmd = build_spec_shell_command(
        cmd_line=cmd_line,
        shrc=shrc,
        cpuset=getattr(args, "spec_cpuset", None),
    )
    with out_path.open("w", encoding="utf-8") as out_fp, err_path.open("w", encoding="utf-8") as err_fp:
        launcher = subprocess.Popen(
            ["bash", "-lc", stream_shell_cmd],
            cwd=run_dir,
            stdout=out_fp,
            stderr=err_fp,
            text=True,
        )

    time.sleep(1.0)
    if launcher.poll() is not None:
        raise RuntimeError("perf stream launcher failed to start")
    collect_mode = str(getattr(args, "collect_mode", "pt"))

    prepared: list[PreparedCase] = []
    start_t = time.time()
    next_at = float(first_after)
    sample_idx = 0
    try:
        while True:
            if max_samples > 0 and sample_idx >= max_samples:
                break
            if launcher.poll() is not None:
                break

            # Wait until the next sampling timestamp.
            deadline = start_t + next_at
            while time.time() < deadline:
                if launcher.poll() is not None:
                    break
                time.sleep(0.05)
            if launcher.poll() is not None:
                break

            perf_target = cpu_perf_target(int(getattr(args, "perf_cpu", 6)))
            log_spec_perf_core(
                bench=bench,
                phase="perf_stream",
                perf_target=perf_target,
                cpuset=getattr(args, "spec_cpuset", None),
                sample_label=f"sample_index={sample_idx} t={next_at:g}s",
            )

            # Materialize one sample as its own case (warmup_seconds = time since start).
            layout = make_case_layout(bench=bench, warmup_seconds=next_at, output_base=args.output_base)
            if collect_mode == "stat":
                if bool(getattr(args, "skip_existing", True)) and layout.perf_stat_json.is_file() and layout.perf_stat_json.stat().st_size > 0:
                    prepared.append(PreparedCase(seq=seq_base + sample_idx, layout=layout))
                    sample_idx += 1
                    next_at += interval
                    continue
            elif bool(getattr(args, "skip_existing", True)) and layout.perf_data.is_file() and layout.perf_data.stat().st_size > 0:
                # Resume-friendly: if perf.data already exists for this timestamped case dir,
                # do not record again; just schedule post phase (which will also reuse existing outputs).
                prepared.append(PreparedCase(seq=seq_base + sample_idx, layout=layout))
                sample_idx += 1
                next_at += interval
                continue
            try:
                if collect_mode == "stat":
                    events = str(getattr(args, "perf_stat_events", "cycles,instructions"))
                    stat_proc = subprocess.Popen(
                        perf_stat_cmd(
                            perf_tool="perf",
                            events=events,
                            target=perf_target,
                            duration_s=float(args.perf_record_seconds),
                        ),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    finalize_perf_stat(
                        stat_proc=stat_proc,
                        layout=layout,
                        args=args,
                        bench=bench,
                        phase="perf_stream",
                        perf_target=perf_target,
                        duration_s=float(args.perf_record_seconds),
                    )
                else:
                    run_step(
                        perf_record_cmd(
                            perf_tool="perf",
                            mmap_pages=args.perf_mmap_pages,
                            event=args.perf_event,
                            output=layout.perf_data,
                            target=perf_target,
                            duration_s=float(args.perf_record_seconds),
                            quiet=True,
                        ),
                        verbose=args.verbose,
                        stderr_path=layout.perf_record_stderr,
                    )
            except Exception:
                # Common race: benchmark exits between the alive check and perf record.
                # In that case, keep already collected samples and stop sampling gracefully.
                esrch = False
                try:
                    if layout.perf_record_stderr.is_file():
                        t = layout.perf_record_stderr.read_text(encoding="utf-8", errors="replace").lower()
                        # perf: sys_perf_event_open ESRCH, e.g.:
                        #   "returned with 3 (No such process)" or similar.
                        if "no such process" in t or "sys_perf_event_open" in t and "returned with 3" in t:
                            esrch = True
                except OSError:
                    pass
                if esrch or launcher.poll() is not None:
                    break
                raise
            if collect_mode == "stat":
                if not layout.perf_stat_json.exists() or layout.perf_stat_json.stat().st_size == 0:
                    if launcher.poll() is not None:
                        break
                    raise RuntimeError("empty perf.stat.json in perf stream sampling")
            else:
                if not layout.perf_data.exists() or layout.perf_data.stat().st_size == 0:
                    if launcher.poll() is not None:
                        break
                    raise RuntimeError("empty perf.data in perf stream sampling")
            prepared.append(PreparedCase(seq=seq_base + sample_idx, layout=layout))
            sample_idx += 1
            next_at += interval
    finally:
        # Ensure benchmark is terminated if still alive.
        terminate_process(launcher)

    return prepared
