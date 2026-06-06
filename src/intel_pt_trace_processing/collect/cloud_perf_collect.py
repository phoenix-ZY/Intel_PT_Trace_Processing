from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

from intel_pt_trace_processing.collect.perf_targets import PerfTarget, perf_record_cmd, run_perf_stat
from intel_pt_trace_processing.collect.perf_stats import parse_perf_stat_csv, parse_perf_stat_unsupported
from intel_pt_trace_processing.perf.selection import load_selection_sidecar, write_selection_sidecar
from intel_pt_trace_processing.workloads.cloud_runtime import log, pid_alive, run_cmd


def verify_buildid_cache(
    *,
    perf_tool: Path,
    perf_data: Path,
    command_prefix: tuple[str, ...],
) -> None:
    result = run_cmd(
        [
            *command_prefix,
            str(perf_tool),
            "buildid-cache",
            "-f",
            "-M",
            str(perf_data),
        ],
        env={**os.environ, "PERF_PAGER": "cat"},
    )
    missing = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
    if result.returncode != 0 or missing:
        detail = "; ".join(missing[:5])
        if not detail:
            detail = (result.stderr or "").strip().splitlines()[-1] if (result.stderr or "").strip() else "unknown error"
        raise RuntimeError(f"build-id cache verification failed for {perf_data.name}: {detail}")


def run_perf_stat_sample(
    *,
    perf_tool: Path,
    target: PerfTarget,
    duration_s: float,
    out_txt: Path,
    out_json: Path,
    events: str,
    cgroup: str | None = None,
    command_prefix: tuple[str, ...] = (),
) -> tuple[int, int]:
    """
    Run `perf stat` for a perf target for duration_s seconds.
    Returns (returncode, stderr_len). Writes raw text + parsed JSON.
    """
    return run_perf_stat(
        perf_tool=perf_tool,
        target=target,
        duration_s=duration_s,
        out_txt=out_txt,
        out_json=out_json,
        events=events,
        parse_metrics=parse_perf_stat_csv,
        parse_unsupported=parse_perf_stat_unsupported,
        cgroup=cgroup,
        command_prefix=command_prefix,
    )

def collect_traces_for_config(
    perf_tool: Path,
    bench_name: str,
    perf_target: PerfTarget,
    monitor_pid: int | None,
    output_dir: Path,
    interval: float,
    record_duration: float,
    max_samples: int,
    bench_process: subprocess.Popen,
    perf_mmap_pages: str,
    intel_pt_event: str,
    perf_cgroup: str,
    perf_command_prefix: tuple[str, ...] = (),
    *,
    collect_mode: str = "pt",  # "pt" | "stat"
    perf_stat_events: str = "cycles,instructions",
    start_index: int = 0,
):
    """
    Periodically record PT traces from a perf target.
    Container mode uses `perf record -a -C CPU -G CGROUP`.
    Output files: perf.<bench_name>.<sample_index>.data
    """
    sample_count = int(start_index)
    start_time = time.time()

    log(
        "📊",
        f"Sampling perf target {perf_target.flag} {perf_target.cpu} every {interval}s "
        f"in cgroup {perf_cgroup} "
        f"(target {max_samples} samples; starting at {sample_count})...",
    )
    if collect_mode == "pt":
        log("🔬", f"mode=pt perf record -m {perf_mmap_pages} (data,aux mmap pages)")
    else:
        log("🔬", f"mode=stat perf stat -e {perf_stat_events}")

    while sample_count < max_samples:
        # Check if the thread is still alive
        if monitor_pid is not None and not pid_alive(monitor_pid):
            log("🏁", "Monitored target process/thread exited.")
            break

        # Check if the bench process has finished
        if bench_process.poll() is not None:
            log("🏁", "Benchmark load finished.")
            break

        sample_count += 1
        elapsed = time.time() - start_time
        pt_path = output_dir / f"perf.{bench_name}.{sample_count}.data"
        if collect_mode == "stat":
            case_root = output_dir / bench_name
            report_dir = case_root / "report"
            report_dir.mkdir(parents=True, exist_ok=True)
            slug = bench_name.replace(".", "_")
            prefix = f"{slug}_s{sample_count}"
            stat_txt = report_dir / f"{prefix}.perf.stat.csv"
            stat_json = report_dir / f"{prefix}.perf.stat.json"
            if stat_json.is_file() and stat_json.stat().st_size > 0:
                log("⚠️", f"{stat_json.name} already exists; skipping index {sample_count}")
                continue
            rc, _ = run_perf_stat_sample(
                perf_tool=perf_tool,
                target=perf_target,
                duration_s=record_duration,
                out_txt=stat_txt,
                out_json=stat_json,
                events=perf_stat_events,
                cgroup=perf_cgroup,
                command_prefix=perf_command_prefix,
            )
            # perf stat exits 255 when any requested event is unsupported/not-counted,
            # but it still prints partial results. Treat 255 as non-fatal.
            if rc not in (0, 255):
                log("❌", f"perf stat failed for {bench_name} sample {sample_count} (rc={rc})")
                break
            log("✅", f"Sample {sample_count} @ {elapsed:.0f}s → {stat_json.name}")
        else:
            if pt_path.exists():
                try:
                    existing_sz = pt_path.stat().st_size
                except OSError:
                    existing_sz = 0
                if existing_sz > 0:
                    existing_selection = load_selection_sidecar(pt_path)
                    if (
                        existing_selection is not None
                        and existing_selection.get("cgroup") == perf_cgroup
                        and existing_selection.get("root_pid") == monitor_pid
                    ):
                        log("⚠️", f"{pt_path.name} already exists ({existing_sz}B); skipping index {sample_count}")
                        continue
                    log("♻️", f"{pt_path.name} belongs to an older target; re-recording")
                    pt_path.unlink()
                else:
                    # Empty file: treat as a failed prior record and re-collect.
                    try:
                        pt_path.unlink()
                    except FileNotFoundError:
                        pass
                    log("♻️", f"{pt_path.name} exists but is 0B — deleting and re-recording")

            # Keep ownership with the invoking user when perf itself runs through sudo.
            pt_path.touch()
            pr = run_cmd(
                perf_record_cmd(
                    perf_tool=perf_tool,
                    mmap_pages=perf_mmap_pages,
                    event=intel_pt_event,
                    output=pt_path,
                    target=perf_target,
                    duration_s=record_duration,
                    cgroup=perf_cgroup,
                    command_prefix=perf_command_prefix,
                )
            )
            # perf can fail (permissions, perf_event_paranoid, unsupported intel_pt) and still leave a 0B file.
            # Treat empty output as failure so we don't "succeed" with unusable perf.data.
            try:
                out_sz = pt_path.stat().st_size if pt_path.exists() else 0
            except OSError:
                out_sz = 0
            if pr.returncode != 0 or out_sz <= 0:
                if out_sz <= 0 and pt_path.exists():
                    try:
                        pt_path.unlink()
                    except FileNotFoundError:
                        pass
                err = (pr.stderr or "").strip()
                hint = (
                    "perf record produced empty output. Common causes: not running as root, "
                    "kernel.perf_event_paranoid too restrictive, missing CAP_PERFMON/CAP_SYS_ADMIN, "
                    "or intel_pt not supported/enabled on this machine."
                )
                log("❌", f"perf record failed for {bench_name} sample {sample_count} (rc={pr.returncode}, size={out_sz}B)")
                if err:
                    log("❌", f"perf stderr: {err.splitlines()[-1]}")
                log("💡", hint)
                break

            verify_buildid_cache(
                perf_tool=perf_tool,
                perf_data=pt_path,
                command_prefix=perf_command_prefix,
            )
            write_selection_sidecar(
                pt_path,
                {
                    "mode": "cgroup",
                    "cgroup": perf_cgroup,
                    "cpu": perf_target.cpu,
                    "root_pid": monitor_pid,
                    "bench": bench_name,
                    "perf_command_prefix": list(perf_command_prefix),
                    "buildid_cache_verified": True,
                },
            )
            log("✅", f"Sample {sample_count} @ {elapsed:.0f}s → {pt_path.name} ({out_sz}B)")

        # Wait for the next interval
        wait_until = time.time() + interval
        while time.time() < wait_until:
            if (monitor_pid is not None and not pid_alive(monitor_pid)) or bench_process.poll() is not None:
                log("🏁", "Target/benchmark finished during wait.")
                return sample_count
            time.sleep(1)

    return sample_count
