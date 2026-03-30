#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import json
import math
import os
import shlex
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path

import analyze_insn_trace_portrait as insn_portrait
from perf_pipeline import perf_postprocess_one, run_step
from perf_pipeline import add_perf_postprocess_args, validate_perf_postprocess_args

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


def ts_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def pid_alive(pid: int) -> bool:
    return (Path("/proc") / str(pid)).exists()


def read_proc_exe(pid: int) -> str:
    try:
        return str((Path("/proc") / str(pid) / "exe").resolve())
    except OSError:
        return ""


def read_proc_argv0_basename(pid: int) -> str:
    """
    Read argv[0] basename from /proc/<pid>/cmdline.

    Why: in SPEC CPU runs the benchmark binary may be executed from a copied/renamed
    path like /tmp/fileXXXX (so /proc/<pid>/exe basename is "fileXXXX"), while argv[0]
    often remains the original "../run_base.../<bench>_base..." string. For PID
    resolution, argv[0] is a more stable identifier in that case.
    """
    try:
        raw = (Path("/proc") / str(pid) / "cmdline").read_bytes()
    except OSError:
        return ""
    if not raw:
        return ""
    argv0_b = raw.split(b"\0", 1)[0]
    if not argv0_b:
        return ""
    argv0 = argv0_b.decode("utf-8", errors="replace").strip()
    if not argv0:
        return ""
    return Path(argv0).name


def read_proc_ppid(pid: int) -> int:
    try:
        for line in (Path("/proc") / str(pid) / "status").read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("PPid:"):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return 0


def is_descendant_of(pid: int, ancestor: int) -> bool:
    if pid <= 1 or ancestor <= 0:
        return False
    cur = pid
    for _ in range(2048):
        if cur == ancestor:
            return True
        ppid = read_proc_ppid(cur)
        if ppid <= 1:
            return False
        cur = ppid
    return False


def is_strict_descendant_of(pid: int, ancestor: int) -> bool:
    """True if pid is a proper descendant of ancestor (pid != ancestor)."""
    if pid <= 1 or ancestor <= 0 or pid == ancestor:
        return False
    cur = read_proc_ppid(pid)
    for _ in range(2048):
        if cur == ancestor:
            return True
        if cur <= 1:
            return False
        cur = read_proc_ppid(cur)
    return False


def scan_proc_benchmark_pid(
    run_dir: Path,
    exe_basename: str,
    prefer_under_pid: int,
) -> int | None:
    """
    Last-resort PID lookup: same information `ps` uses, but via /proc (no brittle parsing).

    When the launcher shell has not exec'd yet, or the process tree is odd, BFS from
    launcher_pid can miss the real benchmark while `ps` still shows it under run_dir.
    We match cwd == run_dir and argv[0] basename == exe_basename.

    SPEC workloads like 505.mcf_r often fork a parent that stays sleeping (same argv0/cwd)
    and a child that runs hot. is_descendant_of(p, launcher) is True when p==launcher,
    so we must not return the parent first; among launcher + descendants in candidates,
    pick the highest ps pcpu.
    """
    try:
        run_res = run_dir.resolve()
    except OSError:
        return None
    candidates: list[int] = []
    for p in Path("/proc").iterdir():
        if not p.name.isdigit():
            continue
        pid = int(p.name)
        try:
            cwd = Path(os.readlink(f"/proc/{pid}/cwd")).resolve()
        except OSError:
            continue
        if cwd != run_res:
            continue
        if read_proc_argv0_basename(pid) != exe_basename:
            continue
        candidates.append(pid)
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    in_tree = [
        p
        for p in candidates
        if p == prefer_under_pid or is_strict_descendant_of(p, prefer_under_pid)
    ]
    pool = in_tree if in_tree else candidates
    return pick_hottest_pid_by_ps_pcpu(pool)


def read_ps_pcpu(pid: int) -> float:
    try:
        pr = subprocess.run(
            ["ps", "-p", str(pid), "-o", "pcpu=", "--no-headers"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return float(pr.stdout.strip() or "0")
    except (ValueError, subprocess.TimeoutExpired, OSError):
        return 0.0


def pick_hottest_pid_by_ps_pcpu(pids: list[int]) -> int:
    if not pids:
        raise ValueError("empty pids")
    if len(pids) == 1:
        return pids[0]
    best = pids[0]
    best_c = read_ps_pcpu(best)
    for pid in pids[1:]:
        c = read_ps_pcpu(pid)
        if c > best_c:
            best, best_c = pid, c
    return best


def spec_get_thread_tids(pid: int) -> list[dict[str, float | int | str]]:
    """
    Threads under pid via ps -T (same idea as run_cloud_perf_trace_analysis.get_thread_tids).
    Sorted by pcpu descending in Python (some ps builds ignore --sort with -T).
    """
    result = subprocess.run(
        ["ps", "-T", "-p", str(pid), "-o", "spid=", "-o", "pcpu=", "-o", "comm="],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    threads: list[dict[str, float | int | str]] = []
    for line in (result.stdout or "").strip().splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) >= 2 and parts[0].isdigit():
            threads.append(
                {
                    "tid": int(parts[0]),
                    "cpu": float(parts[1]),
                    "comm": parts[2] if len(parts) > 2 else "",
                }
            )
    threads.sort(key=lambda t: float(t["cpu"]), reverse=True)
    return threads


def spec_get_busiest_tid(pid: int) -> int:
    threads = spec_get_thread_tids(pid)
    if threads:
        return int(threads[0]["tid"])
    return pid


def pick_spec_perf_record_target(
    resolved_process_pid: int,
    perf_attach: str,
) -> tuple[int, str]:
    """
    Returns (id_for_perf, flag) where flag is '-p' or '-t' for perf record.
    Cloud pipeline uses -t <busiest_tid> for PT on hot threads.
    """
    mode = (perf_attach or "process").strip().lower()
    if mode in ("busiest-tid", "busiest_tid", "tid"):
        tid = spec_get_busiest_tid(resolved_process_pid)
        return tid, "-t"
    return resolved_process_pid, "-p"


def log_spec_perf_attach(
    *,
    bench: str,
    phase: str,
    launcher_pid: int,
    resolved_pid: int,
    perf_flag: str,
    perf_id: int,
    run_dir: Path,
    sample_label: str = "",
) -> None:
    exe = read_proc_exe(resolved_pid)
    argv0 = read_proc_argv0_basename(resolved_pid)
    try:
        cwd = os.readlink(f"/proc/{resolved_pid}/cwd")
    except OSError:
        cwd = ""
    sfx = f" {sample_label}" if sample_label else ""
    print(
        f"[spec-pt]{sfx} bench={bench} phase={phase} launcher_pid={launcher_pid} "
        f"resolved_pid={resolved_pid} perf_record {perf_flag} {perf_id} "
        f"exe={exe} argv0_basename={argv0} cwd={cwd}",
        flush=True,
    )


def pick_spec_benchmark_pid(
    launcher_pid: int,
    run_dir: Path,
    exe_basename: str,
    *,
    resolve_timeout: float = 8.0,
) -> int:
    """
    Prefer /proc scan (cwd + argv0) so we attach to the same process `ps` shows in the run dir,
    then fall back to tree walk from the launcher.
    """
    scanned = scan_proc_benchmark_pid(run_dir, exe_basename, launcher_pid)
    if scanned is not None:
        return scanned
    return resolve_target_pid(
        launcher_pid,
        exe_basename,
        run_dir=run_dir,
        timeout_s=resolve_timeout,
    )


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


def collect_matching_pids_under_launcher(
    launcher_pid: int,
    exe_basename: str | None,
    run_dir: Path | None,
) -> list[int]:
    """
    BFS under launcher_pid; collect every pid that looks like the benchmark binary.
    Used to prefer the hot child when parent+child share argv0/cwd (e.g. mcf_r fork).
    """
    out: list[int] = []
    if not exe_basename or not pid_alive(launcher_pid):
        return out

    def matches(pid: int) -> bool:
        cexe = read_proc_exe(pid)
        if cexe and Path(cexe).name == exe_basename:
            return True
        if read_proc_argv0_basename(pid) == exe_basename:
            return True
        if run_dir:
            try:
                cwd = os.readlink(f"/proc/{pid}/cwd")
                if (
                    cexe
                    and Path(cexe).is_file()
                    and str(Path(cexe).resolve()).startswith(str(run_dir.resolve()) + os.sep)
                    and Path(cwd).resolve() == run_dir.resolve()
                ):
                    return True
            except OSError:
                pass
        return False

    q = [launcher_pid]
    seen: set[int] = set()
    while q:
        pid = q.pop(0)
        if pid in seen:
            continue
        if len(seen) >= 4096:
            break
        seen.add(pid)
        if matches(pid):
            out.append(pid)
        for cpid in children_of(pid):
            if cpid not in seen:
                q.append(cpid)
    return out


def resolve_target_pid(
    launcher_pid: int,
    exe_basename: str | None = None,
    *,
    run_dir: Path | None = None,
    timeout_s: float = 8.0,
) -> int:
    end = time.time() + timeout_s
    while time.time() <= end:
        if pid_alive(launcher_pid) and exe_basename:
            cands = collect_matching_pids_under_launcher(launcher_pid, exe_basename, run_dir)
            if cands:
                return pick_hottest_pid_by_ps_pcpu(cands)
        time.sleep(0.02)
    if run_dir is not None and exe_basename:
        scanned = scan_proc_benchmark_pid(run_dir, exe_basename, launcher_pid)
        if scanned is not None:
            return scanned
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


def load_compare_metrics(path: Path, metric_prefix: str = "") -> dict:
    obj = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, object] = {}
    excluded = obj.get("excluded_feature_scalars")
    if isinstance(excluded, list):
        out[f"{metric_prefix}excluded_feature_scalars"] = "|".join(str(x) for x in excluded)
    accesses = obj.get("accesses") or list(obj.get("per_access", {}).keys())
    for access in accesses:
        pa = obj["per_access"][access]
        p = f"{metric_prefix}{access}_"
        metrics = pa.get("metrics", {})
        if isinstance(metrics, dict):
            for k, v in metrics.items():
                if isinstance(v, (int, float)):
                    out[f"{p}rd_{k}"] = v
        sdp_metrics = pa.get("sdp", {}).get("metrics", {})
        if isinstance(sdp_metrics, dict):
            for k, v in sdp_metrics.items():
                if isinstance(v, (int, float)):
                    out[f"{p}sdp_{k}"] = v
        stride = pa.get("stride", {})
        sm = stride.get("metrics", {})
        if isinstance(sm, dict):
            for k, v in sm.items():
                if isinstance(v, (int, float)):
                    out[f"{p}stride_{k}"] = v
        fm = pa.get("feature_metrics", {})
        if isinstance(fm, dict):
            for k, v in fm.items():
                if isinstance(v, (int, float)):
                    out[f"{p}{k}"] = v
        ov = pa.get("overall_vector", {})
        om = ov.get("metrics", {}) if isinstance(ov, dict) else {}
        if isinstance(om, dict):
            for k, v in om.items():
                if isinstance(v, (int, float)):
                    out[f"{p}overall_{k}"] = v
        comps = om.get("overall_score_components") if isinstance(om, dict) else None
        if isinstance(comps, dict):
            for k, v in comps.items():
                if isinstance(v, (int, float)):
                    out[f"{p}overall_component_{k}"] = v
        out[f"{p}overall_dims"] = ov.get("dimensions", 0) if isinstance(ov, dict) else 0
        top_dims = ov.get("largest_error_dims", []) if isinstance(ov, dict) else []
        top0 = top_dims[0] if top_dims and isinstance(top_dims[0], dict) else {}
        out[f"{p}overall_top_dim"] = top0.get("dimension", "")
        out[f"{p}overall_top_dim_abs_diff"] = top0.get("abs_diff", 0.0)
        top3 = [x.get("dimension", "") for x in top_dims[:3] if isinstance(x, dict) and x.get("dimension")]
        out[f"{p}overall_top3_dims"] = "|".join(top3)
    return out


def maybe_write_feature_bundle(
    *,
    out_path: Path,
    sde_data_analysis: Path,
    sde_inst_analysis: Path,
    perf_data_analysis: Path,
    perf_inst_analysis: Path,
    data_compare: Path,
    inst_compare: Path,
) -> None:
    def pick_features(analysis_obj: dict) -> dict:
        per = analysis_obj.get("per_access", {})
        out: dict[str, dict] = {}
        for access, access_obj in per.items():
            feat = access_obj.get("feature")
            if isinstance(feat, dict):
                out[access] = feat
        return out

    sde_data = json.loads(sde_data_analysis.read_text(encoding="utf-8"))
    sde_inst = json.loads(sde_inst_analysis.read_text(encoding="utf-8"))
    perf_data = json.loads(perf_data_analysis.read_text(encoding="utf-8"))
    perf_inst = json.loads(perf_inst_analysis.read_text(encoding="utf-8"))
    data_cmp = json.loads(data_compare.read_text(encoding="utf-8"))
    inst_cmp = json.loads(inst_compare.read_text(encoding="utf-8"))

    bundle = {
        "schema": "trace-feature-bundle-v1",
        "line_size": sde_data.get("line_size"),
        "rd_definition": sde_data.get("rd_definition"),
        "rd_hist_cap_lines": sde_data.get("rd_hist_cap_lines"),
        "stride_bin_cap_lines": sde_data.get("stride_bin_cap_lines"),
        "data": {
            "ref_path": sde_data.get("input_path"),
            "test_path": perf_data.get("input_path"),
            "ref_features": pick_features(sde_data),
            "test_features": pick_features(perf_data),
            "feature_metrics": {
                access: data_cmp.get("per_access", {}).get(access, {}).get("feature_metrics", {})
                for access in data_cmp.get("accesses", [])
            },
            "overall_vector_similarity": {
                access: data_cmp.get("per_access", {}).get(access, {}).get("overall_vector", {})
                for access in data_cmp.get("accesses", [])
            },
        },
        "inst": {
            "ref_path": sde_inst.get("input_path"),
            "test_path": perf_inst.get("input_path"),
            "ref_features": pick_features(sde_inst),
            "test_features": pick_features(perf_inst),
            "feature_metrics": {
                access: inst_cmp.get("per_access", {}).get(access, {}).get("feature_metrics", {})
                for access in inst_cmp.get("accesses", [])
            },
            "overall_vector_similarity": {
                access: inst_cmp.get("per_access", {}).get(access, {}).get("overall_vector", {})
                for access in inst_cmp.get("accesses", [])
            },
        },
    }
    out_path.write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")


@dataclass
class RunCase:
    bench: str
    warmup: float
    status: str
    out_dir: str
    error: str | None = None
    metrics: dict | None = None


@dataclass
class CaseLayout:
    bench: str
    warmup: float
    out_dir: Path
    inputs_dir: Path
    intermediate_dir: Path
    mem_dir: Path
    report_dir: Path
    prefix: str
    sde_trace: Path
    sde_mem: Path
    sde_insn: Path
    perf_data: Path
    perf_script: Path
    perf_script_stderr: Path
    perf_record_stderr: Path
    perf_insn: Path
    perf_rec_mem: Path
    sde_data_analysis_json: Path
    perf_data_analysis_json: Path
    data_sim_json: Path
    sde_inst_analysis_json: Path
    perf_inst_analysis_json: Path
    inst_sim_json: Path
    feature_bundle_json: Path
    sde_log: Path
    perf_portrait_txt: Path
    perf_portrait_stderr: Path
    insn_portrait_json: Path
    trace_profile_merged_json: Path


@dataclass
class PreparedCase:
    seq: int
    layout: CaseLayout


def make_case_layout(*, bench: str, warmup_seconds: float, output_base: Path) -> CaseLayout:
    tag = warmup_tag(warmup_seconds)
    out_dir = output_base / bench / tag
    inputs_dir = out_dir / "inputs"
    intermediate_dir = out_dir / "intermediate"
    mem_dir = out_dir / "mem"
    report_dir = out_dir / "report"
    for d in (inputs_dir, intermediate_dir, mem_dir, report_dir):
        d.mkdir(parents=True, exist_ok=True)
    prefix = f"{bench.replace('.', '_')}_{tag}"
    return CaseLayout(
        bench=bench,
        warmup=warmup_seconds,
        out_dir=out_dir,
        inputs_dir=inputs_dir,
        intermediate_dir=intermediate_dir,
        mem_dir=mem_dir,
        report_dir=report_dir,
        prefix=prefix,
        sde_trace=inputs_dir / f"{prefix}.sde.debugtrace.txt",
        sde_mem=mem_dir / f"{prefix}.sde.mem.real.jsonl",
        sde_insn=intermediate_dir / f"{prefix}.sde.insn.trace.txt",
        perf_data=intermediate_dir / f"{prefix}.perf.data",
        perf_script=intermediate_dir / f"{prefix}.perf.script.txt",
        perf_script_stderr=report_dir / f"{prefix}.perf.script.stderr.txt",
        perf_record_stderr=report_dir / f"{prefix}.perf.record.stderr.txt",
        perf_insn=intermediate_dir / f"{prefix}.perf.insn.trace.txt",
        perf_rec_mem=mem_dir / f"{prefix}.perf.mem.recovered.jsonl",
        sde_data_analysis_json=report_dir / f"{prefix}.sde.data.analysis.json",
        perf_data_analysis_json=report_dir / f"{prefix}.perf.recovered.data.analysis.json",
        data_sim_json=report_dir / f"{prefix}.sde_vs_perf_recovered.data.locality.compare.json",
        sde_inst_analysis_json=report_dir / f"{prefix}.sde.inst.analysis.json",
        perf_inst_analysis_json=report_dir / f"{prefix}.perf.inst.analysis.json",
        inst_sim_json=report_dir / f"{prefix}.sde_vs_perf.inst.locality.compare.json",
        feature_bundle_json=report_dir / f"{prefix}.features.bundle.json",
        sde_log=report_dir / f"{prefix}.sde.attach.log",
        perf_portrait_txt=intermediate_dir / f"{prefix}.perf.insn.portrait.txt",
        perf_portrait_stderr=report_dir / f"{prefix}.perf.portrait.script.stderr.txt",
        insn_portrait_json=report_dir / f"{prefix}.insn.portrait.json",
        trace_profile_merged_json=report_dir / f"{prefix}.trace_profile.merged.json",
    )


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


def cosine(xs: list[float], ys: list[float]) -> float:
    if len(xs) != len(ys) or not xs:
        return 0.0
    dot = sum(a * b for a, b in zip(xs, ys))
    nx = math.sqrt(sum(a * a for a in xs))
    ny = math.sqrt(sum(b * b for b in ys))
    if nx == 0.0 or ny == 0.0:
        return 0.0
    return dot / (nx * ny)


def pearson(xs: list[float], ys: list[float]) -> float:
    if len(xs) != len(ys) or not xs:
        return 0.0
    mx = sum(xs) / len(xs)
    my = sum(ys) / len(ys)
    num = sum((a - mx) * (b - my) for a, b in zip(xs, ys))
    denx = math.sqrt(sum((a - mx) ** 2 for a in xs))
    deny = math.sqrt(sum((b - my) ** 2 for b in ys))
    if denx == 0.0 or deny == 0.0:
        return 0.0
    return num / (denx * deny)


def flatten_feature_vector(feature_obj: dict) -> dict[str, float]:
    out: dict[str, float] = {}
    rd_bins = feature_obj.get("rd_bins", [])
    rd_prob = feature_obj.get("rd_prob", [])
    if isinstance(rd_bins, list) and isinstance(rd_prob, list):
        for b, p in zip(rd_bins, rd_prob):
            out[f"rd_prob::{b}"] = float(p)
    st_bins = feature_obj.get("stride_bins", [])
    st_prob = feature_obj.get("stride_prob", [])
    if isinstance(st_bins, list) and isinstance(st_prob, list):
        for b, p in zip(st_bins, st_prob):
            out[f"stride_prob::{b}"] = float(p)
    for k, v in feature_obj.items():
        if k in ("rd_bins", "rd_prob", "stride_bins", "stride_prob"):
            continue
        if isinstance(v, (int, float)):
            out[k] = float(v)
    return out


def compare_named_vectors(ref_vec: dict[str, float], test_vec: dict[str, float], top_k: int = 3) -> dict:
    keys = sorted(set(ref_vec) | set(test_vec))
    rv = [float(ref_vec.get(k, 0.0)) for k in keys]
    tv = [float(test_vec.get(k, 0.0)) for k in keys]
    diffs = []
    for k, a, b in zip(keys, rv, tv):
        diffs.append({"dim": k, "abs_diff": abs(a - b)})
    diffs.sort(key=lambda x: x["abs_diff"], reverse=True)
    r = pearson(rv, tv)
    return {
        "dims": len(keys),
        "cosine": cosine(rv, tv),
        "r2": max(0.0, r * r),
        "l1_mean_abs": sum(abs(a - b) for a, b in zip(rv, tv)) / max(1, len(keys)),
        "top_dims": [x["dim"] for x in diffs[: max(1, top_k)]],
    }


def warmup_cross_similarity(cases: list[RunCase], out_base: Path) -> tuple[Path, Path] | None:
    ok_cases = [c for c in cases if c.status == "ok" and c.out_dir]
    by_bench: dict[str, list[RunCase]] = {}
    for c in ok_cases:
        by_bench.setdefault(c.bench, []).append(c)

    rows: list[dict] = []
    for bench, bench_cases in by_bench.items():
        bench_cases.sort(key=lambda x: x.warmup)
        if len(bench_cases) < 2:
            continue
        bundle_cache: dict[str, dict] = {}
        for c in bench_cases:
            report_dir = Path(c.out_dir) / "report"
            bundles = list(report_dir.glob("*.features.bundle.json"))
            if not bundles:
                continue
            try:
                bundle_cache[c.out_dir] = json.loads(bundles[0].read_text(encoding="utf-8"))
            except Exception:
                continue
        for a, b in combinations(bench_cases, 2):
            ba = bundle_cache.get(a.out_dir)
            bb = bundle_cache.get(b.out_dir)
            if not ba or not bb:
                continue
            spaces = [
                ("data_ref", ba.get("data", {}).get("ref_features", {}).get("all", {}), bb.get("data", {}).get("ref_features", {}).get("all", {})),
                ("data_test", ba.get("data", {}).get("test_features", {}).get("all", {}), bb.get("data", {}).get("test_features", {}).get("all", {})),
                ("inst_ref", ba.get("inst", {}).get("ref_features", {}).get("all", {}), bb.get("inst", {}).get("ref_features", {}).get("all", {})),
                ("inst_test", ba.get("inst", {}).get("test_features", {}).get("all", {}), bb.get("inst", {}).get("test_features", {}).get("all", {})),
            ]
            for space, fa, fb in spaces:
                if not isinstance(fa, dict) or not isinstance(fb, dict) or not fa or not fb:
                    continue
                cmp = compare_named_vectors(flatten_feature_vector(fa), flatten_feature_vector(fb), top_k=3)
                rows.append(
                    {
                        "bench": bench,
                        "warmup_a": a.warmup,
                        "warmup_b": b.warmup,
                        "space": space,
                        "cosine": cmp["cosine"],
                        "r2": cmp["r2"],
                        "l1_mean_abs": cmp["l1_mean_abs"],
                        "dims": cmp["dims"],
                        "top3_dims": "|".join(cmp["top_dims"]),
                    }
                )

    if not rows:
        return None

    out_json = out_base / "warmup_pairwise_similarity.json"
    out_csv = out_base / "warmup_pairwise_similarity.csv"
    out_json.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    keys = ["bench", "warmup_a", "warmup_b", "space", "cosine", "r2", "l1_mean_abs", "dims", "top3_dims"]
    lines = [",".join(keys)]
    for r in rows:
        lines.append(",".join(str(r[k]).replace(",", ";") for k in keys))
    out_csv.write_text("\n".join(lines) + "\n", encoding="utf-8")

    for bench in sorted({r["bench"] for r in rows}):
        b = [r for r in rows if r["bench"] == bench and r["space"] == "data_ref"]
        if not b:
            continue
        mean_cos = sum(float(x["cosine"]) for x in b) / len(b)
        print(f"[warmup] bench={bench} data_ref_pairs={len(b)} mean_cos={mean_cos:.4f}")
    return out_json, out_csv


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
    layout = make_case_layout(bench=bench, warmup_seconds=warmup_seconds, output_base=args.output_base)
    prepared = run_trace_phase(
        seq=0,
        layout=layout,
        script_dir=script_dir,
        spec_root=spec_root,
        sde_path=sde_path,
        run_dir=run_dir,
        args=args,
    )
    return run_post_phase(script_dir=script_dir, prepared=prepared, args=args)


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
        with (layout.report_dir / f"{layout.prefix}.spec.sde.stdout.txt").open("w", encoding="utf-8") as out_fp, (
            layout.report_dir / f"{layout.prefix}.spec.sde.stderr.txt"
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
    env_prefix = f"source {shlex.quote(str(shrc))} >/dev/null 2>&1 || true; " if shrc.exists() else ""
    with (layout.report_dir / f"{layout.prefix}.spec.perf.stdout.txt").open("w", encoding="utf-8") as out_fp, (
        layout.report_dir / f"{layout.prefix}.spec.perf.stderr.txt"
    ).open("w", encoding="utf-8") as err_fp:
        perf_launcher = subprocess.Popen(
            ["bash", "-lc", f"{env_prefix}exec {cmd_line}"],
            cwd=run_dir,
            stdout=out_fp,
            stderr=err_fp,
            text=True,
        )
    perf_launcher_pid = int(perf_launcher.pid)
    time.sleep(1.0)
    if not pid_alive(perf_launcher_pid):
        raise RuntimeError("perf phase launcher failed to start")
    probe = pick_spec_benchmark_pid(perf_launcher_pid, run_dir, exe_basename, resolve_timeout=8.0)
    if not pid_alive(probe):
        cleanup_pid(perf_launcher_pid)
        raise RuntimeError("benchmark exited before perf warmup")
    if layout.warmup > 0:
        time.sleep(layout.warmup)
    perf_target_pid = pick_spec_benchmark_pid(
        perf_launcher_pid, run_dir, exe_basename, resolve_timeout=8.0
    )
    attach = getattr(args, "spec_perf_attach", "busiest-tid")
    perf_id, perf_flag = pick_spec_perf_record_target(perf_target_pid, attach)
    log_spec_perf_attach(
        bench=layout.bench,
        phase="perf_once",
        launcher_pid=perf_launcher_pid,
        resolved_pid=perf_target_pid,
        perf_flag=perf_flag,
        perf_id=perf_id,
        run_dir=run_dir,
    )
    if not pid_alive(perf_target_pid):
        cleanup_pid(perf_launcher_pid)
        raise RuntimeError("benchmark exited before perf attach")

    run_step(
        [
            "perf",
            "record",
            "-q",
            "-m",
            str(args.perf_mmap_pages),
            "-e",
            args.perf_event,
            "-o",
            str(layout.perf_data),
            perf_flag,
            str(perf_id),
            "--",
            "sleep",
            str(args.perf_record_seconds),
        ],
        verbose=args.verbose,
        stderr_path=layout.perf_record_stderr,
    )
    cleanup_pid(perf_target_pid)
    if perf_target_pid != perf_launcher_pid:
        cleanup_pid(perf_launcher_pid)
    try:
        perf_launcher.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        pass
    if not layout.perf_data.exists() or layout.perf_data.stat().st_size == 0:
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
    exe_basename = Path(shlex.split(cmd_line)[0]).name

    # Put the benchmark stdout/stderr into a stable location (not per-sample).
    stream_dir = args.output_base / bench / "_stream"
    stream_report = stream_dir / "report"
    stream_report.mkdir(parents=True, exist_ok=True)
    out_path = stream_report / f"{bench.replace('.', '_')}.spec.perf.stdout.txt"
    err_path = stream_report / f"{bench.replace('.', '_')}.spec.perf.stderr.txt"

    shrc = spec_root / "shrc"
    env_prefix = f"source {shlex.quote(str(shrc))} >/dev/null 2>&1 || true; " if shrc.exists() else ""
    with out_path.open("w", encoding="utf-8") as out_fp, err_path.open("w", encoding="utf-8") as err_fp:
        launcher = subprocess.Popen(
            ["bash", "-lc", f"{env_prefix}exec {cmd_line}"],
            cwd=run_dir,
            stdout=out_fp,
            stderr=err_fp,
            text=True,
        )

    launcher_pid = int(launcher.pid)
    time.sleep(1.0)
    if not pid_alive(launcher_pid):
        raise RuntimeError("perf stream launcher failed to start")
    target_pid = pick_spec_benchmark_pid(launcher_pid, run_dir, exe_basename, resolve_timeout=8.0)
    attach = getattr(args, "spec_perf_attach", "busiest-tid")
    if not pid_alive(target_pid):
        cleanup_pid(launcher_pid)
        raise RuntimeError("benchmark exited before perf stream sampling")

    prepared: list[PreparedCase] = []
    start_t = time.time()
    next_at = float(first_after)
    sample_idx = 0
    try:
        while True:
            if max_samples > 0 and sample_idx >= max_samples:
                break
            if not pid_alive(target_pid):
                break

            # Wait until the next sampling timestamp.
            deadline = start_t + next_at
            while time.time() < deadline:
                if not pid_alive(target_pid):
                    break
                time.sleep(0.05)
            if not pid_alive(target_pid):
                break

            # Re-resolve before each sample: same criteria as `ps` in run_dir (scan wins).
            target_pid = pick_spec_benchmark_pid(
                launcher_pid, run_dir, exe_basename, resolve_timeout=1.5
            )
            if not pid_alive(target_pid):
                break
            perf_id, perf_flag = pick_spec_perf_record_target(target_pid, attach)
            log_spec_perf_attach(
                bench=bench,
                phase="perf_stream",
                launcher_pid=launcher_pid,
                resolved_pid=target_pid,
                perf_flag=perf_flag,
                perf_id=perf_id,
                run_dir=run_dir,
                sample_label=f"sample_index={sample_idx} t={next_at:g}s",
            )

            # Materialize one sample as its own case (warmup_seconds = time since start).
            layout = make_case_layout(bench=bench, warmup_seconds=next_at, output_base=args.output_base)
            try:
                run_step(
                    [
                        "perf",
                        "record",
                        "-q",
                        "-m",
                        str(args.perf_mmap_pages),
                        "-e",
                        args.perf_event,
                        "-o",
                        str(layout.perf_data),
                        perf_flag,
                        str(perf_id),
                        "--",
                        "sleep",
                        str(args.perf_record_seconds),
                    ],
                    verbose=args.verbose,
                    stderr_path=layout.perf_record_stderr,
                )
            except Exception:
                # Common race: benchmark exits between the alive check and perf attach.
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
                if esrch or not pid_alive(target_pid):
                    break
                raise
            if not layout.perf_data.exists() or layout.perf_data.stat().st_size == 0:
                if not pid_alive(target_pid):
                    break
                raise RuntimeError("empty perf.data in perf stream sampling")
            prepared.append(PreparedCase(seq=seq_base + sample_idx, layout=layout))
            sample_idx += 1
            next_at += interval
    finally:
        # Ensure benchmark is terminated if still alive.
        cleanup_pid(target_pid)
        if target_pid != launcher_pid:
            cleanup_pid(launcher_pid)
        try:
            launcher.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            pass

    return prepared


def run_post_phase(*, script_dir: Path, prepared: PreparedCase, args: argparse.Namespace) -> RunCase:
    layout = prepared.layout
    skip_existing = bool(getattr(args, "skip_existing", True))

    def _nonempty(p: Path) -> bool:
        try:
            return p.is_file() and p.stat().st_size > 0
        except OSError:
            return False

    # Fast path: reuse existing perf post-process artifacts if present.
    if skip_existing and _nonempty(layout.perf_data_analysis_json) and _nonempty(layout.perf_inst_analysis_json):
        metrics: dict = {"mode": "reuse_existing"}
        metrics["perf_inst_analysis_json"] = str(layout.perf_inst_analysis_json)
        metrics["perf_data_analysis_json"] = str(layout.perf_data_analysis_json)
        # Reuse portrait metrics if requested and available.
        if getattr(args, "insn_portrait", False) and _nonempty(layout.insn_portrait_json):
            try:
                rep = json.loads(layout.insn_portrait_json.read_text(encoding="utf-8"))
                metrics.update(insn_portrait.flatten_portrait_metrics(rep))
                metrics["perf_insn_portrait_json"] = str(layout.insn_portrait_json)
                metrics["trace_profile_merged_json"] = str(layout.trace_profile_merged_json)
            except Exception:
                pass
        return RunCase(
            bench=layout.bench,
            warmup=layout.warmup,
            status="ok",
            out_dir=str(layout.out_dir),
            metrics=metrics,
        )

    if args.enable_sde:
        sde_analyzer = script_dir / "analyze_sde_trace_uc"
        if not sde_analyzer.exists():
            raise RuntimeError(f"missing {sde_analyzer}; run build_recover_mem_addrs_uc.sh first")
        need_sde_analyze = not (
            layout.sde_mem.exists()
            and layout.sde_insn.exists()
            and layout.sde_inst_analysis_json.exists()
            and layout.sde_data_analysis_json.exists()
        )
        if need_sde_analyze:
            run_step(
                [
                    str(sde_analyzer),
                    "-i",
                    str(layout.sde_trace),
                    "--mem-out",
                    str(layout.sde_mem),
                    "--insn-out",
                    str(layout.sde_insn),
                    "--inst-analysis-out",
                    str(layout.sde_inst_analysis_json),
                    "--data-analysis-out",
                    str(layout.sde_data_analysis_json),
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
    perf_aux_lost, perf_trace_errors, perf_insn_lines, _, _, _, _, portrait_txt = perf_postprocess_one(
        script_dir=script_dir,
        perf_tool="perf",
        perf_data=layout.perf_data,
        prefix=layout.prefix,
        intermediate_dir=layout.intermediate_dir,
        mem_dir=layout.mem_dir,
        report_dir=layout.report_dir,
        perf_max_insn_lines=args.perf_max_insn_lines,
        line_size=args.line_size,
        analysis_rd_hist_cap_lines=args.analysis_rd_hist_cap_lines,
        analysis_stride_bin_cap_lines=args.analysis_stride_bin_cap_lines,
        recover_init_regs=args.recover_init_regs,
        recover_reg_staging=args.recover_reg_staging,
        recover_mvs=args.recover_mvs,
        recover_fill_seed=args.recover_fill_seed,
        recover_page_init=args.recover_page_init,
        recover_page_init_seed=args.recover_page_init_seed,
        recover_progress_every=args.recover_progress_every,
        recover_salvage_invalid_mem=args.recover_salvage_invalid_mem,
        recover_salvage_reads=args.recover_salvage_reads,
        insn_portrait=getattr(args, "insn_portrait", True),
        verbose=args.verbose,
    )

    metrics = {}
    if args.enable_sde:
        if not layout.sde_data_analysis_json.exists() or not layout.sde_inst_analysis_json.exists():
            raise RuntimeError("analyze_sde_trace_uc did not produce SDE analysis JSON outputs")
        run_step(
            [
                sys.executable,
                str(script_dir / "compare_mem_trace_metrics.py"),
                "--ref-analysis",
                str(layout.sde_data_analysis_json),
                "--test-analysis",
                str(layout.perf_data_analysis_json),
                "--top-k",
                str(max(1, args.stride_top_k)),
                "--max-error-bins",
                "20",
                "--sdp-max-lines",
                "262144",
                "--json-out",
                str(layout.data_sim_json),
            ],
            verbose=args.verbose,
        )
        run_step(
            [
                sys.executable,
                str(script_dir / "compare_mem_trace_metrics.py"),
                "--ref-analysis",
                str(layout.sde_inst_analysis_json),
                "--test-analysis",
                str(layout.perf_inst_analysis_json),
                "--top-k",
                str(max(1, args.stride_top_k)),
                "--max-error-bins",
                "20",
                "--sdp-max-lines",
                "262144",
                "--json-out",
                str(layout.inst_sim_json),
            ],
            verbose=args.verbose,
        )
        metrics.update(load_compare_metrics(layout.data_sim_json, metric_prefix="data_"))
        metrics.update(load_compare_metrics(layout.inst_sim_json, metric_prefix="inst_"))
        if args.write_feature_bundle:
            maybe_write_feature_bundle(
                out_path=layout.feature_bundle_json,
                sde_data_analysis=layout.sde_data_analysis_json,
                sde_inst_analysis=layout.sde_inst_analysis_json,
                perf_data_analysis=layout.perf_data_analysis_json,
                perf_inst_analysis=layout.perf_inst_analysis_json,
                data_compare=layout.data_sim_json,
                inst_compare=layout.inst_sim_json,
            )
    else:
        metrics["mode"] = "perf_only"
        metrics["perf_inst_analysis_json"] = str(layout.perf_inst_analysis_json)
        metrics["perf_data_analysis_json"] = str(layout.perf_data_analysis_json)
    metrics["perf_insn_lines"] = perf_insn_lines
    metrics["perf_aux_lost"] = perf_aux_lost
    metrics["perf_trace_errors"] = perf_trace_errors

    if getattr(args, "insn_portrait", False) and portrait_txt is not None and portrait_txt.is_file() and portrait_txt.stat().st_size > 0:
        max_p = args.perf_max_insn_lines if args.perf_max_insn_lines > 0 else 0
        rep = insn_portrait.analyze_file(portrait_txt, max_insns=max_p)
        rep["input_path"] = str(layout.perf_portrait_txt.resolve())
        layout.insn_portrait_json.parent.mkdir(parents=True, exist_ok=True)
        layout.insn_portrait_json.write_text(json.dumps(rep, indent=2, ensure_ascii=False), encoding="utf-8")
        metrics.update(insn_portrait.flatten_portrait_metrics(rep))
        metrics["perf_insn_portrait_json"] = str(layout.insn_portrait_json)
        # Free space: portrait trace text can be large; JSON is the stable artifact.
        try:
            portrait_txt.unlink()
        except FileNotFoundError:
            pass
        merged = {
            "schema": "trace-profile-v1",
            "bench": layout.bench,
            "warmup_seconds": layout.warmup,
            "paths": {
                "perf_data": str(layout.perf_data),
                "perf_recovered_mem_jsonl": str(layout.perf_rec_mem),
                "perf_data_analysis_json": str(layout.perf_data_analysis_json),
                "perf_inst_analysis_json": str(layout.perf_inst_analysis_json),
                "insn_portrait_json": str(layout.insn_portrait_json),
            },
            "insn_portrait": rep,
        }
        if args.enable_sde:
            merged["paths"].update(
                {
                    "sde_data_analysis_json": str(layout.sde_data_analysis_json),
                    "sde_inst_analysis_json": str(layout.sde_inst_analysis_json),
                    "data_compare_json": str(layout.data_sim_json),
                    "inst_compare_json": str(layout.inst_sim_json),
                }
            )
        layout.trace_profile_merged_json.write_text(
            json.dumps(merged, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        metrics["trace_profile_merged_json"] = str(layout.trace_profile_merged_json)

    return RunCase(bench=layout.bench, warmup=layout.warmup, status="ok", out_dir=str(layout.out_dir), metrics=metrics)


def _validate_spec_batch_common_args(args: argparse.Namespace) -> None:
    if args.total_insns <= 0:
        raise SystemExit("--total-insns must be > 0")
    if args.perf_record_seconds <= 0:
        raise SystemExit("--perf-record-seconds must be > 0")
    if args.perf_mmap_pages <= 0:
        raise SystemExit("--perf-mmap-pages must be > 0")
    if args.recover_page_init_seed < 0:
        raise SystemExit("--recover-page-init-seed must be >= 0")
    if args.recover_progress_every < 0:
        raise SystemExit("--recover-progress-every must be >= 0")
    if args.post_workers <= 0:
        raise SystemExit("--post-workers must be > 0")

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
    warmups = [] if use_stream else parse_warmups(args.warmup_sweep)
    all_benches = sorted(p.name for p in spec_cpu.iterdir() if p.is_dir() and p.name.startswith("5") and p.name.endswith("_r"))
    if args.benchmarks.strip():
        benches = [x.strip() for x in args.benchmarks.split(",") if x.strip()]
    else:
        benches = [b for b in DEFAULT_REPRESENTATIVE_BENCHES if b in all_benches]
        if not benches:
            benches = all_benches
    if args.bench_limit > 0:
        benches = benches[: args.bench_limit]
    if not benches:
        raise SystemExit("no benchmarks selected")

    root = script_dir if script_dir is not None else Path(__file__).resolve().parent
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
    for bench in benches:
        run_dir = bench_run_dirs.get(bench)
        if run_dir is None:
            continue
        if use_stream:
            trace_idx += 1
            print(f"[trace {trace_idx}/{total_cases}] bench={bench} mode=stream")
            try:
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
                    if bool(getattr(args, "skip_existing", True)) and layout.perf_data_analysis_json.is_file() and layout.perf_inst_analysis_json.is_file():
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
        exporter = (Path(__file__).resolve().parent / "export_perf_full_features.py").resolve()
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
    # Perf post-process args (shared with cloud pipeline)
    add_perf_postprocess_args(ap)
    ap.add_argument("--stride-top-k", type=int, default=20)
    # Too-short windows often yield no decoded insn trace from Intel PT.
    ap.add_argument("--perf-record-seconds", type=float, default=0.1)
    # Intel PT AUX buffers are mlock()'d; keep default conservative to avoid
    # "Permission error mapping pages" on systems with low memlock limits.
    ap.add_argument("--perf-mmap-pages", type=int, default=64, help="perf record -m pages (PT buffer size)")
    ap.add_argument("--perf-event", type=str, default="intel_pt/cyc,noretcomp=0/u")
    ap.add_argument(
        "--spec-perf-attach",
        choices=["process", "busiest-tid"],
        default="busiest-tid",
        help="perf record target: whole process (-p PID) or hottest thread (-t TID), like cloud collector",
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
        help="optional comma list like 505.mcf_r,510.parest_r; empty means representative subset",
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
