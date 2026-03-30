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


def parse_perf_script_health(stderr_path: Path) -> tuple[int, int]:
    aux_lost = 0
    trace_errors = 0
    if not stderr_path.exists():
        return aux_lost, trace_errors
    for raw in stderr_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip().lower()
        if "aux data lost" in line:
            aux_lost += 1
        if "instruction trace errors" in line or "instruction trace error" in line:
            trace_errors += 1
    return aux_lost, trace_errors


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


@dataclass
class PreparedCase:
    seq: int
    layout: CaseLayout
    perf_insn_lines: int
    perf_aux_lost: int
    perf_trace_errors: int


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
            f"out={case.out_dir}",
        )
        return
    print(
        "  ok:",
        "mode=perf-only",
        f"perf_insn_lines={case.metrics.get('perf_insn_lines', 0)}",
        f"pt_aux_lost={case.metrics.get('perf_aux_lost', 0)}",
        f"pt_trace_err={case.metrics.get('perf_trace_errors', 0)}",
        f"inst_analysis={case.metrics.get('perf_inst_analysis_json', '')}",
        f"data_analysis={case.metrics.get('perf_data_analysis_json', '')}",
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
        target_pid = resolve_target_pid(launcher_pid, exe_basename, timeout_s=8.0)
        target_exe = read_proc_exe(target_pid)
        if not target_exe or Path(target_exe).name != exe_basename:
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
    with (layout.report_dir / f"{layout.prefix}.spec.perf.stdout.txt").open("w", encoding="utf-8") as out_fp, (
        layout.report_dir / f"{layout.prefix}.spec.perf.stderr.txt"
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
    if layout.warmup > 0:
        time.sleep(layout.warmup)
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
            "-p",
            str(perf_target_pid),
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

    run_step(
        ["perf", "script", "--insn-trace", "-F", "tid,time,ip,insn", "-i", str(layout.perf_data)],
        verbose=args.verbose,
        stdout_path=layout.perf_script,
        stderr_path=layout.perf_script_stderr,
    )
    perf_aux_lost, perf_trace_errors = parse_perf_script_health(layout.perf_script_stderr)
    perf_insn_lines = extract_perf_insn_trace(layout.perf_script, layout.perf_insn, args.perf_max_insn_lines)
    try:
        layout.perf_script.unlink()
    except FileNotFoundError:
        pass
    if perf_insn_lines < 1:
        raise RuntimeError("no perf insn lines extracted")
    return PreparedCase(
        seq=seq,
        layout=layout,
        perf_insn_lines=perf_insn_lines,
        perf_aux_lost=perf_aux_lost,
        perf_trace_errors=perf_trace_errors,
    )


def run_post_phase(*, script_dir: Path, prepared: PreparedCase, args: argparse.Namespace) -> RunCase:
    layout = prepared.layout
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
    recover_cmd = [
        str(script_dir / "recover_mem_addrs_uc"),
        "-i",
        str(layout.perf_insn),
        "-o",
        str(layout.perf_rec_mem),
        "--init-regs",
        args.recover_init_regs,
        "--reg-staging",
        args.recover_reg_staging,
        "--mvs",
        args.recover_mvs,
        "--seed",
        str(args.recover_fill_seed),
        "--page-init",
        args.recover_page_init,
        "--page-init-seed",
        str(args.recover_page_init_seed),
        "--progress-every",
        str(args.recover_progress_every),
        "--inst-analysis-out",
        str(layout.perf_inst_analysis_json),
        "--data-analysis-out",
        str(layout.perf_data_analysis_json),
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

    if not layout.perf_data_analysis_json.exists() or not layout.perf_inst_analysis_json.exists():
        raise RuntimeError("recover_mem_addrs_uc did not produce perf analysis JSON outputs")

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
    metrics["perf_insn_lines"] = prepared.perf_insn_lines
    metrics["perf_aux_lost"] = prepared.perf_aux_lost
    metrics["perf_trace_errors"] = prepared.perf_trace_errors
    return RunCase(bench=layout.bench, warmup=layout.warmup, status="ok", out_dir=str(layout.out_dir), metrics=metrics)


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
        help="enable SDE trace and SDE-vs-perf comparison (set --no-enable-sde for perf-only flow)",
    )
    ap.add_argument("--warmup-sweep", type=str, default="60,120", help="comma list, e.g. 60,120")
    ap.add_argument("--total-insns", type=int, default=2_000_000)
    ap.add_argument("--line-size", type=int, default=64)
    ap.add_argument("--stride-top-k", type=int, default=20)
    ap.add_argument("--perf-record-seconds", type=float, default=0.001)
    ap.add_argument("--perf-mmap-pages", type=int, default=1024, help="perf record -m pages (PT buffer size)")
    ap.add_argument("--perf-event", type=str, default="intel_pt/cyc,noretcomp=0/u")
    ap.add_argument("--perf-max-insn-lines", type=int, default=500_000)
    ap.add_argument("--trace-post-sde-sleep", type=float, default=8.0)
    ap.add_argument("--trace-settle-timeout", type=float, default=300.0)
    ap.add_argument("--trace-settle-interval", type=float, default=1.0)
    ap.add_argument("--trace-stable-rounds", type=int, default=4)
    ap.add_argument("--recover-init-regs", choices=["zero", "random"], default="random")
    ap.add_argument(
        "--recover-reg-staging",
        choices=["legacy", "dwt"],
        default="dwt",
        help="register staging strategy passed to recover_mem_addrs_uc",
    )
    ap.add_argument(
        "--recover-mvs",
        choices=["on", "off"],
        default="on",
        help="whether to enable MVS in recover_mem_addrs_uc",
    )
    ap.add_argument("--recover-fill-seed", type=int, default=1)
    ap.add_argument(
        "--recover-page-init",
        choices=["zero", "random", "stable"],
        default="zero",
        help="page initialization policy for recover_mem_addrs_uc (default: zero)",
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
        "--write-feature-bundle",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="write per-case combined feature bundle JSON (default: true)",
    )
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
    args = ap.parse_args()

    if args.total_insns <= 0:
        raise SystemExit("--total-insns must be > 0")
    if args.line_size <= 0 or (args.line_size & (args.line_size - 1)) != 0:
        raise SystemExit("--line-size must be positive power-of-two")
    if args.perf_record_seconds <= 0:
        raise SystemExit("--perf-record-seconds must be > 0")
    if args.perf_mmap_pages <= 0:
        raise SystemExit("--perf-mmap-pages must be > 0")
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
    if args.post_workers <= 0:
        raise SystemExit("--post-workers must be > 0")

    spec_cpu = args.spec_root / "benchspec" / "CPU"
    if not spec_cpu.is_dir():
        raise SystemExit(f"not found: {spec_cpu}")
    if args.enable_sde and not args.sde.exists():
        raise SystemExit(f"sde not found: {args.sde}")

    warmups = parse_warmups(args.warmup_sweep)
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

    script_dir = Path(__file__).resolve().parent
    summary: list[RunCase] = []
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

    total_cases = sum(len(warmups) for b in benches if b in bench_run_dirs)
    print(f"[plan] runnable_cases={total_cases}")

    prepared_cases: list[PreparedCase] = []
    seq = 0
    trace_idx = 0
    stop_now = False
    for bench in benches:
        run_dir = bench_run_dirs.get(bench)
        if run_dir is None:
            continue
        for w in warmups:
            trace_idx += 1
            print(f"[trace {trace_idx}/{total_cases}] bench={bench} warmup={w:g}s")
            try:
                layout = make_case_layout(bench=bench, warmup_seconds=w, output_base=args.output_base)
                prepared = run_trace_phase(
                    seq=seq,
                    layout=layout,
                    script_dir=script_dir,
                    spec_root=args.spec_root,
                    sde_path=args.sde,
                    run_dir=run_dir,
                    args=args,
                )
                prepared_cases.append(prepared)
                seq += 1
                print(f"  traced: perf_insn_lines={prepared.perf_insn_lines} out={layout.out_dir}")
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
                    case = run_post_phase(script_dir=script_dir, prepared=prepared, args=args)
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
                    ex.submit(run_post_phase, script_dir=script_dir, prepared=prepared, args=args): prepared
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
