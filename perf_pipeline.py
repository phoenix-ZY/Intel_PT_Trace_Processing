#!/usr/bin/env python3
"""
Reusable perf-only post-processing pipeline utilities.

Goal: keep the "perf.data -> perf script -> insn trace -> recover_mem_addrs_uc -> analysis JSON"
logic in one place so SPEC and cloud collectors can share it.
"""

from __future__ import annotations

import json
import math
import shlex
import subprocess
from pathlib import Path
from typing import Any
import argparse
import signal


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


def add_perf_postprocess_args(parser: argparse.ArgumentParser) -> None:
    """
    Add arguments shared by all perf-only pipelines:
      - perf decode and extraction limits
      - recover_mem_addrs_uc knobs
      - analysis knobs
      - optional instruction portrait
    """
    parser.add_argument("--line-size", type=int, default=64, help="Cache line size (power of two)")
    parser.add_argument(
        "--perf-max-insn-lines",
        type=int,
        default=5_000_000,
        help="Max insn lines to keep from perf script (0 = unlimited)",
    )
    parser.add_argument(
        "--insn-portrait",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Second perf script --xed + instruction portrait / merged profile JSON (needs XED for perf)",
    )
    parser.add_argument("--recover-init-regs", choices=["zero", "random"], default="random")
    parser.add_argument("--recover-reg-staging", choices=["legacy", "dwt"], default="dwt")
    parser.add_argument("--recover-mvs", choices=["on", "off"], default="on")
    parser.add_argument("--recover-fill-seed", type=int, default=1)
    parser.add_argument("--recover-page-init", choices=["zero", "random", "stable"], default="zero")
    parser.add_argument("--recover-page-init-seed", type=int, default=1)
    parser.add_argument("--recover-progress-every", type=int, default=0)
    parser.add_argument("--recover-salvage-invalid-mem", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--recover-salvage-reads", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--analysis-rd-hist-cap-lines", type=int, default=262144)
    parser.add_argument("--analysis-stride-bin-cap-lines", type=int, default=262144)


def validate_perf_postprocess_args(args: argparse.Namespace) -> None:
    if args.line_size <= 0 or (args.line_size & (args.line_size - 1)) != 0:
        raise SystemExit("❌ --line-size must be a positive power of two")
    if args.perf_max_insn_lines < 0:
        raise SystemExit("❌ --perf-max-insn-lines must be >= 0")
    if args.analysis_rd_hist_cap_lines < 0 or args.analysis_stride_bin_cap_lines < 0:
        raise SystemExit("❌ analysis cap lines must be >= 0")
    if args.recover_progress_every < 0:
        raise SystemExit("❌ --recover-progress-every must be >= 0")


def perf_postprocess_one(
    *,
    script_dir: Path,
    perf_tool: str | Path,
    perf_data: Path,
    prefix: str,
    intermediate_dir: Path,
    mem_dir: Path,
    report_dir: Path,
    perf_max_insn_lines: int,
    line_size: int,
    analysis_rd_hist_cap_lines: int,
    analysis_stride_bin_cap_lines: int,
    recover_init_regs: str,
    recover_reg_staging: str,
    recover_mvs: str,
    recover_fill_seed: int,
    recover_page_init: str,
    recover_page_init_seed: int,
    recover_progress_every: int,
    recover_salvage_invalid_mem: bool,
    recover_salvage_reads: bool,
    insn_portrait: bool,
    verbose: bool,
) -> tuple[int, int, int, Path, Path, Path, Path, Path | None]:
    """
    Common perf-only post-processing:
      perf script --insn-trace -> extract perf.insn.trace -> recover_mem_addrs_uc -> analysis JSONs

    Returns:
      (aux_lost, trace_errors, insn_lines,
       perf_insn_trace_path, perf_recovered_mem_jsonl_path,
       perf_data_analysis_json_path, perf_inst_analysis_json_path,
       perf_portrait_txt_path_or_none)
    """
    recover_bin = script_dir / "recover_mem_addrs_uc"
    if not recover_bin.exists():
        raise RuntimeError(f"missing {recover_bin}; run build_recover_mem_addrs_uc.sh first")

    intermediate_dir.mkdir(parents=True, exist_ok=True)
    mem_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    def _nonempty(p: Path) -> bool:
        try:
            return p.is_file() and p.stat().st_size > 0
        except OSError:
            return False

    def _count_lines(p: Path) -> int:
        try:
            with p.open("r", encoding="utf-8", errors="replace") as f:
                return sum(1 for _ in f)
        except OSError:
            return 0

    perf_script = intermediate_dir / f"{prefix}.perf.script.txt"
    perf_script_stderr = report_dir / f"{prefix}.perf.script.stderr.txt"
    perf_insn = intermediate_dir / f"{prefix}.perf.insn.trace.txt"
    perf_rec_mem = mem_dir / f"{prefix}.perf.mem.recovered.jsonl"
    perf_data_analysis = report_dir / f"{prefix}.perf.recovered.data.analysis.json"
    perf_inst_analysis = report_dir / f"{prefix}.perf.inst.analysis.json"
    perf_recover_report = report_dir / f"{prefix}.perf.recover.report.json"

    perf_portrait_txt = intermediate_dir / f"{prefix}.perf.insn.portrait.txt"
    perf_portrait_stderr = report_dir / f"{prefix}.perf.portrait.script.stderr.txt"
    perf_portrait_tmp = intermediate_dir / f"{prefix}.perf.insn.portrait.tmp.txt"

    def run_perf_script_streaming(
        cmd: list[str],
        *,
        out_path: Path,
        stderr_path: Path,
        max_keep_lines: int,
        keep_predicate: Any | None = None,
    ) -> int:
        """
        Run `perf script` and stream stdout to `out_path`.

        If `keep_predicate` is provided, only lines where predicate(line) is True are written.
        Stops early when written lines reach `max_keep_lines` (if >0) by terminating the subprocess.
        Returns number of lines written.
        """
        out_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        with out_path.open("w", encoding="utf-8") as fout, stderr_path.open("w", encoding="utf-8") as ferr:
            if verbose:
                print("[cmd]", " ".join(shlex.quote(x) for x in cmd))
            p = subprocess.Popen(cmd, text=True, stdout=subprocess.PIPE, stderr=ferr)
            try:
                assert p.stdout is not None
                for line in p.stdout:
                    if keep_predicate is not None and not keep_predicate(line):
                        continue
                    fout.write(line)
                    written += 1
                    if max_keep_lines > 0 and written >= max_keep_lines:
                        # Enough for downstream analysis; stop perf script early.
                        p.send_signal(signal.SIGINT)
                        break
            finally:
                # Ensure process terminates.
                try:
                    p.wait(timeout=2.0)
                except Exception:
                    try:
                        p.kill()
                    except Exception:
                        pass
                    try:
                        p.wait(timeout=2.0)
                    except Exception:
                        pass
        return written

    def truncate_text(src: Path, dst: Path, max_lines: int) -> int:
        if max_lines <= 0:
            # Keep whole file
            if src != dst:
                dst.write_bytes(src.read_bytes())
            return -1
        n = 0
        with src.open("r", encoding="utf-8", errors="replace") as fin, dst.open("w", encoding="utf-8") as fout:
            for line in fin:
                fout.write(line)
                n += 1
                if n >= max_lines:
                    break
        return n

    aux_lost = 0
    trace_errors = 0
    if _nonempty(perf_insn):
        # Reuse existing extracted insn trace (useful for resume/re-run).
        insn_lines = _count_lines(perf_insn)
    else:
        if perf_max_insn_lines > 0:
            # Stream-filter on the fly to avoid huge perf.script.txt.
            insn_lines = run_perf_script_streaming(
                [
                    str(perf_tool),
                    "script",
                    "-f",
                    "--insn-trace",
                    "-F",
                    "tid,time,ip,insn",
                    "-i",
                    str(perf_data),
                ],
                out_path=perf_insn,
                stderr_path=perf_script_stderr,
                max_keep_lines=perf_max_insn_lines,
                keep_predicate=lambda s: " insn:" in s,
            )
            aux_lost, trace_errors = parse_perf_script_health(perf_script_stderr)
        else:
            run_step(
                [
                    str(perf_tool),
                    "script",
                    "-f",
                    "--insn-trace",
                    "-F",
                    "tid,time,ip,insn",
                    "-i",
                    str(perf_data),
                ],
                verbose=verbose,
                stdout_path=perf_script,
                stderr_path=perf_script_stderr,
            )
            aux_lost, trace_errors = parse_perf_script_health(perf_script_stderr)
            insn_lines = extract_perf_insn_trace(perf_script, perf_insn, perf_max_insn_lines)
            try:
                perf_script.unlink()
            except FileNotFoundError:
                pass
    if insn_lines < 1:
        raise RuntimeError(f"no perf insn lines extracted (aux_lost={aux_lost}, trace_errors={trace_errors})")

    if insn_portrait:
        # If the portrait decode output already exists, keep it (resume-friendly).
        if not _nonempty(perf_portrait_txt):
            if perf_max_insn_lines > 0:
                # Stream-truncate portrait decode too.
                run_perf_script_streaming(
                    [
                        str(perf_tool),
                        "script",
                        "-f",
                        "--insn-trace",
                        "--xed",
                        "-F",
                        "tid,ip,insn,ipc",
                        "-i",
                        str(perf_data),
                    ],
                    out_path=perf_portrait_txt,
                    stderr_path=perf_portrait_stderr,
                    max_keep_lines=perf_max_insn_lines,
                    keep_predicate=None,
                )
            else:
                run_step(
                    [
                        str(perf_tool),
                        "script",
                        "-f",
                        "--insn-trace",
                        "--xed",
                        "-F",
                        "tid,ip,insn,ipc",
                        "-i",
                        str(perf_data),
                    ],
                    verbose=verbose,
                    stdout_path=perf_portrait_tmp,
                    stderr_path=perf_portrait_stderr,
                )
                if perf_portrait_tmp.exists() and perf_portrait_tmp.stat().st_size > 0:
                    try:
                        perf_portrait_tmp.replace(perf_portrait_txt)
                    except OSError:
                        perf_portrait_txt.write_bytes(perf_portrait_tmp.read_bytes())
                        try:
                            perf_portrait_tmp.unlink()
                        except FileNotFoundError:
                            pass

    recover_cmd = [
        str(recover_bin),
        "-i",
        str(perf_insn),
        "-o",
        str(perf_rec_mem),
        "--report-out",
        str(perf_recover_report),
        "--init-regs",
        recover_init_regs,
        "--reg-staging",
        recover_reg_staging,
        "--mvs",
        recover_mvs,
        "--seed",
        str(recover_fill_seed),
        "--page-init",
        recover_page_init,
        "--page-init-seed",
        str(recover_page_init_seed),
        "--progress-every",
        str(recover_progress_every),
        "--inst-analysis-out",
        str(perf_inst_analysis),
        "--data-analysis-out",
        str(perf_data_analysis),
        "--analysis-line-size",
        str(line_size),
        "--analysis-sdp-max-lines",
        "262144",
        "--analysis-rd-definition",
        "stack_depth",
        "--analysis-rd-hist-cap-lines",
        str(analysis_rd_hist_cap_lines),
        "--analysis-stride-bin-cap-lines",
        str(analysis_stride_bin_cap_lines),
    ]
    if recover_salvage_invalid_mem:
        recover_cmd.append("--salvage-invalid-mem")
        if recover_salvage_reads:
            recover_cmd.append("--salvage-reads")
    # If recover outputs already exist, skip re-running recover_mem_addrs_uc.
    if not (_nonempty(perf_data_analysis) and _nonempty(perf_inst_analysis) and _nonempty(perf_rec_mem)):
        run_step(recover_cmd, verbose=verbose)
        if not perf_data_analysis.exists() or not perf_inst_analysis.exists():
            raise RuntimeError("recover_mem_addrs_uc did not write analysis JSON outputs")

        # Free space: perf_insn trace can be large and is no longer needed after recover.
        try:
            perf_insn.unlink()
        except FileNotFoundError:
            pass

    portrait_out: Path | None = None
    if insn_portrait and perf_portrait_txt.is_file() and perf_portrait_txt.stat().st_size > 0:
        portrait_out = perf_portrait_txt

    return (
        aux_lost,
        trace_errors,
        insn_lines,
        perf_insn,
        perf_rec_mem,
        perf_data_analysis,
        perf_inst_analysis,
        portrait_out,
    )

