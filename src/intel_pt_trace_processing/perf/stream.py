from __future__ import annotations

import argparse
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from intel_pt_trace_processing.core.features import build_trace_profile, load_json_object, write_trace_profile
from intel_pt_trace_processing.perf.selection import discover_process_tree_pids


@dataclass
class PerfStreamResult:
    aux_lost: int
    trace_errors: int
    insn_lines: int
    trace_profile_json: Path
    perf_script_stderr: Path
    processor_stderr: Path

    @property
    def profile(self) -> dict[str, Any]:
        return load_json_object(self.trace_profile_json)


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


def add_perf_processor_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--line-size", type=int, default=64, help="Cache line size (power of two)")
    parser.add_argument(
        "--perf-max-insn-lines",
        type=int,
        default=5_000_000,
        help="Max decoded instruction lines to process (0 = unlimited)",
    )
    parser.add_argument(
        "--insn-portrait",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Emit instruction portrait features from the one-pass stream processor",
    )
    parser.add_argument("--recover-mvs", choices=["on", "off"], default="on")
    parser.add_argument("--recover-fill-seed", type=int, default=1)
    parser.add_argument("--recover-progress-every", type=int, default=0)
    parser.add_argument("--recover-salvage-invalid-mem", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--recover-salvage-reads", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--analysis-rd-hist-cap-lines", type=int, default=262144)
    parser.add_argument("--analysis-stride-bin-cap-lines", type=int, default=262144)
    parser.add_argument("--analysis-sdp-max-lines", type=int, default=262144)
    parser.add_argument("--split-crossline", choices=["on", "off"], default="on")
    parser.add_argument("--rcx-soft-threshold", type=int, default=128)


def validate_perf_processor_args(args: argparse.Namespace) -> None:
    if args.line_size <= 0 or (args.line_size & (args.line_size - 1)) != 0:
        raise SystemExit("--line-size must be a positive power of two")
    if args.perf_max_insn_lines < 0:
        raise SystemExit("--perf-max-insn-lines must be >= 0")
    if args.analysis_rd_hist_cap_lines < 0 or args.analysis_stride_bin_cap_lines < 0:
        raise SystemExit("analysis cap lines must be >= 0")
    if args.analysis_sdp_max_lines < 0:
        raise SystemExit("--analysis-sdp-max-lines must be >= 0")
    if args.recover_progress_every < 0:
        raise SystemExit("--recover-progress-every must be >= 0")
    if args.rcx_soft_threshold < 0:
        raise SystemExit("--rcx-soft-threshold must be >= 0")


add_perf_postprocess_args = add_perf_processor_args
validate_perf_postprocess_args = validate_perf_processor_args


def _perf_locate_args(symfs_dir: str | Path | None, target_pid: str | None) -> list[str]:
    out: list[str] = []
    if symfs_dir is not None:
        symfs_path = Path(symfs_dir)
        if not symfs_path.is_dir():
            raise RuntimeError(f"symfs_dir is not a directory: {symfs_path}")
        out += ["--symfs", str(symfs_path)]
    if target_pid:
        out += ["--pid", str(target_pid)]
    return out


def process_perf_stream(
    *,
    script_dir: Path,
    perf_tool: str | Path,
    perf_data: Path,
    prefix: str,
    intermediate_dir: Path,
    report_dir: Path,
    perf_max_insn_lines: int,
    line_size: int,
    analysis_rd_hist_cap_lines: int,
    analysis_stride_bin_cap_lines: int,
    recover_mvs: str,
    recover_fill_seed: int,
    recover_progress_every: int,
    recover_salvage_invalid_mem: bool,
    recover_salvage_reads: bool,
    verbose: bool,
    insn_portrait: bool = True,
    analysis_sdp_max_lines: int = 262144,
    split_crossline: str = "on",
    rcx_soft_threshold: int = 128,
    symfs_dir: str | Path | None = None,
    target_pid: str | None = None,
    target_pid_include_descendants: bool = True,
    perf_command_prefix: Sequence[str] = (),
    metadata: dict[str, Any] | None = None,
) -> PerfStreamResult:
    processor_bin = script_dir / "trace_feature_processor"
    if not processor_bin.exists():
        raise RuntimeError(f"missing {processor_bin}; run build_trace_tools.sh first")

    intermediate_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    processor_json = intermediate_dir / f"{prefix}.trace_profile.processor.json"
    trace_profile_json = report_dir / f"{prefix}.trace_profile.json"
    perf_script_stderr = report_dir / f"{prefix}.perf.script.stderr.txt"
    processor_stderr = report_dir / f"{prefix}.trace_feature_processor.stderr.txt"

    selected_pid = target_pid
    effective_metadata = dict(metadata or {})
    if target_pid:
        if target_pid_include_descendants:
            try:
                root_pid = int(target_pid)
            except ValueError as exc:
                raise ValueError("target_pid must be one integer when descendant filtering is enabled") from exc
            selected_pids = discover_process_tree_pids(
                perf_tool=perf_tool,
                perf_data=perf_data,
                root_pid=root_pid,
            )
            selected_pid = ",".join(str(pid) for pid in selected_pids)
            effective_metadata["trace_selection"] = {
                "mode": "process_tree",
                "root_pid": root_pid,
                "selected_pids": selected_pids,
                "include_descendants": True,
            }
        else:
            effective_metadata["trace_selection"] = {
                "mode": "pid",
                "selected_pids": [int(pid) for pid in str(target_pid).split(",") if pid],
                "include_descendants": False,
            }

    perf_cmd = [
        *perf_command_prefix,
        str(perf_tool),
        "script",
        "-f",
        *_perf_locate_args(symfs_dir, selected_pid),
        "--insn-trace",
        "-F",
        "tid,cpu,time,ip,insn,ipc",
        "-i",
        str(perf_data),
    ]
    processor_cmd = [
        str(processor_bin),
        "--out",
        str(processor_json),
        "--max-insns",
        str(perf_max_insn_lines),
        "--progress-every",
        str(recover_progress_every),
        "--analysis-line-size",
        str(line_size),
        "--analysis-sdp-max-lines",
        str(analysis_sdp_max_lines),
        "--analysis-rd-definition",
        "stack_depth",
        "--analysis-rd-hist-cap-lines",
        str(analysis_rd_hist_cap_lines),
        "--analysis-stride-bin-cap-lines",
        str(analysis_stride_bin_cap_lines),
        "--split-crossline",
        split_crossline,
        "--mvs",
        recover_mvs,
        "--seed",
        str(recover_fill_seed),
        "--rcx-soft-threshold",
        str(rcx_soft_threshold),
    ]
    if recover_salvage_invalid_mem:
        processor_cmd.append("--salvage-invalid-mem")
        if recover_salvage_reads:
            processor_cmd.append("--salvage-reads")

    if verbose:
        print("[cmd]", " ".join(shlex.quote(x) for x in perf_cmd), "|", " ".join(shlex.quote(x) for x in processor_cmd))

    perf_script_stderr.parent.mkdir(parents=True, exist_ok=True)
    processor_stderr.parent.mkdir(parents=True, exist_ok=True)
    with perf_script_stderr.open("w", encoding="utf-8") as perf_err, processor_stderr.open(
        "w", encoding="utf-8"
    ) as proc_err:
        perf_proc = subprocess.Popen(perf_cmd, stdout=subprocess.PIPE, stderr=perf_err, text=True)
        try:
            assert perf_proc.stdout is not None
            processor_proc = subprocess.Popen(processor_cmd, stdin=perf_proc.stdout, stderr=proc_err, text=True)
            perf_proc.stdout.close()
            proc_rc = processor_proc.wait()
            perf_rc = perf_proc.wait()
        finally:
            try:
                if perf_proc.poll() is None:
                    perf_proc.kill()
            except Exception:
                pass

    aux_lost, trace_errors = parse_perf_script_health(perf_script_stderr)
    processor_profile = load_json_object(processor_json)
    health = processor_profile.get("health", {}) if isinstance(processor_profile, dict) else {}
    insn_lines = int(health.get("parsed_lines", 0) or 0) if isinstance(health, dict) else 0

    if proc_rc != 0 and insn_lines < 1:
        raise RuntimeError(f"trace_feature_processor failed with exit code {proc_rc}; see {processor_stderr}")
    if perf_rc not in (0, 130, 141, -13) and insn_lines < 1:
        raise RuntimeError(f"perf script failed with exit code {perf_rc}; see {perf_script_stderr}")
    if insn_lines < 1:
        raise RuntimeError(f"no perf insn lines processed (aux_lost={aux_lost}, trace_errors={trace_errors})")

    portrait_obj = processor_profile.get("portrait", {}) if insn_portrait else {}
    profile = build_trace_profile(
        source_kind="perf",
        source_path=perf_data,
        prefix=prefix,
        data_locality=processor_profile.get("data_locality", {}),
        inst_locality=processor_profile.get("inst_locality", {}),
        insn_portrait=portrait_obj if isinstance(portrait_obj, dict) else None,
        recover_report=processor_profile.get("recover", {}),
        health={
            "aux_lost": aux_lost,
            "trace_errors": trace_errors,
            "insn_lines": insn_lines,
            "perf_script_returncode": perf_rc,
            "processor_returncode": proc_rc,
            **(health if isinstance(health, dict) else {}),
        },
        artifacts={
            "perf_data": perf_data,
            "processor_profile_json": processor_json,
            "perf_script_stderr": perf_script_stderr,
            "processor_stderr": processor_stderr,
        },
        metadata=effective_metadata,
    )
    write_trace_profile(trace_profile_json, profile)

    return PerfStreamResult(
        aux_lost=aux_lost,
        trace_errors=trace_errors,
        insn_lines=insn_lines,
        trace_profile_json=trace_profile_json,
        perf_script_stderr=perf_script_stderr,
        processor_stderr=processor_stderr,
    )
