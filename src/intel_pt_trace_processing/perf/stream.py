from __future__ import annotations

import argparse
import json
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class PerfStreamResult:
    aux_lost: int
    trace_errors: int
    insn_lines: int
    combined_json: Path
    recovered_mem_jsonl: Path
    data_analysis_json: Path
    inst_analysis_json: Path
    recover_report_json: Path
    portrait_json: Path
    perf_script_stderr: Path
    processor_stderr: Path

    @property
    def profile(self) -> dict[str, Any]:
        return load_json_object(self.combined_json)


def load_json_object(path: str | Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    p = Path(path)
    if not p.is_file():
        return {}
    try:
        obj = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


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


# Backward-compatible helper names for collector scripts during the migration.
add_perf_postprocess_args = add_perf_processor_args
validate_perf_postprocess_args = validate_perf_processor_args


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj if obj is not None else {}, indent=2, ensure_ascii=False), encoding="utf-8")


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
    mem_dir: Path,
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
) -> PerfStreamResult:
    processor_bin = script_dir / "trace_feature_processor"
    if not processor_bin.exists():
        raise RuntimeError(f"missing {processor_bin}; run build_recover_mem_addrs_uc.sh first")

    intermediate_dir.mkdir(parents=True, exist_ok=True)
    mem_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    combined_json = report_dir / f"{prefix}.trace_profile.stream.json"
    perf_rec_mem = mem_dir / f"{prefix}.perf.mem.recovered.jsonl"
    perf_data_analysis = report_dir / f"{prefix}.perf.recovered.data.analysis.json"
    perf_inst_analysis = report_dir / f"{prefix}.perf.inst.analysis.json"
    perf_recover_report = report_dir / f"{prefix}.perf.recover.report.json"
    perf_portrait_json = report_dir / f"{prefix}.insn.portrait.json"
    perf_script_stderr = report_dir / f"{prefix}.perf.script.stderr.txt"
    processor_stderr = report_dir / f"{prefix}.trace_feature_processor.stderr.txt"

    perf_cmd = [
        str(perf_tool),
        "script",
        "-f",
        *_perf_locate_args(symfs_dir, target_pid),
        "--insn-trace",
        "-F",
        "tid,cpu,time,ip,insn,ipc",
        "-i",
        str(perf_data),
    ]
    processor_cmd = [
        str(processor_bin),
        "--out",
        str(combined_json),
        "--mem-out",
        str(perf_rec_mem),
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
    profile = load_json_object(combined_json)
    health = profile.get("health", {}) if isinstance(profile, dict) else {}
    insn_lines = int(health.get("parsed_lines", 0) or 0) if isinstance(health, dict) else 0

    if proc_rc != 0:
        raise RuntimeError(f"trace_feature_processor failed with exit code {proc_rc}; see {processor_stderr}")
    if perf_rc not in (0, 130, 141, -13) and insn_lines < 1:
        raise RuntimeError(f"perf script failed with exit code {perf_rc}; see {perf_script_stderr}")
    if insn_lines < 1:
        raise RuntimeError(f"no perf insn lines processed (aux_lost={aux_lost}, trace_errors={trace_errors})")

    _write_json(perf_data_analysis, profile.get("data_locality", {}))
    _write_json(perf_inst_analysis, profile.get("inst_locality", {}))
    _write_json(perf_recover_report, profile.get("recover", {}))
    if insn_portrait:
        portrait_obj = profile.get("portrait", {})
    else:
        portrait_obj = {}
    _write_json(perf_portrait_json, portrait_obj)

    return PerfStreamResult(
        aux_lost=aux_lost,
        trace_errors=trace_errors,
        insn_lines=insn_lines,
        combined_json=combined_json,
        recovered_mem_jsonl=perf_rec_mem,
        data_analysis_json=perf_data_analysis,
        inst_analysis_json=perf_inst_analysis,
        recover_report_json=perf_recover_report,
        portrait_json=perf_portrait_json,
        perf_script_stderr=perf_script_stderr,
        processor_stderr=processor_stderr,
    )
