from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from perf_pipeline import run_step

from intel_pt_trace_processing.core.features import build_trace_profile, load_json_object


@dataclass
class SdeProcessingConfig:
    line_size: int = 64
    analysis_sdp_max_lines: int = 262144
    analysis_rd_definition: str = "stack_depth"
    analysis_rd_hist_cap_lines: int = 262144
    analysis_stride_bin_cap_lines: int = 262144
    split_crossline: bool = True
    emit_instruction_trace: bool = False
    emit_instruction_analysis: bool = False
    verbose: bool = False

    def validate(self) -> None:
        if self.line_size <= 0 or (self.line_size & (self.line_size - 1)) != 0:
            raise ValueError("line_size must be a positive power of two")
        if self.analysis_rd_definition not in {"stack_depth", "distinct_since_last"}:
            raise ValueError("analysis_rd_definition must be stack_depth or distinct_since_last")


@dataclass
class SdeProcessingResult:
    profile: dict[str, Any]
    paths: dict[str, Path | None]

    def write_json(self, output_json: str | Path) -> Path:
        out_path = Path(output_json).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(self.profile, indent=2, ensure_ascii=False), encoding="utf-8")
        return out_path


def repo_root_from_package() -> Path:
    return Path(__file__).resolve().parents[3]


def process_sde_debugtrace(
    sde_trace: str | Path,
    *,
    output_dir: str | Path,
    config: SdeProcessingConfig | None = None,
    prefix: str = "trace",
    script_dir: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> SdeProcessingResult:
    trace_path = Path(sde_trace).resolve()
    if not trace_path.is_file():
        raise FileNotFoundError(f"sde_trace not found: {trace_path}")
    cfg = config or SdeProcessingConfig()
    cfg.validate()

    root = Path(script_dir).resolve() if script_dir is not None else repo_root_from_package()
    analyzer = root / "analyze_sde_trace_uc"
    if not analyzer.exists():
        raise RuntimeError(f"missing {analyzer}; run build_recover_mem_addrs_uc.sh first")

    out_dir = Path(output_dir).resolve()
    mem_dir = out_dir / "mem"
    report_dir = out_dir / "report"
    intermediate_dir = out_dir / "intermediate"
    mem_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)
    intermediate_dir.mkdir(parents=True, exist_ok=True)

    mem_jsonl = mem_dir / f"{prefix}.sde.mem.real.jsonl"
    data_analysis = report_dir / f"{prefix}.sde.data.analysis.json"
    insn_trace = intermediate_dir / f"{prefix}.sde.insn.trace.txt" if cfg.emit_instruction_trace else None
    inst_analysis = report_dir / f"{prefix}.sde.inst.analysis.json" if cfg.emit_instruction_analysis else None

    cmd = [
        str(analyzer),
        "-i",
        str(trace_path),
        "--mem-out",
        str(mem_jsonl),
        "--data-analysis-out",
        str(data_analysis),
        "--analysis-line-size",
        str(cfg.line_size),
        "--split-crossline",
        "on" if cfg.split_crossline else "off",
        "--analysis-sdp-max-lines",
        str(cfg.analysis_sdp_max_lines),
        "--analysis-rd-definition",
        cfg.analysis_rd_definition,
        "--analysis-rd-hist-cap-lines",
        str(cfg.analysis_rd_hist_cap_lines),
        "--analysis-stride-bin-cap-lines",
        str(cfg.analysis_stride_bin_cap_lines),
    ]
    if insn_trace is not None:
        cmd += ["--insn-out", str(insn_trace)]
    if inst_analysis is not None:
        cmd += ["--inst-analysis-out", str(inst_analysis)]

    stderr_path = report_dir / f"{prefix}.sde.analyze.stderr.txt"
    run_step(cmd, verbose=cfg.verbose, stderr_path=stderr_path)

    artifacts: dict[str, Path | None] = {
        "work_dir": out_dir,
        "sde_memory_trace": mem_jsonl,
        "data_analysis_json": data_analysis,
        "instruction_trace": insn_trace,
        "instruction_analysis_json": inst_analysis,
        "stderr": stderr_path,
    }
    profile = build_trace_profile(
        source_kind="sde",
        source_path=trace_path,
        prefix=prefix,
        data_locality=load_json_object(data_analysis),
        inst_locality=load_json_object(inst_analysis) if inst_analysis is not None else None,
        insn_portrait=None,
        recover_report=None,
        health={},
        artifacts=artifacts,
        metadata=metadata,
    )
    return SdeProcessingResult(profile=profile, paths=artifacts)
