from __future__ import annotations

import json
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from intel_pt_trace_processing.core.features import build_trace_profile
from intel_pt_trace_processing.perf.stream import process_perf_stream


@dataclass
class PerfProcessingConfig:
    perf_tool: str | Path = "perf"
    line_size: int = 64
    perf_max_insn_lines: int = 5_000_000
    insn_portrait: bool = True

    symfs_dir: str | Path | None = None
    target_pid: str | None = None

    recover_mvs: str = "on"
    recover_fill_seed: int = 1
    recover_progress_every: int = 0
    recover_salvage_invalid_mem: bool = True
    recover_salvage_reads: bool = True

    analysis_sdp_max_lines: int = 262144
    analysis_rd_hist_cap_lines: int = 262144
    analysis_stride_bin_cap_lines: int = 262144
    split_crossline: str = "on"
    rcx_soft_threshold: int = 128

    verbose: bool = False

    def validate(self) -> None:
        if self.line_size <= 0 or (self.line_size & (self.line_size - 1)) != 0:
            raise ValueError("line_size must be a positive power of two")
        if self.perf_max_insn_lines < 0:
            raise ValueError("perf_max_insn_lines must be >= 0")
        if self.analysis_rd_hist_cap_lines < 0 or self.analysis_stride_bin_cap_lines < 0:
            raise ValueError("analysis cap lines must be >= 0")
        if self.analysis_sdp_max_lines < 0:
            raise ValueError("analysis_sdp_max_lines must be >= 0")
        if self.recover_progress_every < 0:
            raise ValueError("recover_progress_every must be >= 0")
        if self.recover_mvs not in {"on", "off"}:
            raise ValueError("recover_mvs must be on or off")
        if self.split_crossline not in {"on", "off"}:
            raise ValueError("split_crossline must be on or off")
        if self.rcx_soft_threshold < 0:
            raise ValueError("rcx_soft_threshold must be >= 0")
        if self.symfs_dir is not None and not Path(self.symfs_dir).is_dir():
            raise ValueError(f"symfs_dir is not a directory: {self.symfs_dir}")


@dataclass
class PerfProcessingResult:
    profile: dict[str, Any]
    paths: dict[str, Path | None]

    def write_json(self, output_json: str | Path) -> Path:
        out_path = Path(output_json).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(self.profile, indent=2, ensure_ascii=False), encoding="utf-8")
        return out_path


def repo_root_from_package() -> Path:
    return Path(__file__).resolve().parents[3]


def process_perf_data(
    perf_data: str | Path,
    *,
    config: PerfProcessingConfig | None = None,
    work_dir: str | Path | None = None,
    keep_intermediate: bool = False,
    prefix: str = "trace",
    script_dir: str | Path | None = None,
    metadata: dict[str, Any] | None = None,
) -> PerfProcessingResult:
    perf_data_path = Path(perf_data).resolve()
    if not perf_data_path.is_file():
        raise FileNotFoundError(f"perf_data not found: {perf_data_path}")

    cfg = config or PerfProcessingConfig()
    cfg.validate()

    root = Path(script_dir).resolve() if script_dir is not None else repo_root_from_package()
    owns_work_dir = work_dir is None
    base_dir = Path(tempfile.mkdtemp(prefix="trace_feat_")) if owns_work_dir else Path(work_dir).resolve()
    intermediate_dir = base_dir / "intermediate"
    mem_dir = base_dir / "mem"
    report_dir = base_dir / "report"

    try:
        stream_result = process_perf_stream(
            script_dir=root,
            perf_tool=cfg.perf_tool,
            perf_data=perf_data_path,
            prefix=prefix,
            intermediate_dir=intermediate_dir,
            mem_dir=mem_dir,
            report_dir=report_dir,
            perf_max_insn_lines=cfg.perf_max_insn_lines,
            line_size=cfg.line_size,
            analysis_sdp_max_lines=cfg.analysis_sdp_max_lines,
            analysis_rd_hist_cap_lines=cfg.analysis_rd_hist_cap_lines,
            analysis_stride_bin_cap_lines=cfg.analysis_stride_bin_cap_lines,
            recover_mvs=cfg.recover_mvs,
            recover_fill_seed=cfg.recover_fill_seed,
            recover_progress_every=cfg.recover_progress_every,
            recover_salvage_invalid_mem=cfg.recover_salvage_invalid_mem,
            recover_salvage_reads=cfg.recover_salvage_reads,
            insn_portrait=cfg.insn_portrait,
            split_crossline=cfg.split_crossline,
            rcx_soft_threshold=cfg.rcx_soft_threshold,
            verbose=cfg.verbose,
            symfs_dir=cfg.symfs_dir,
            target_pid=cfg.target_pid,
        )
        stream_profile = stream_result.profile
        portrait_features = stream_profile.get("portrait") if cfg.insn_portrait else None

        artifacts: dict[str, Path | None] = {
            "work_dir": base_dir,
            "stream_profile_json": stream_result.combined_json,
            "perf_recovered_memory": stream_result.recovered_mem_jsonl,
            "data_analysis_json": stream_result.data_analysis_json,
            "instruction_analysis_json": stream_result.inst_analysis_json,
            "recover_report_json": stream_result.recover_report_json,
            "portrait_json": stream_result.portrait_json,
            "perf_script_stderr": stream_result.perf_script_stderr,
            "processor_stderr": stream_result.processor_stderr,
        }
        profile = build_trace_profile(
            source_kind="perf",
            source_path=perf_data_path,
            prefix=prefix,
            data_locality=stream_profile.get("data_locality", {}),
            inst_locality=stream_profile.get("inst_locality", {}),
            insn_portrait=portrait_features if isinstance(portrait_features, dict) else None,
            recover_report=stream_profile.get("recover", {}),
            health={
                "aux_lost": stream_result.aux_lost,
                "trace_errors": stream_result.trace_errors,
                "insn_lines": stream_result.insn_lines,
                **(stream_profile.get("health", {}) if isinstance(stream_profile.get("health"), dict) else {}),
            },
            artifacts=artifacts,
            metadata=metadata,
        )
        return PerfProcessingResult(profile=profile, paths=artifacts)
    finally:
        if owns_work_dir and not keep_intermediate:
            shutil.rmtree(base_dir, ignore_errors=True)
