from __future__ import annotations

import json
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from intel_pt_trace_processing.core import portrait as insn_portrait
from intel_pt_trace_processing.core.features import build_trace_profile, load_json_object
from intel_pt_trace_processing.core.theory import TheoryConfig, predict_from_trace_profile
from intel_pt_trace_processing.perf.pipeline import perf_postprocess_one


@dataclass
class PerfProcessingConfig:
    perf_tool: str | Path = "perf"
    line_size: int = 64
    perf_max_insn_lines: int = 5_000_000
    insn_portrait: bool = True

    symfs_dir: str | Path | None = None
    target_pid: str | None = None

    recover_init_regs: str = "random"
    recover_reg_staging: str = "dwt"
    recover_mvs: str = "on"
    recover_fill_seed: int = 1
    recover_page_init: str = "zero"
    recover_page_init_seed: int = 1
    recover_progress_every: int = 0
    recover_salvage_invalid_mem: bool = True
    recover_salvage_reads: bool = True

    analysis_rd_hist_cap_lines: int = 262144
    analysis_stride_bin_cap_lines: int = 262144

    theory: TheoryConfig = field(default_factory=TheoryConfig)
    verbose: bool = False

    def validate(self) -> None:
        if self.line_size <= 0 or (self.line_size & (self.line_size - 1)) != 0:
            raise ValueError("line_size must be a positive power of two")
        if self.perf_max_insn_lines < 0:
            raise ValueError("perf_max_insn_lines must be >= 0")
        if self.analysis_rd_hist_cap_lines < 0 or self.analysis_stride_bin_cap_lines < 0:
            raise ValueError("analysis cap lines must be >= 0")
        if self.recover_progress_every < 0:
            raise ValueError("recover_progress_every must be >= 0")
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
        (
            aux_lost,
            trace_errors,
            insn_lines,
            perf_insn,
            perf_rec_mem,
            perf_data_analysis,
            perf_inst_analysis,
            portrait_txt,
        ) = perf_postprocess_one(
            script_dir=root,
            perf_tool=cfg.perf_tool,
            perf_data=perf_data_path,
            prefix=prefix,
            intermediate_dir=intermediate_dir,
            mem_dir=mem_dir,
            report_dir=report_dir,
            perf_max_insn_lines=cfg.perf_max_insn_lines,
            line_size=cfg.line_size,
            analysis_rd_hist_cap_lines=cfg.analysis_rd_hist_cap_lines,
            analysis_stride_bin_cap_lines=cfg.analysis_stride_bin_cap_lines,
            recover_init_regs=cfg.recover_init_regs,
            recover_reg_staging=cfg.recover_reg_staging,
            recover_mvs=cfg.recover_mvs,
            recover_fill_seed=cfg.recover_fill_seed,
            recover_page_init=cfg.recover_page_init,
            recover_page_init_seed=cfg.recover_page_init_seed,
            recover_progress_every=cfg.recover_progress_every,
            recover_salvage_invalid_mem=cfg.recover_salvage_invalid_mem,
            recover_salvage_reads=cfg.recover_salvage_reads,
            insn_portrait=cfg.insn_portrait,
            verbose=cfg.verbose,
            symfs_dir=cfg.symfs_dir,
            target_pid=cfg.target_pid,
        )

        recover_report = report_dir / f"{prefix}.perf.recover.report.json"
        portrait_features: dict[str, Any] | None = None
        if cfg.insn_portrait and portrait_txt is not None and portrait_txt.is_file():
            max_p = cfg.perf_max_insn_lines if cfg.perf_max_insn_lines > 0 else 0
            portrait_features = insn_portrait.analyze_file(portrait_txt, max_insns=max_p)

        artifacts: dict[str, Path | None] = {
            "work_dir": base_dir,
            "perf_instruction_trace": perf_insn,
            "perf_recovered_memory": perf_rec_mem,
            "data_analysis_json": perf_data_analysis,
            "instruction_analysis_json": perf_inst_analysis,
            "recover_report_json": recover_report,
            "portrait_text": portrait_txt,
        }
        profile = build_trace_profile(
            source_kind="perf",
            source_path=perf_data_path,
            prefix=prefix,
            data_locality=load_json_object(perf_data_analysis),
            inst_locality=load_json_object(perf_inst_analysis),
            insn_portrait=portrait_features,
            recover_report=load_json_object(recover_report),
            health={
                "aux_lost": aux_lost,
                "trace_errors": trace_errors,
                "insn_lines": insn_lines,
            },
            artifacts=artifacts,
            metadata=metadata,
        )
        theory = predict_from_trace_profile(profile, cfg.theory)
        if theory is not None:
            profile["theory"] = theory
        return PerfProcessingResult(profile=profile, paths=artifacts)
    finally:
        if owns_work_dir and not keep_intermediate:
            shutil.rmtree(base_dir, ignore_errors=True)
