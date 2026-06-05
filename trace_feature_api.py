#!/usr/bin/env python3
"""
Software-feature extraction API for Intel PT traces.

This module is the stable, importable entry point that downstream projects
(e.g. ArchLens) should call. It abstracts the full pipeline

    perf.data -> perf script --insn-trace -> recover_mem_addrs_uc -> analysis JSON

into a single function that returns a software-feature dictionary, hiding the
low-level path bookkeeping and the large parameter surface of
``perf_pipeline.perf_postprocess_one``.

Scope boundary (intentional):
  - This API produces *software* features only (instruction-flow, data/instruction
    locality, optional instruction portrait). It deliberately does NOT attach any
    hardware/microarchitecture parameters; that step belongs to the downstream
    consumer (ArchLens).
  - Trace collection (perf record) and SDE-based validation live elsewhere and are
    not part of this API.

Typical usage::

    from trace_feature_api import extract_software_features

    features = extract_software_features("perf.data")
    print(features["data_locality"], features["inst_locality"])

The returned dictionary follows the ``trace-profile-v1`` schema.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import analyze_insn_trace_portrait as insn_portrait
from perf_pipeline import perf_postprocess_one

SCHEMA_VERSION = "trace-profile-v1"


@dataclass
class FeatureExtractionConfig:
    """
    Tunable knobs for software-feature extraction.

    Defaults mirror the production pipeline (``perf_pipeline.add_perf_postprocess_args``)
    so that calling ``extract_software_features`` with no config reproduces the same
    behavior as the batch runners.
    """

    perf_tool: str | Path = "perf"
    line_size: int = 64
    perf_max_insn_lines: int = 5_000_000
    insn_portrait: bool = True

    # Binary-resolution knobs for off-host / production perf.data decoding.
    # symfs_dir: a captured binary root (perf --symfs) so decoding does not rely
    #   on the local disk having the exact binaries that were traced.
    # target_pid: restrict decoding to one process (perf --pid).
    # Both default to None, i.e. same-host decoding using local binaries.
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


def _script_dir() -> Path:
    return Path(__file__).resolve().parent


def _load_json(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    if not raw.strip():
        return {}
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return obj if isinstance(obj, dict) else {}


def extract_software_features(
    perf_data: str | Path,
    *,
    config: FeatureExtractionConfig | None = None,
    work_dir: str | Path | None = None,
    keep_intermediate: bool = False,
    prefix: str = "trace",
) -> dict[str, Any]:
    """
    Extract software features from a single Intel PT ``perf.data`` file.

    Args:
        perf_data: Path to the raw Intel PT capture (perf.data).
        config: Optional tuning knobs. Defaults reproduce the production pipeline.
        work_dir: Directory for intermediate/report artifacts. If omitted, a
            temporary directory is used and removed unless ``keep_intermediate``.
        keep_intermediate: Keep the working directory and its artifacts on disk.
        prefix: Filename prefix for generated artifacts.

    Returns:
        A ``trace-profile-v1`` software-feature dictionary with keys:
          - schema, prefix
          - data_locality: data-access locality features
          - inst_locality: instruction-access locality features
          - recover_report: memory-recovery report metrics
          - insn_portrait: optional instruction portrait (None if disabled/empty)
          - health: pipeline health counters (aux_lost, trace_errors, insn_lines)

    Raises:
        FileNotFoundError: if ``perf_data`` does not exist.
        RuntimeError: if the recover binary is missing or produces no output.
    """
    perf_data_path = Path(perf_data).resolve()
    if not perf_data_path.is_file():
        raise FileNotFoundError(f"perf_data not found: {perf_data_path}")

    cfg = config or FeatureExtractionConfig()
    cfg.validate()

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
            _perf_insn,
            _perf_rec_mem,
            perf_data_analysis,
            perf_inst_analysis,
            portrait_txt,
        ) = perf_postprocess_one(
            script_dir=_script_dir(),
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

        features: dict[str, Any] = {
            "schema": SCHEMA_VERSION,
            "prefix": prefix,
            "source_perf_data": str(perf_data_path),
            "data_locality": _load_json(perf_data_analysis),
            "inst_locality": _load_json(perf_inst_analysis),
            "recover_report": _load_json(recover_report),
            "insn_portrait": portrait_features,
            "health": {
                "aux_lost": aux_lost,
                "trace_errors": trace_errors,
                "insn_lines": insn_lines,
            },
        }
        return features
    finally:
        if owns_work_dir and not keep_intermediate:
            shutil.rmtree(base_dir, ignore_errors=True)


def extract_software_features_to_json(
    perf_data: str | Path,
    output_json: str | Path,
    *,
    config: FeatureExtractionConfig | None = None,
    work_dir: str | Path | None = None,
    keep_intermediate: bool = False,
    prefix: str = "trace",
) -> Path:
    """
    Convenience wrapper: extract features and write them to a JSON file.

    Returns the path to the written JSON file.
    """
    features = extract_software_features(
        perf_data,
        config=config,
        work_dir=work_dir,
        keep_intermediate=keep_intermediate,
        prefix=prefix,
    )
    out_path = Path(output_json).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(features, indent=2, ensure_ascii=False), encoding="utf-8")
    return out_path


def _build_cli_config(args: Any) -> FeatureExtractionConfig:
    return FeatureExtractionConfig(
        perf_tool=args.perf_tool,
        line_size=args.line_size,
        perf_max_insn_lines=args.perf_max_insn_lines,
        insn_portrait=args.insn_portrait,
        recover_init_regs=args.recover_init_regs,
        recover_reg_staging=args.recover_reg_staging,
        recover_mvs=args.recover_mvs,
        recover_fill_seed=args.recover_fill_seed,
        recover_page_init=args.recover_page_init,
        recover_page_init_seed=args.recover_page_init_seed,
        recover_progress_every=args.recover_progress_every,
        recover_salvage_invalid_mem=args.recover_salvage_invalid_mem,
        recover_salvage_reads=args.recover_salvage_reads,
        analysis_rd_hist_cap_lines=args.analysis_rd_hist_cap_lines,
        analysis_stride_bin_cap_lines=args.analysis_stride_bin_cap_lines,
        verbose=args.verbose,
        symfs_dir=args.symfs_dir,
        target_pid=args.target_pid,
    )


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Extract software features from a single Intel PT perf.data file."
    )
    parser.add_argument("perf_data", type=Path, help="Path to the raw Intel PT capture (perf.data)")
    parser.add_argument("-o", "--output-json", type=Path, required=True, help="Where to write the feature JSON")
    parser.add_argument("--prefix", type=str, default="trace", help="Filename prefix for generated artifacts")
    parser.add_argument("--work-dir", type=Path, default=None, help="Directory for intermediate artifacts")
    parser.add_argument(
        "--keep-intermediate", action="store_true", help="Keep the working directory and its artifacts"
    )

    parser.add_argument("--perf-tool", type=str, default="perf", help="perf executable to use")
    parser.add_argument(
        "--symfs",
        dest="symfs_dir",
        type=str,
        default=None,
        help="Binary root for off-host decoding (perf --symfs); needed when the traced "
        "binaries are not at their original paths on this machine",
    )
    parser.add_argument(
        "--pid",
        dest="target_pid",
        type=str,
        default=None,
        help="Restrict decoding to this process id (perf --pid)",
    )
    parser.add_argument("--line-size", type=int, default=64, help="Cache line size (power of two)")
    parser.add_argument("--perf-max-insn-lines", type=int, default=5_000_000)
    parser.add_argument("--insn-portrait", action=argparse.BooleanOptionalAction, default=True)
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
    parser.add_argument("--verbose", action="store_true")

    args = parser.parse_args()
    out_path = extract_software_features_to_json(
        args.perf_data,
        args.output_json,
        config=_build_cli_config(args),
        work_dir=args.work_dir,
        keep_intermediate=args.keep_intermediate,
        prefix=args.prefix,
    )
    print(f"[ok] software features written to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
