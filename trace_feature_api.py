#!/usr/bin/env python3
"""
Public software-feature extraction API for Intel PT traces.

This file is kept as the stable downstream entry point. The implementation now
delegates to the refactored core package under ``src/intel_pt_trace_processing``.

Main path:

    perf.data -> perf script --insn-trace -> instruction processing -> trace-profile-v1 JSON

The API produces software features only. Hardware/microarchitecture parameters
belong to downstream consumers or to the optional theory-model layer.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_SRC_DIR = Path(__file__).resolve().parent / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from intel_pt_trace_processing.core.theory import TheoryConfig
from intel_pt_trace_processing.perf.processor import PerfProcessingConfig, process_perf_data

SCHEMA_VERSION = "trace-profile-v1"

# Backward-compatible public name. Existing callers can keep importing
# FeatureExtractionConfig from this module.
FeatureExtractionConfig = PerfProcessingConfig


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

    Returns a ``trace-profile-v1`` dictionary. The normalized surface is:

      - ``features.data_memory``
      - ``features.instruction_memory``
      - ``features.instruction_portrait``
      - ``features.recovery``
      - ``health``
      - optional ``theory``

    Legacy top-level keys such as ``data_locality`` and ``inst_locality`` are
    still present for compatibility.
    """
    result = process_perf_data(
        perf_data,
        config=config,
        work_dir=work_dir,
        keep_intermediate=keep_intermediate,
        prefix=prefix,
        script_dir=Path(__file__).resolve().parent,
    )
    return result.profile


def extract_software_features_to_json(
    perf_data: str | Path,
    output_json: str | Path,
    *,
    config: FeatureExtractionConfig | None = None,
    work_dir: str | Path | None = None,
    keep_intermediate: bool = False,
    prefix: str = "trace",
) -> Path:
    result = process_perf_data(
        perf_data,
        config=config,
        work_dir=work_dir,
        keep_intermediate=keep_intermediate,
        prefix=prefix,
        script_dir=Path(__file__).resolve().parent,
    )
    out_path = Path(output_json).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result.profile, indent=2, ensure_ascii=False), encoding="utf-8")
    return out_path


def _build_cli_config(args: Any) -> FeatureExtractionConfig:
    return FeatureExtractionConfig(
        perf_tool=args.perf_tool,
        line_size=args.line_size,
        perf_max_insn_lines=args.perf_max_insn_lines,
        insn_portrait=args.insn_portrait,
        recover_mvs=args.recover_mvs,
        recover_fill_seed=args.recover_fill_seed,
        recover_progress_every=args.recover_progress_every,
        recover_salvage_invalid_mem=args.recover_salvage_invalid_mem,
        recover_salvage_reads=args.recover_salvage_reads,
        analysis_sdp_max_lines=args.analysis_sdp_max_lines,
        analysis_rd_hist_cap_lines=args.analysis_rd_hist_cap_lines,
        analysis_stride_bin_cap_lines=args.analysis_stride_bin_cap_lines,
        split_crossline=args.split_crossline,
        rcx_soft_threshold=args.rcx_soft_threshold,
        verbose=args.verbose,
        symfs_dir=args.symfs_dir,
        target_pid=args.target_pid,
        theory=TheoryConfig(enabled=args.theory_model, access=args.theory_access),
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
        help="Binary root for off-host decoding (perf --symfs)",
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
    parser.add_argument("--recover-mvs", choices=["on", "off"], default="on")
    parser.add_argument("--recover-fill-seed", type=int, default=1)
    parser.add_argument("--recover-progress-every", type=int, default=0)
    parser.add_argument("--recover-salvage-invalid-mem", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--recover-salvage-reads", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--analysis-sdp-max-lines", type=int, default=262144)
    parser.add_argument("--analysis-rd-hist-cap-lines", type=int, default=262144)
    parser.add_argument("--analysis-stride-bin-cap-lines", type=int, default=262144)
    parser.add_argument("--split-crossline", choices=["on", "off"], default="on")
    parser.add_argument("--rcx-soft-threshold", type=int, default=128)
    parser.add_argument(
        "--theory-model",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Attach an initial MIIC interval-model prediction to the output JSON",
    )
    parser.add_argument("--theory-access", type=str, default="all", help="per_access key used by theory model")
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
