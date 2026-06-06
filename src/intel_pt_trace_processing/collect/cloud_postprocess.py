from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path

from intel_pt_trace_processing.collect.cloud_perf_collect import verify_buildid_cache
from intel_pt_trace_processing.perf.stream import process_perf_stream
from intel_pt_trace_processing.perf.selection import load_selection_sidecar
from intel_pt_trace_processing.workloads.cloud_runtime import log

def iter_perf_data_files(output_dir: Path, bench_name: str) -> list[tuple[int, Path]]:
    """Sorted (sample_index, path) for perf.<bench_name>.<n>.data files."""
    out: list[tuple[int, Path]] = []
    prefix = f"perf.{bench_name}."
    for p in sorted(output_dir.iterdir()):
        if not p.is_file() or not p.name.startswith(prefix) or not p.name.endswith(".data"):
            continue
        mid = p.name[len(prefix) : -len(".data")]
        if mid.isdigit():
            out.append((int(mid), p))
    return out

def cloud_postprocess_reports_complete(output_dir: Path, bench_name: str) -> bool:
    """True if every perf sample under output_dir has a trace profile in report/."""
    samples = iter_perf_data_files(output_dir, bench_name)
    if not samples:
        return False
    slug = bench_name.replace(".", "_")
    report_dir = output_dir / bench_name / "report"
    if not report_dir.is_dir():
        return False
    for idx, perf_data in samples:
        selection = load_selection_sidecar(perf_data)
        if selection is None:
            return False
        profile_json = report_dir / f"{slug}_s{idx}.trace_profile.json"
        if not profile_json.is_file() or profile_json.stat().st_size == 0:
            return False
        try:
            profile = json.loads(profile_json.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            return False
        metadata = profile.get("metadata", {}) if isinstance(profile, dict) else {}
        if not isinstance(metadata, dict) or metadata.get("trace_selection") != selection:
            return False
    return True

def cloud_run_perf_postprocess(
    *,
    script_dir: Path,
    output_dir: Path,
    bench_name: str,
    perf_tool: Path,
    args: argparse.Namespace,
) -> None:
    """
    perf script --insn-trace -> trace_feature_processor
    (same tool chain as run_spec5 with --no-enable-sde).
    """
    processor_bin = script_dir / "trace_feature_processor"
    if not processor_bin.is_file() or not os.access(processor_bin, os.X_OK):
        raise RuntimeError(
            f"missing executable {processor_bin}; build it first (e.g. build_recover_mem_addrs_uc.sh)"
        )

    data_files = iter_perf_data_files(output_dir, bench_name)
    if not data_files:
        log("⚠️", f"No perf.data files for {bench_name}; skipping post-process.")
        return

    # <output-base>/<bench>/{intermediate,report} — fixed path; re-runs overwrite outputs.
    case_root = output_dir / bench_name
    intermediate = case_root / "intermediate"
    report_dir = case_root / "report"
    for d in (intermediate, report_dir):
        d.mkdir(parents=True, exist_ok=True)

    slug = bench_name.replace(".", "_")
    for sample_idx, perf_data in data_files:
        prefix = f"{slug}_s{sample_idx}"
        perf_data_copy = intermediate / f"{prefix}.perf.data"
        trace_profile_json = report_dir / f"{prefix}.trace_profile.json"

        want_portrait = bool(getattr(args, "insn_portrait", True))
        selection = load_selection_sidecar(perf_data)
        if selection is None:
            raise RuntimeError(f"missing trace selection metadata for {perf_data}")
        if not bool(selection.get("buildid_cache_verified", False)):
            raise RuntimeError(f"build-id cache was not verified for {perf_data}")
        command_prefix = tuple(str(x) for x in selection.get("perf_command_prefix", []))

        if trace_profile_json.is_file() and trace_profile_json.stat().st_size > 0:
            try:
                profile = json.loads(trace_profile_json.read_text(encoding="utf-8", errors="replace"))
            except (OSError, json.JSONDecodeError):
                profile = {}
            metadata = profile.get("metadata", {}) if isinstance(profile, dict) else {}
            if selection is None or (
                isinstance(metadata, dict) and metadata.get("trace_selection") == selection
            ):
                log("⏭️", f"Sample {sample_idx}: trace profile already exists; skipping perf decode.")
                continue

        verify_buildid_cache(
            perf_tool=perf_tool,
            perf_data=perf_data,
            command_prefix=command_prefix,
        )

        # "Extract perf.data" step for cloud: copy into intermediate (skip if already present).
        if not (perf_data_copy.is_file() and perf_data_copy.stat().st_size > 0):
            shutil.copy2(perf_data, perf_data_copy)

        log("📜", f"Post-process sample {sample_idx}: perf script → trace_feature_processor …")
        result = process_perf_stream(
            script_dir=script_dir,
            perf_tool=perf_tool,
            perf_data=perf_data_copy,
            prefix=prefix,
            intermediate_dir=intermediate,
            report_dir=report_dir,
            perf_max_insn_lines=args.perf_max_insn_lines,
            line_size=args.line_size,
            analysis_sdp_max_lines=args.analysis_sdp_max_lines,
            analysis_rd_hist_cap_lines=args.analysis_rd_hist_cap_lines,
            analysis_stride_bin_cap_lines=args.analysis_stride_bin_cap_lines,
            recover_mvs=args.recover_mvs,
            recover_fill_seed=args.recover_fill_seed,
            recover_progress_every=args.recover_progress_every,
            recover_salvage_invalid_mem=args.recover_salvage_invalid_mem,
            recover_salvage_reads=args.recover_salvage_reads,
            insn_portrait=want_portrait,
            split_crossline=args.split_crossline,
            rcx_soft_threshold=args.rcx_soft_threshold,
            verbose=args.verbose_post,
            perf_command_prefix=command_prefix,
            metadata={
                "bench": bench_name,
                "sample_index": sample_idx,
                "buildid_cache_verified": True,
                **({"trace_selection": selection} if selection is not None else {}),
            },
        )
        log(
            "✅",
            f"Sample {sample_idx}: profile={result.trace_profile_json.name} "
            f"(pt_aux_lost={result.aux_lost}, pt_trace_err={result.trace_errors})",
        )
