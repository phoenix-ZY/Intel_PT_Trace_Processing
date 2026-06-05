from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path

from intel_pt_trace_processing.perf.stream import process_perf_stream
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
    """True if every perf sample under output_dir has stream-processor analysis JSONs in report/."""
    samples = iter_perf_data_files(output_dir, bench_name)
    if not samples:
        return False
    slug = bench_name.replace(".", "_")
    report_dir = output_dir / bench_name / "report"
    if not report_dir.is_dir():
        return False
    for idx, _ in samples:
        data_json = report_dir / f"{slug}_s{idx}.perf.recovered.data.analysis.json"
        inst_json = report_dir / f"{slug}_s{idx}.perf.inst.analysis.json"
        if not data_json.is_file() or not inst_json.is_file():
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
        perf_data_analysis = report_dir / f"{prefix}.perf.recovered.data.analysis.json"
        perf_inst_analysis = report_dir / f"{prefix}.perf.inst.analysis.json"
        perf_insn_portrait_json = report_dir / f"{prefix}.insn.portrait.json"

        want_portrait = bool(getattr(args, "insn_portrait", True))
        have_portrait_json = perf_insn_portrait_json.is_file() and perf_insn_portrait_json.stat().st_size > 0
        have_recover_outputs = (
            perf_data_analysis.is_file()
            and perf_data_analysis.stat().st_size > 0
            and perf_inst_analysis.is_file()
            and perf_inst_analysis.stat().st_size > 0
        )

        # If recover+analysis already exist, skip unless we still need to generate portrait JSON.
        if have_recover_outputs and (not want_portrait or have_portrait_json):
            log("⏭️", f"Sample {sample_idx}: recovered analysis already exists; skipping perf decode/recover.")
            continue

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
        )
        trace_profile_merged_json = report_dir / f"{prefix}.trace_profile.merged.json"
        merged = result.profile
        merged.update(
            {
                "bench": bench_name,
                "sample_index": sample_idx,
                "paths": {
                    "perf_data_copy": str(perf_data_copy),
                    "perf_data_analysis_json": str(result.data_analysis_json),
                    "perf_inst_analysis_json": str(result.inst_analysis_json),
                    "insn_portrait_json": str(result.portrait_json),
                    "stream_profile_json": str(result.combined_json),
                },
            }
        )
        trace_profile_merged_json.write_text(json.dumps(merged, indent=2, ensure_ascii=False), encoding="utf-8")
        log(
            "✅",
            f"Sample {sample_idx}: data={result.data_analysis_json.name} inst={result.inst_analysis_json.name} "
            f"(pt_aux_lost={result.aux_lost}, pt_trace_err={result.trace_errors})",
        )
