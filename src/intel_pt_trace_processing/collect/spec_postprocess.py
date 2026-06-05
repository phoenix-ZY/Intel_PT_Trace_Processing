from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from intel_pt_trace_processing.collect.spec_layout import PreparedCase, RunCase, make_case_layout
from intel_pt_trace_processing.collect.spec_trace import run_trace_phase
from intel_pt_trace_processing.compare.similarity import load_compare_metrics, maybe_write_feature_bundle
from intel_pt_trace_processing.core.commands import run_step
from intel_pt_trace_processing.core.portrait_metrics import flatten_portrait_metrics
from intel_pt_trace_processing.perf.stream import process_perf_stream

def run_one_case(
    *,
    script_dir: Path,
    spec_root: Path,
    sde_path: Path,
    bench: str,
    run_dir: Path,
    warmup_seconds: float,
    args: argparse.Namespace,
) -> RunCase:
    layout = make_case_layout(bench=bench, warmup_seconds=warmup_seconds, output_base=args.output_base)
    prepared = run_trace_phase(
        seq=0,
        layout=layout,
        script_dir=script_dir,
        spec_root=spec_root,
        sde_path=sde_path,
        run_dir=run_dir,
        args=args,
    )
    return run_post_phase(script_dir=script_dir, prepared=prepared, args=args)

def run_post_phase(*, script_dir: Path, prepared: PreparedCase, args: argparse.Namespace) -> RunCase:
    layout = prepared.layout
    skip_existing = bool(getattr(args, "skip_existing", True))
    collect_mode = str(getattr(args, "collect_mode", "pt"))

    # PMU-only mode: post phase is just "load perf stat json".
    if collect_mode == "stat":
        metrics: dict = {"mode": "perf_stat_only"}
        try:
            if layout.perf_stat_json.is_file() and layout.perf_stat_json.stat().st_size > 0:
                payload = json.loads(layout.perf_stat_json.read_text(encoding="utf-8", errors="replace"))
                metrics.update(payload.get("metrics", {}) if isinstance(payload, dict) else {})
                metrics["perf_stat_json"] = str(layout.perf_stat_json)
                metrics["perf_stat_csv"] = str(layout.perf_stat_csv)
                return RunCase(
                    bench=layout.bench,
                    warmup=layout.warmup,
                    status="ok",
                    out_dir=str(layout.out_dir),
                    metrics=metrics,
                )
            return RunCase(
                bench=layout.bench,
                warmup=layout.warmup,
                status="error",
                out_dir=str(layout.out_dir),
                error="missing perf.stat.json (collect-mode=stat)",
                metrics=metrics,
            )
        except Exception as e:
            return RunCase(
                bench=layout.bench,
                warmup=layout.warmup,
                status="error",
                out_dir=str(layout.out_dir),
                error=f"failed to read perf.stat.json: {e}",
                metrics=metrics,
            )

    def _nonempty(p: Path) -> bool:
        try:
            return p.is_file() and p.stat().st_size > 0
        except OSError:
            return False

    want_portrait = bool(getattr(args, "insn_portrait", False))

    # Fast path: reuse existing perf post-process artifacts if present.
    # IMPORTANT: if portrait is requested but portrait JSON is missing, do NOT return here;
    # the one-pass stream processor should refresh the full perf feature set.
    if (
        skip_existing
        and _nonempty(layout.perf_data_analysis_json)
        and _nonempty(layout.perf_inst_analysis_json)
        and (not want_portrait or _nonempty(layout.insn_portrait_json))
    ):
        metrics: dict = {"mode": "reuse_existing"}
        metrics["perf_inst_analysis_json"] = str(layout.perf_inst_analysis_json)
        metrics["perf_data_analysis_json"] = str(layout.perf_data_analysis_json)
        # Reuse portrait metrics if requested and available.
        if getattr(args, "insn_portrait", False) and _nonempty(layout.insn_portrait_json):
            try:
                rep = json.loads(layout.insn_portrait_json.read_text(encoding="utf-8"))
                metrics.update(flatten_portrait_metrics(rep))
                metrics["perf_insn_portrait_json"] = str(layout.insn_portrait_json)
                metrics["trace_profile_merged_json"] = str(layout.trace_profile_merged_json)
            except Exception:
                pass
        return RunCase(
            bench=layout.bench,
            warmup=layout.warmup,
            status="ok",
            out_dir=str(layout.out_dir),
            metrics=metrics,
        )

    if args.enable_sde:
        sde_analyzer = script_dir / "analyze_sde_trace_uc"
        if not sde_analyzer.exists():
            raise RuntimeError(f"missing {sde_analyzer}; run build_recover_mem_addrs_uc.sh first")
        need_sde_analyze = not (
            layout.sde_insn.exists()
            and layout.sde_inst_analysis_json.exists()
            and layout.sde_data_analysis_json.exists()
        )
        if need_sde_analyze:
            run_step(
                [
                    str(sde_analyzer),
                    "-i",
                    str(layout.sde_trace),
                    "--insn-out",
                    str(layout.sde_insn),
                    "--inst-analysis-out",
                    str(layout.sde_inst_analysis_json),
                    "--data-analysis-out",
                    str(layout.sde_data_analysis_json),
                    "--analysis-line-size",
                    str(args.line_size),
                    "--analysis-sdp-max-lines",
                    "262144",
                    "--analysis-rd-definition",
                    "stack_depth",
                    "--analysis-rd-hist-cap-lines",
                    str(args.analysis_rd_hist_cap_lines),
                    "--analysis-stride-bin-cap-lines",
                    str(args.analysis_stride_bin_cap_lines),
                ],
                verbose=args.verbose,
            )
    perf_result = process_perf_stream(
        script_dir=script_dir,
        perf_tool="perf",
        perf_data=layout.perf_data,
        prefix=layout.prefix,
        intermediate_dir=layout.intermediate_dir,
        report_dir=layout.report_dir,
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
        verbose=args.verbose,
    )

    metrics = {}
    if args.enable_sde:
        if not layout.sde_data_analysis_json.exists() or not layout.sde_inst_analysis_json.exists():
            raise RuntimeError("analyze_sde_trace_uc did not produce SDE analysis JSON outputs")
        run_step(
            [
                sys.executable,
                str(script_dir / "scripts/tools/compare_mem_trace_metrics.py"),
                "--ref-analysis",
                str(layout.sde_data_analysis_json),
                "--test-analysis",
                str(layout.perf_data_analysis_json),
                "--top-k",
                str(max(1, args.stride_top_k)),
                "--max-error-bins",
                "20",
                "--sdp-max-lines",
                "262144",
                "--json-out",
                str(layout.data_sim_json),
            ],
            verbose=args.verbose,
        )
        run_step(
            [
                sys.executable,
                str(script_dir / "scripts/tools/compare_mem_trace_metrics.py"),
                "--ref-analysis",
                str(layout.sde_inst_analysis_json),
                "--test-analysis",
                str(layout.perf_inst_analysis_json),
                "--top-k",
                str(max(1, args.stride_top_k)),
                "--max-error-bins",
                "20",
                "--sdp-max-lines",
                "262144",
                "--json-out",
                str(layout.inst_sim_json),
            ],
            verbose=args.verbose,
        )
        metrics.update(load_compare_metrics(layout.data_sim_json, metric_prefix="data_"))
        metrics.update(load_compare_metrics(layout.inst_sim_json, metric_prefix="inst_"))
        if args.write_feature_bundle:
            maybe_write_feature_bundle(
                out_path=layout.feature_bundle_json,
                sde_data_analysis=layout.sde_data_analysis_json,
                sde_inst_analysis=layout.sde_inst_analysis_json,
                perf_data_analysis=layout.perf_data_analysis_json,
                perf_inst_analysis=layout.perf_inst_analysis_json,
                data_compare=layout.data_sim_json,
                inst_compare=layout.inst_sim_json,
            )
    else:
        metrics["mode"] = "perf_only"
        metrics["perf_inst_analysis_json"] = str(layout.perf_inst_analysis_json)
        metrics["perf_data_analysis_json"] = str(layout.perf_data_analysis_json)
    metrics["perf_insn_lines"] = perf_result.insn_lines
    metrics["perf_aux_lost"] = perf_result.aux_lost
    metrics["perf_trace_errors"] = perf_result.trace_errors

    if getattr(args, "insn_portrait", False) and _nonempty(perf_result.portrait_json):
        rep = json.loads(perf_result.portrait_json.read_text(encoding="utf-8"))
        metrics.update(flatten_portrait_metrics(rep))
        metrics["perf_insn_portrait_json"] = str(perf_result.portrait_json)

    merged = perf_result.profile
    merged.update(
        {
            "bench": layout.bench,
            "warmup_seconds": layout.warmup,
            "paths": {
                "perf_data": str(layout.perf_data),
                "perf_data_analysis_json": str(perf_result.data_analysis_json),
                "perf_inst_analysis_json": str(perf_result.inst_analysis_json),
                "insn_portrait_json": str(perf_result.portrait_json),
                "stream_profile_json": str(perf_result.combined_json),
            },
        }
    )
    if args.enable_sde:
        merged["paths"].update(
            {
                "sde_data_analysis_json": str(layout.sde_data_analysis_json),
                "sde_inst_analysis_json": str(layout.sde_inst_analysis_json),
                "data_compare_json": str(layout.data_sim_json),
                "inst_compare_json": str(layout.inst_sim_json),
            }
        )
    layout.trace_profile_merged_json.write_text(json.dumps(merged, indent=2, ensure_ascii=False), encoding="utf-8")
    metrics["trace_profile_merged_json"] = str(layout.trace_profile_merged_json)

    return RunCase(bench=layout.bench, warmup=layout.warmup, status="ok", out_dir=str(layout.out_dir), metrics=metrics)
