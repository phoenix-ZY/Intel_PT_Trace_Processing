from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from intel_pt_trace_processing.collect.spec_layout import PreparedCase, RunCase, make_case_layout
from intel_pt_trace_processing.collect.spec_trace import run_trace_phase
from intel_pt_trace_processing.compare.similarity import load_compare_metrics, maybe_write_feature_bundle
from intel_pt_trace_processing.core.commands import run_step
from intel_pt_trace_processing.core.features import (
    build_trace_profile,
    health_view,
    load_json_object,
    write_trace_profile,
)
from intel_pt_trace_processing.tools.flatten import flatten_trace_profile
from intel_pt_trace_processing.perf.selection import load_selection_sidecar
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
    selection = load_selection_sidecar(layout.perf_data)
    if selection is None:
        raise RuntimeError(f"missing trace selection metadata for {layout.perf_data}")
    target_pid = None
    if selection and selection.get("mode") == "process_tree":
        root_pid = selection.get("root_pid")
        if isinstance(root_pid, int) and root_pid > 0:
            target_pid = str(root_pid)

    def _profile_healthy(path: Path) -> bool:
        if not _nonempty(path):
            return False
        profile = load_json_object(path)
        health = health_view(profile)
        if isinstance(health, dict) and int(health.get("insn_lines", health.get("parsed_lines", 0)) or 0) > 0:
            return True
        features = profile.get("features", {})
        return isinstance(features, dict) and bool(features.get("data_memory"))

    def _profile_selection_matches(path: Path) -> bool:
        if target_pid is None:
            return True
        profile = load_json_object(path)
        metadata = profile.get("metadata", {}) if isinstance(profile, dict) else {}
        actual = metadata.get("trace_selection", {}) if isinstance(metadata, dict) else {}
        return isinstance(actual, dict) and actual.get("root_pid") == int(target_pid)

    if (
        skip_existing
        and _profile_healthy(layout.perf_trace_profile_json)
        and _profile_selection_matches(layout.perf_trace_profile_json)
    ):
        sde_ready = not args.enable_sde or _nonempty(layout.sde_trace_profile_json)
        compare_ready = not args.enable_sde or _nonempty(layout.data_sim_json)
        if sde_ready and compare_ready:
            profile = load_json_object(layout.perf_trace_profile_json)
            metrics: dict = {
                "mode": "reuse_existing",
                "trace_profile_json": str(layout.perf_trace_profile_json),
            }
            health = health_view(profile)
            if isinstance(health, dict):
                metrics["perf_insn_lines"] = int(health.get("insn_lines", health.get("parsed_lines", 0)) or 0)
                metrics["perf_aux_lost"] = int(health.get("aux_lost", 0) or 0)
                metrics["perf_trace_errors"] = int(health.get("trace_errors", 0) or 0)
            if want_portrait:
                metrics.update(flatten_trace_profile(profile))
            if args.enable_sde:
                metrics.update(load_compare_metrics(layout.data_sim_json, metric_prefix="data_"))
                metrics["sde_trace_profile_json"] = str(layout.sde_trace_profile_json)
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
        need_sde_analyze = not _nonempty(layout.sde_trace_profile_json)
        if need_sde_analyze:
            run_step(
                [
                    str(sde_analyzer),
                    "-i",
                    str(layout.sde_trace),
                    "--insn-out",
                    str(layout.sde_insn),
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
            sde_profile = build_trace_profile(
                source_kind="sde",
                source_path=layout.sde_trace,
                prefix=layout.prefix,
                data_locality=load_json_object(layout.sde_data_analysis_json),
                inst_locality=None,
                insn_portrait=None,
                recover_report=None,
                health={},
                artifacts={
                    "sde_trace": layout.sde_trace,
                    "instruction_trace": layout.sde_insn,
                    "data_analysis_json": layout.sde_data_analysis_json,
                },
                metadata={"bench": layout.bench, "warmup_seconds": layout.warmup},
            )
            write_trace_profile(layout.sde_trace_profile_json, sde_profile)
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
        target_pid=target_pid,
        target_pid_include_descendants=True,
        metadata={"bench": layout.bench, "warmup_seconds": layout.warmup},
    )

    metrics = {}
    if args.enable_sde:
        if not layout.sde_trace_profile_json.exists():
            raise RuntimeError("SDE analysis did not produce trace_profile.json")
        run_step(
            [
                sys.executable,
                str(script_dir / "scripts/tools/compare_mem_trace_metrics.py"),
                "--ref-profile",
                str(layout.sde_trace_profile_json),
                "--test-profile",
                str(perf_result.trace_profile_json),
                "--memory",
                "data",
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
        metrics.update(load_compare_metrics(layout.data_sim_json, metric_prefix="data_"))
        if args.write_feature_bundle:
            maybe_write_feature_bundle(
                out_path=layout.feature_bundle_json,
                sde_profile=layout.sde_trace_profile_json,
                perf_profile=perf_result.trace_profile_json,
                data_compare=layout.data_sim_json,
            )
    else:
        metrics["mode"] = "perf_only"
        metrics["trace_profile_json"] = str(perf_result.trace_profile_json)
    metrics["perf_insn_lines"] = perf_result.insn_lines
    metrics["perf_aux_lost"] = perf_result.aux_lost
    metrics["perf_trace_errors"] = perf_result.trace_errors

    perf_profile = perf_result.profile
    if getattr(args, "insn_portrait", False):
        metrics.update(flatten_trace_profile(perf_profile))

    metrics["trace_profile_json"] = str(perf_result.trace_profile_json)
    if args.enable_sde:
        metrics["sde_trace_profile_json"] = str(layout.sde_trace_profile_json)

    return RunCase(bench=layout.bench, warmup=layout.warmup, status="ok", out_dir=str(layout.out_dir), metrics=metrics)
