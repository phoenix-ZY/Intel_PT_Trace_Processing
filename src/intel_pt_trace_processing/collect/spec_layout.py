from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

def warmup_tag(v: float) -> str:
    if abs(v - round(v)) < 1e-9:
        return f"{int(round(v))}s"
    return f"{v:g}s".replace(".", "p")

@dataclass
class RunCase:
    bench: str
    warmup: float
    status: str
    out_dir: str
    error: str | None = None
    metrics: dict | None = None

@dataclass
class CaseLayout:
    bench: str
    warmup: float
    out_dir: Path
    inputs_dir: Path
    intermediate_dir: Path
    report_dir: Path
    prefix: str
    sde_trace: Path
    sde_insn: Path
    perf_data: Path
    perf_script: Path
    perf_script_stderr: Path
    perf_record_stderr: Path
    perf_stat_csv: Path
    perf_stat_json: Path
    perf_insn: Path
    sde_data_analysis_json: Path
    perf_data_analysis_json: Path
    data_sim_json: Path
    sde_inst_analysis_json: Path
    perf_inst_analysis_json: Path
    inst_sim_json: Path
    feature_bundle_json: Path
    sde_log: Path
    perf_portrait_txt: Path
    perf_portrait_stderr: Path
    insn_portrait_json: Path
    trace_profile_merged_json: Path

@dataclass
class PreparedCase:
    seq: int
    layout: CaseLayout

def make_case_layout(*, bench: str, warmup_seconds: float, output_base: Path) -> CaseLayout:
    tag = warmup_tag(warmup_seconds)
    out_dir = output_base / bench / tag
    inputs_dir = out_dir / "inputs"
    intermediate_dir = out_dir / "intermediate"
    report_dir = out_dir / "report"
    for d in (inputs_dir, intermediate_dir, report_dir):
        d.mkdir(parents=True, exist_ok=True)
    prefix = f"{bench.replace('.', '_')}_{tag}"
    return CaseLayout(
        bench=bench,
        warmup=warmup_seconds,
        out_dir=out_dir,
        inputs_dir=inputs_dir,
        intermediate_dir=intermediate_dir,
        report_dir=report_dir,
        prefix=prefix,
        sde_trace=inputs_dir / f"{prefix}.sde.debugtrace.txt",
        sde_insn=intermediate_dir / f"{prefix}.sde.insn.trace.txt",
        perf_data=intermediate_dir / f"{prefix}.perf.data",
        perf_script=intermediate_dir / f"{prefix}.perf.script.txt",
        perf_script_stderr=report_dir / f"{prefix}.perf.script.stderr.txt",
        perf_record_stderr=report_dir / f"{prefix}.perf.record.stderr.txt",
        perf_stat_csv=report_dir / f"{prefix}.perf.stat.csv",
        perf_stat_json=report_dir / f"{prefix}.perf.stat.json",
        perf_insn=intermediate_dir / f"{prefix}.perf.insn.trace.txt",
        sde_data_analysis_json=report_dir / f"{prefix}.sde.data.analysis.json",
        perf_data_analysis_json=report_dir / f"{prefix}.perf.recovered.data.analysis.json",
        data_sim_json=report_dir / f"{prefix}.sde_vs_perf_recovered.data.locality.compare.json",
        sde_inst_analysis_json=report_dir / f"{prefix}.sde.inst.analysis.json",
        perf_inst_analysis_json=report_dir / f"{prefix}.perf.inst.analysis.json",
        inst_sim_json=report_dir / f"{prefix}.sde_vs_perf.inst.locality.compare.json",
        feature_bundle_json=report_dir / f"{prefix}.features.bundle.json",
        sde_log=report_dir / f"{prefix}.sde.attach.log",
        perf_portrait_txt=intermediate_dir / f"{prefix}.perf.insn.portrait.txt",
        perf_portrait_stderr=report_dir / f"{prefix}.perf.portrait.script.stderr.txt",
        insn_portrait_json=report_dir / f"{prefix}.insn.portrait.json",
        trace_profile_merged_json=report_dir / f"{prefix}.trace_profile.merged.json",
    )
