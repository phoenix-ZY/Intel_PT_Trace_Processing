#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any

import analyze_insn_trace_portrait as insn_portrait
from export_trace_features_to_excel import write_csv, write_xlsx


def _warmup_seconds_from_tag(tag: str) -> float:
    t = tag.strip().lower()
    if not t.endswith("s"):
        return float("nan")
    core = t[:-1].replace("p", ".")
    try:
        return float(core)
    except Exception:
        return float("nan")


def flatten_feature_vector(feature_obj: dict[str, Any]) -> dict[str, float]:
    out: dict[str, float] = {}
    rd_bins = feature_obj.get("rd_bins", [])
    rd_prob = feature_obj.get("rd_prob", [])
    if isinstance(rd_bins, list) and isinstance(rd_prob, list):
        for b, p in zip(rd_bins, rd_prob):
            try:
                out[f"rd_prob::{b}"] = float(p)
            except Exception:
                continue

    st_bins = feature_obj.get("stride_bins", [])
    st_prob = feature_obj.get("stride_prob", [])
    if isinstance(st_bins, list) and isinstance(st_prob, list):
        for b, p in zip(st_bins, st_prob):
            try:
                out[f"stride_prob::{b}"] = float(p)
            except Exception:
                continue

    for k, v in feature_obj.items():
        if k in ("rd_bins", "rd_prob", "stride_bins", "stride_prob"):
            continue
        if isinstance(v, bool):
            continue
        if isinstance(v, (int, float)):
            fv = float(v)
            if math.isfinite(fv):
                out[k] = fv
    return out


def load_locality_feature_from_analysis_json(path: Path, *, access: str = "all") -> dict[str, float]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    per = obj.get("per_access", {})
    if not isinstance(per, dict):
        return {}
    aobj = per.get(access)
    if not isinstance(aobj, dict):
        return {}
    feat = aobj.get("feature")
    if not isinstance(feat, dict):
        return {}
    return flatten_feature_vector(feat)


def load_portrait_metrics(path: Path) -> dict[str, float]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    flat = insn_portrait.flatten_portrait_metrics(obj)
    out: dict[str, float] = {}
    for k, v in flat.items():
        if isinstance(v, (int, float)):
            fv = float(v)
            if math.isfinite(fv):
                out[k] = fv
    return out


def load_recover_report_metrics(path: Path) -> dict[str, float]:
    """
    Parse recover_mem_addrs_uc --report-out JSON and derive syscall features.
    """
    obj = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, float] = {}
    if isinstance(obj.get("syscall_events"), (int, float)):
        out["recover_syscall_events"] = float(obj["syscall_events"])
    syscalls = obj.get("syscalls", [])
    if not isinstance(syscalls, list):
        return out

    # Linux x86_64 syscall numbers (subset) -> coarse category.
    cat_map: dict[int, str] = {}
    for nr in (
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 20, 21,
        22, 23, 24, 25, 26, 27, 28, 29, 32, 33, 34, 35, 39, 40,
    ):
        cat_map[nr] = "file"
    for nr in (41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55):
        cat_map[nr] = "net"
    for nr in (56, 57, 58, 59, 60, 61, 62, 63, 64, 65):
        cat_map[nr] = "process"
    for nr in (96, 201, 202, 228, 229, 230, 231, 232, 233, 234):
        cat_map[nr] = "time"
    for nr in (9, 10, 11, 12, 25, 26, 27, 28, 29, 158, 159, 160):
        cat_map[nr] = "memory"

    total = 0.0
    by_cat: dict[str, float] = {}
    by_nr: list[tuple[int, float]] = []
    for ent in syscalls:
        if not isinstance(ent, dict):
            continue
        nr = ent.get("nr")
        cnt = ent.get("count")
        if not isinstance(nr, (int, float)) or not isinstance(cnt, (int, float)):
            continue
        nr_i = int(nr)
        c = float(cnt)
        if c <= 0:
            continue
        total += c
        by_nr.append((nr_i, c))
        cat = cat_map.get(nr_i, "other")
        by_cat[cat] = by_cat.get(cat, 0.0) + c

    out["recover_syscall_distinct"] = float(len(by_nr))
    out["recover_syscall_total_count"] = float(total)
    if by_nr:
        by_nr.sort(key=lambda x: x[1], reverse=True)
        out["recover_syscall_top_nr"] = float(by_nr[0][0])
        out["recover_syscall_top_count"] = float(by_nr[0][1])
    for cat, c in by_cat.items():
        out[f"recover_syscall_cat_{cat}_count"] = float(c)
        out[f"recover_syscall_cat_{cat}_ratio"] = float(c / total) if total > 0 else 0.0
    return out


def iter_cases(output_base: Path) -> list[tuple[str, str, Path, Path | None]]:
    """
    Returns list of (bench, warmup_tag, perf_data_analysis_json, perf_insn_portrait_json_or_none).

    Supports both layouts:
    - SPEC: <out>/<bench>/<warmup_tag>/report/*.perf.recovered.data.analysis.json
    - cloud: <out>/<bench>/report/*.perf.recovered.data.analysis.json
    """
    out: list[tuple[str, str, Path, Path | None]] = []
    for data_json in sorted(output_base.glob("**/report/*.perf.recovered.data.analysis.json")):
        report_dir = data_json.parent
        warmup_tag = report_dir.parent.name
        bench = report_dir.parent.parent.name
        # If layout is cloud (<bench>/report), warmup_tag would be "bench" and bench would be <out>.
        # Detect by checking that report_dir.parent.parent is output_base (cloud case).
        if report_dir.parent.parent.resolve() == output_base.resolve():
            bench = report_dir.parent.name
            warmup_tag = ""
        prefix = data_json.name.replace(".perf.recovered.data.analysis.json", "")
        portrait_json = data_json.parent / f"{prefix}.insn.portrait.json"
        out.append((bench, warmup_tag, data_json, portrait_json if portrait_json.is_file() else None))
    return out


def _merge_features(dst: dict[str, Any], src: dict[str, float]) -> None:
    """
    Merge numeric features into dst. If key exists, suffix with __dupN.
    """
    for k, v in src.items():
        if k not in dst:
            dst[k] = v
            continue
        i = 2
        while True:
            kk = f"{k}__dup{i}"
            if kk not in dst:
                dst[kk] = v
                break
            i += 1


def _strip_known_prefix(s: str, prefix: str) -> str:
    return s[len(prefix) :] if s.startswith(prefix) else s


def _classify_portrait_key(core: str) -> str:
    """
    Classify flattened portrait metric key (without leading 'portrait_') into a category.

    Categories:
      - mix: instruction mix / operand mix / barriers
      - branch: branch behavior stats
      - syscall: syscall-related (from portrait)
      - dep: register dependency distance stats (scalar + vector)
      - ipc: IPC-related (prediction target; exported last)
      - other: fallback (fold into mix by default)
    """
    if core.startswith(("mix_", "submix_", "opmix_", "barrier_")):
        return "mix"
    if core.startswith("branch_"):
        return "branch"
    if core.startswith("syscall_"):
        return "syscall"
    if core.startswith(("raw_dist", "war_dist", "waw_dist", "vec_")):
        return "dep"
    if core.startswith("ipc_"):
        return "ipc"
    return "other"


def _classify_recover_key(core: str) -> str:
    # Currently only syscall features are exported from recover report.
    if core.startswith("syscall_"):
        return "syscall"
    return "other"


def _fmt_cat_key(cat: str, name: str) -> str:
    # user wants category prefixes like: mix_, data_, inst_, branch_, syscall_, dep_, ipc_
    return f"{cat}_{name}"


def _dedup_subprefix(cat: str, core: str) -> str:
    """
    Avoid names like mix_mix_alu, branch_branch_taken_rate, ipc_ipc_total.
    If core already starts with '<cat>_', strip it for the final feature name.
    """
    p = f"{cat}_"
    while core.startswith(p):
        core = core[len(p) :]
    return core


def _predefined_cols() -> dict[str, list[str]]:
    """
    Return predefined feature columns (without the category prefix).

    The exporter will always emit these columns; missing values are filled with 0.0.
    This stabilizes feature dimensions across workloads.
    """
    rd_bins = [
        "1",
        "2",
        "3-4",
        "5-8",
        "9-16",
        "17-32",
        "33-64",
        "65-128",
        "129-256",
        "257-512",
        "513-1024",
        "1025-2048",
        "2049-4096",
        "4097-8192",
        "8193-16384",
        "16385-32768",
        "32769-65536",
        "65537-131072",
        "131073-262144",
        ">=262144",
    ]
    stride_bins = [
        "0",
        "1",
        "2-4",
        "5-16",
        "17-64",
        "65-256",
        "257-1024",
        "1025-4096",
        "4097-16384",
        "16385-65536",
        "65537-262144",
        ">=262144",
    ]
    loc_common = (
        [f"rd_prob::{b}" for b in rd_bins]
        + [f"stride_prob::{b}" for b in stride_bins]
        + [
            "rd_entropy",
            "stride_entropy",
            "rd_local_mass_le_64",
            "stride_near_mass_abs_le_1",
            "stride_far_mass_abs_gt_64",
            "stride_forward_ratio",
            "stride_backward_ratio",
        ]
    )
    loc_data = loc_common + [
        # prefetch proxies (data only)
            "prefetch_nl_accuracy_proxy",
            "prefetch_nl_coverage_proxy",
            "prefetch_nl_pollution_proxy",
            "prefetch_pc_nl_coverage_proxy_mean",
            "prefetch_pc_nl_coverage_proxy_p90",
            "prefetch_pc_nl_coverage_proxy_weighted",
            "prefetch_pc_sign_flip_rate_mean",
            "prefetch_pc_stability_proxy_mean",
            "prefetch_pc_stream_forward_le4_proxy_mean",
            "prefetch_stream_far_jump_proxy",
            "prefetch_stream_forward_le4_proxy",
            "prefetch_zero_delta_proxy",
    ]
    loc_inst = loc_common
    mix = [
        # instruction_mix fractions
        "alu",
        "branch_conditional",
        "branch_unconditional",
        "call_direct",
        "return",
        "lea",
        "compare",
        "load_store_mov",
        "mov_reg",
        "other",
        # operand_mix fractions
        "opmix_reg_to_reg",
        "opmix_mem_to_reg",
        "opmix_imm_to_reg",
        "opmix_reg_to_mem",
        "opmix_imm_to_mem",
        "opmix_imm",
        "opmix_reg",
        "opmix_none",
        # instruction_submix fractions (stable list; zeros ok)
        "submix_alu_addsub",
        "submix_alu_logic",
        "submix_alu_shift",
        "submix_alu_muldiv",
        "submix_compare",
        "submix_mov_mem",
        "submix_mov_reg",
        "submix_lea",
        "submix_branch",
        "submix_call",
        "submix_ret",
        "submix_setcc",
        "submix_cmov",
        "submix_prefix_rep",
        "submix_prefix_lock",
        "submix_barrier_fence",
        "submix_barrier_serialize",
        "submix_barrier_pause",
        "submix_syscall",
        "submix_simd_sse",
        "submix_simd_avx",
        "submix_simd_avx_xmm",
        "submix_simd_avx_other",
        "submix_simd_avx512",
        "submix_other",
    ]
    branch = [
        "conditional_per_1k",
        "unconditional_per_1k",
        "indirect_per_1k",
        "call_direct_per_1k",
        "call_indirect_per_1k",
        "return_per_1k",
        "taken_rate",
        "taken_entropy",
        "unknown_next_ip_total",
        "site_entropy_mean",
        "site_transition_rate_mean",
        "pat4_distinct",
        "pat4_top_mass",
        "pat4_entropy",
        "pat8_distinct",
        "pat8_top_mass",
        "pat8_entropy",
        "pat16_distinct",
        "pat16_top_mass",
        "pat16_entropy",
        "pat32_distinct",
        "pat32_top_mass",
        "pat32_entropy",
    ]
    # Compact syscall features (avoid redundant counts and categorical 'top_nr').
    syscall = [
        "per_1k",  # from portrait (syscall per 1k insns)
        # after dedup_subprefix('syscall', 'syscall_distinct') -> 'distinct'
        "distinct",
        "total_count",
        # after dedup_subprefix('syscall', 'syscall_cat_*_ratio') -> 'cat_*_ratio'
        "cat_file_ratio",
        "cat_net_ratio",
        "cat_memory_ratio",
        "cat_process_ratio",
        "cat_time_ratio",
        "cat_other_ratio",
    ]
    dep = [
        "raw_dist_count",
        "raw_dist_mean",
        "raw_dist_median",
        "raw_dist_bucket_1-4",
        "raw_dist_bucket_5-16",
        "raw_dist_bucket_17-64",
        "raw_dist_bucket_65+",
        "war_dist_count",
        "war_dist_mean",
        "war_dist_median",
        "war_dist_bucket_1-4",
        "war_dist_bucket_5-16",
        "war_dist_bucket_17-64",
        "war_dist_bucket_65+",
        "waw_dist_count",
        "waw_dist_mean",
        "waw_dist_median",
        "waw_dist_bucket_1-4",
        "waw_dist_bucket_5-16",
        "waw_dist_bucket_17-64",
        "waw_dist_bucket_65+",
        # vector dependency distances
        "vec_raw_dist_count",
        "vec_raw_dist_mean",
        "vec_raw_dist_median",
        "vec_war_dist_count",
        "vec_war_dist_mean",
        "vec_war_dist_median",
        "vec_waw_dist_count",
        "vec_waw_dist_mean",
        "vec_waw_dist_median",
        "vec_raw_dist_bucket_1-4",
        "vec_raw_dist_bucket_5-16",
        "vec_raw_dist_bucket_17-64",
        "vec_raw_dist_bucket_65+",
        "vec_waw_dist_bucket_1-4",
        "vec_waw_dist_bucket_5-16",
        "vec_waw_dist_bucket_17-64",
        "vec_waw_dist_bucket_65+",
        "vec_war_dist_bucket_1-4",
        "vec_war_dist_bucket_5-16",
        "vec_war_dist_bucket_17-64",
        "vec_war_dist_bucket_65+",
    ]
    ipc = ["total"]
    return {
        "mix": mix,
        "data": loc_data,
        "inst": loc_inst,
        "branch": branch,
        "syscall": syscall,
        "dep": dep,
        "ipc": ipc,
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Export full perf feature vector = recovered data+inst locality features + insn portrait metrics."
    )
    ap.add_argument(
        "--output-base",
        type=Path,
        default=Path("/home/huangtianhao/Intel_PT_Trace_Processing/outputs/spec5_sde_perf_subset"),
        help="SPEC-style output base (<bench>/<warmup>/report/...)",
    )
    ap.add_argument("--access", type=str, default="all", help="per_access key to export (default: all)")
    ap.add_argument("--xlsx-out", type=Path, default=None)
    ap.add_argument("--csv-out", type=Path, default=None)
    ap.add_argument(
        "--strict-columns",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Only export predefined feature columns (default: true) for identical schemas across datasets.",
    )
    args = ap.parse_args()

    cases = iter_cases(args.output_base)
    if not cases:
        print(f"[error] no cases found under {args.output_base}", file=sys.stderr)
        return 2

    rows: list[dict[str, Any]] = []
    predefined = _predefined_cols()
    allowed_feature_cols: set[str] = set()
    for cat, names in predefined.items():
        for n in names:
            allowed_feature_cols.add(_fmt_cat_key(cat, n))
    feature_cols_by_cat: dict[str, set[str]] = {
        "mix": set(),
        "data": set(),
        "inst": set(),
        "branch": set(),
        "syscall": set(),
        "dep": set(),
        "ipc": set(),
    }

    # IPC: keep only the global average (total insns / total cycles).
    ipc_keep = {"ipc_total"}

    for bench, tag, data_json, portrait_json in cases:
        data_feat = load_locality_feature_from_analysis_json(data_json, access=args.access)
        # perf_pipeline currently writes "<prefix>.perf.inst.analysis.json" (without "recovered" in filename).
        inst_json_candidates = [
            Path(str(data_json).replace(".perf.recovered.data.analysis.json", ".perf.inst.analysis.json")),
            Path(str(data_json).replace(".perf.recovered.data.analysis.json", ".perf.recovered.inst.analysis.json")),
        ]
        inst_json = next((p for p in inst_json_candidates if p.is_file()), inst_json_candidates[0])
        inst_feat = load_locality_feature_from_analysis_json(inst_json, access=args.access) if inst_json.is_file() else {}
        port_feat = load_portrait_metrics(portrait_json) if portrait_json is not None else {}
        recover_report = data_json.parent / data_json.name.replace(
            ".perf.recovered.data.analysis.json", ".perf.recover.report.json"
        )
        rec_feat = load_recover_report_metrics(recover_report) if recover_report.is_file() else {}

        row: dict[str, Any] = {
            "bench": bench,
            "warmup_tag": tag,
            "warmup_seconds": _warmup_seconds_from_tag(tag),
            "access": args.access,
            "data_analysis_json": str(data_json),
            "inst_analysis_json": str(inst_json) if inst_json.is_file() else "",
            "portrait_json": str(portrait_json) if portrait_json is not None else "",
        }
        # data locality features
        data_prefixed = {_fmt_cat_key("data", k): v for k, v in data_feat.items()}
        if args.strict_columns:
            data_prefixed = {k: v for k, v in data_prefixed.items() if k in allowed_feature_cols}
        _merge_features(row, data_prefixed)
        feature_cols_by_cat["data"].update(data_prefixed.keys())

        # inst locality features
        inst_prefixed = {_fmt_cat_key("inst", k): v for k, v in inst_feat.items()}
        if args.strict_columns:
            inst_prefixed = {k: v for k, v in inst_prefixed.items() if k in allowed_feature_cols}
        _merge_features(row, inst_prefixed)
        feature_cols_by_cat["inst"].update(inst_prefixed.keys())

        # portrait metrics
        for k, v in port_feat.items():
            core = _strip_known_prefix(k, "portrait_")
            cat = _classify_portrait_key(core)
            if cat == "other":
                cat = "mix"
            if core in ("lines_with_ipc_annotation", "skipped_lines", "parsed_instructions"):
                # Not useful as final model features; 'skipped_lines'/'parsed_instructions' are parsing/coverage artifacts.
                continue
            if cat == "ipc" and core not in ipc_keep:
                continue
            kk = _fmt_cat_key(cat, _dedup_subprefix(cat, core))
            if args.strict_columns and kk not in allowed_feature_cols:
                continue
            _merge_features(row, {kk: v})
            if cat in feature_cols_by_cat:
                feature_cols_by_cat[cat].add(kk)

        # recover report metrics (syscall distribution)
        for k, v in rec_feat.items():
            core = _strip_known_prefix(k, "recover_")
            cat = _classify_recover_key(core)
            if cat == "other":
                cat = "syscall"
            # Keep only compact syscall feature set.
            if cat == "syscall":
                # core is like: syscall_total_count, syscall_cat_file_ratio, ...
                keep = (
                    core in ("syscall_distinct", "syscall_total_count")
                    or (core.startswith("syscall_cat_") and core.endswith("_ratio"))
                )
                if not keep:
                    continue
            kk = _fmt_cat_key(cat, _dedup_subprefix(cat, core))
            if args.strict_columns and kk not in allowed_feature_cols:
                continue
            _merge_features(row, {kk: v})
            if cat in feature_cols_by_cat:
                feature_cols_by_cat[cat].add(kk)

        # Fill missing predefined columns with 0.0 for stable dimensions.
        for cat in ("mix", "data", "inst", "branch", "syscall", "dep", "ipc"):
            for name in predefined.get(cat, []):
                col = _fmt_cat_key(cat, name)
                if col not in row:
                    row[col] = 0.0
                feature_cols_by_cat[cat].add(col)

        rows.append(row)

    headers = [
        "bench",
        "warmup_tag",
        "warmup_seconds",
        "access",
        "data_analysis_json",
        "inst_analysis_json",
        "portrait_json",
    ]

    def _sorted_cols(cat: str) -> list[str]:
        cols = feature_cols_by_cat.get(cat, set())
        pre = [_fmt_cat_key(cat, n) for n in predefined.get(cat, [])]
        pre_set = set(pre)
        extra = sorted(c for c in cols if c not in pre_set)
        if args.strict_columns:
            return [c for c in pre if c in cols]
        return [c for c in pre if c in cols] + extra

    # Column order requested by user:
    # instruction mix, data locality, inst locality, branch, syscall, reg dependency, IPC (target) last.
    for cat in ("mix", "data", "inst", "branch", "syscall", "dep", "ipc"):
        headers.extend(_sorted_cols(cat))

    # Ensure no missing feature cells: fill absent feature keys with 0.0.
    meta_cols = {
        "bench",
        "warmup_tag",
        "warmup_seconds",
        "access",
        "data_analysis_json",
        "inst_analysis_json",
        "portrait_json",
    }
    feature_headers = [h for h in headers if h not in meta_cols]
    for row in rows:
        for h in feature_headers:
            if h not in row:
                row[h] = 0.0

    csv_out = args.csv_out or (args.output_base / "perf_full_features.csv")
    xlsx_out = args.xlsx_out or (args.output_base / "perf_full_features.xlsx")
    write_csv(csv_out, headers=headers, rows=rows)
    write_xlsx(xlsx_out, headers=headers, rows=rows, sheet_name="perf_full_features")
    print(f"[ok] cases={len(rows)} cols={len(headers)}")
    print(f"[ok] csv:  {csv_out}")
    print(f"[ok] xlsx: {xlsx_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

