#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from miic_interval_model import CpuSprLikeConfig, build_miic_inputs, predict_interval_cycles


def iter_cases(output_base: Path) -> list[dict[str, Any]]:
    """
    Reuse the same discovery logic as export_perf_full_features:
      - SPEC layout: <out>/<bench>/<warmup_tag>/report/*.perf.recovered.data.analysis.json
      - cloud layout: <out>/<bench>/report/*.perf.recovered.data.analysis.json
    """
    out: list[dict[str, Any]] = []
    for data_json in sorted(output_base.glob("**/report/*.perf.recovered.data.analysis.json")):
        report_dir = data_json.parent
        warmup_tag = report_dir.parent.name
        bench = report_dir.parent.parent.name
        if report_dir.parent.parent.resolve() == output_base.resolve():
            bench = report_dir.parent.name
            warmup_tag = ""

        prefix = data_json.name.replace(".perf.recovered.data.analysis.json", "")
        inst_json_candidates = [
            Path(str(data_json).replace(".perf.recovered.data.analysis.json", ".perf.inst.analysis.json")),
            Path(str(data_json).replace(".perf.recovered.data.analysis.json", ".perf.recovered.inst.analysis.json")),
        ]
        inst_json = next((p for p in inst_json_candidates if p.is_file()), inst_json_candidates[0])
        portrait_json = report_dir / f"{prefix}.insn.portrait.json"
        out.append(
            {
                "bench": bench,
                "warmup_tag": warmup_tag,
                "prefix": prefix,
                "data_json": data_json,
                "inst_json": inst_json,
                "portrait_json": portrait_json if portrait_json.is_file() else None,
            }
        )
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Run MIIC-inspired interval model backend on existing perf+intel_pt analysis outputs."
    )
    ap.add_argument(
        "--output-base",
        type=Path,
        required=True,
        help="Root output directory (SPEC or cloud layout) containing report/*.analysis.json files.",
    )
    ap.add_argument("--access", type=str, default="all", help="per_access key in analysis JSON (default: all)")
    ap.add_argument(
        "--spr-defaults",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Use built-in SPR-like parameter defaults (default: true).",
    )
    ap.add_argument("--dispatch-width", type=int, default=None)
    ap.add_argument("--mem-latency-cycles", type=float, default=None)
    ap.add_argument("--mlp", type=float, default=None)
    ap.add_argument("--branch-miss-slope", type=float, default=None)
    ap.add_argument("--branch-penalty-cycles", type=float, default=None)
    ap.add_argument(
        "--out-json",
        type=Path,
        default=None,
        help="Optional output JSON path (default: <output-base>/miic_interval_predictions.json).",
    )
    ap.add_argument(
        "--out-csv",
        type=Path,
        default=None,
        help="Optional output CSV path (default: <output-base>/miic_interval_predictions.csv).",
    )
    args = ap.parse_args()

    out_base = args.output_base.resolve()
    cases = iter_cases(out_base)
    if not cases:
        raise SystemExit(f"no analysis cases found under {out_base}")

    cfg = CpuSprLikeConfig()
    if args.dispatch_width is not None:
        cfg = cfg.__class__(**{**cfg.__dict__, "dispatch_width": int(args.dispatch_width)})
    if args.mem_latency_cycles is not None:
        cfg = cfg.__class__(**{**cfg.__dict__, "mem_latency_cycles": float(args.mem_latency_cycles)})
    if args.mlp is not None:
        cfg = cfg.__class__(**{**cfg.__dict__, "mlp": float(args.mlp)})
    if args.branch_miss_slope is not None:
        cfg = cfg.__class__(**{**cfg.__dict__, "branch_miss_slope": float(args.branch_miss_slope)})
    if args.branch_penalty_cycles is not None:
        cfg = cfg.__class__(**{**cfg.__dict__, "branch_penalty_cycles": float(args.branch_penalty_cycles)})

    rows: list[dict[str, Any]] = []
    for c in cases:
        data_json: Path = c["data_json"]
        inst_json: Path = c["inst_json"]
        portrait_json: Path | None = c["portrait_json"]

        inp = build_miic_inputs(
            data_analysis_json=data_json,
            inst_analysis_json=inst_json,
            portrait_json=portrait_json,
            access=str(args.access),
        )
        pred = predict_interval_cycles(inp, cfg=cfg)
        row = {
            "bench": c["bench"],
            "warmup_tag": c["warmup_tag"],
            "prefix": c["prefix"],
            "data_json": str(data_json),
            "inst_json": str(inst_json) if inst_json.is_file() else "",
            "portrait_json": str(portrait_json) if portrait_json is not None else "",
            "ipc_pred": pred.ipc,
            "cpi_pred": pred.cpi,
            "cycles_pred": pred.cycles,
            # stack
            "cycles_base": pred.stack.get("base", 0.0),
            "cycles_branch": pred.stack.get("branch", 0.0),
            "cycles_icache": pred.stack.get("icache", 0.0),
            "cycles_dcache": pred.stack.get("dcache", 0.0),
        }
        # a few derived metrics that are helpful for debugging
        for k in (
            "N",
            "mr_i_l1",
            "mr_i_l2",
            "mr_i_l3",
            "mr_d_l1",
            "mr_d_l2",
            "mr_d_l3",
            "branch_entropy",
            "branch_miss_rate_est",
            "branch_misses_est",
            "n_data_accesses_est",
            "mlp",
        ):
            if k in pred.derived:
                row[k] = pred.derived[k]
        rows.append(row)

    out_json = args.out_json or (out_base / "miic_interval_predictions.json")
    out_csv = args.out_csv or (out_base / "miic_interval_predictions.csv")
    out_json.write_text(json.dumps({"schema": "miic-interval-v1", "config": cfg.__dict__, "rows": rows}, indent=2), encoding="utf-8")

    # Stable CSV headers
    headers = [
        "bench",
        "warmup_tag",
        "prefix",
        "ipc_pred",
        "cpi_pred",
        "cycles_pred",
        "cycles_base",
        "cycles_branch",
        "cycles_icache",
        "cycles_dcache",
        "N",
        "mr_i_l1",
        "mr_i_l2",
        "mr_i_l3",
        "mr_d_l1",
        "mr_d_l2",
        "mr_d_l3",
        "branch_entropy",
        "branch_miss_rate_est",
        "branch_misses_est",
        "n_data_accesses_est",
        "mlp",
        "data_json",
        "inst_json",
        "portrait_json",
    ]
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for r in rows:
            w.writerow({h: r.get(h, "") for h in headers})

    print(f"[ok] cases={len(rows)}")
    print(f"[ok] json: {out_json}")
    print(f"[ok] csv:  {out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

