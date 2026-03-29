#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from statistics import mean


def warmup_tag(v: float) -> str:
    if abs(v - round(v)) < 1e-9:
        return f"{int(round(v))}s"
    return f"{v:g}s".replace(".", "p")


def load_json(path: Path) -> dict:
    if not path.is_file():
        raise FileNotFoundError(str(path))
    with path.open("r", encoding="utf-8", errors="replace") as fp:
        return json.load(fp)


def metric_summary(compare_obj: dict) -> dict:
    entries = compare_obj.get("compare_to_ref_all_stream", {})
    if not isinstance(entries, dict) or not entries:
        return {
            "pairs": 0,
            "pearson_r_min": None,
            "pearson_r_mean": None,
            "r2_min": None,
            "r2_mean": None,
            "sdp_r2_min": None,
            "sdp_r2_mean": None,
            "sdp_mae_max": None,
            "sdp_mae_mean": None,
        }
    rs: list[float] = []
    r2s: list[float] = []
    sdp_r2s: list[float] = []
    sdp_maes: list[float] = []
    for _, item in entries.items():
        vs = item.get("vs_ref", {})
        metrics = vs.get("metrics", {})
        sdp_metrics = vs.get("sdp", {}).get("metrics", {})
        r = metrics.get("pearson_r")
        r2 = metrics.get("r2")
        sr2 = sdp_metrics.get("r2")
        smae = sdp_metrics.get("mean_abs_error")
        if isinstance(r, (int, float)):
            rs.append(float(r))
        if isinstance(r2, (int, float)):
            r2s.append(float(r2))
        if isinstance(sr2, (int, float)):
            sdp_r2s.append(float(sr2))
        if isinstance(smae, (int, float)):
            sdp_maes.append(float(smae))
    return {
        "pairs": len(entries),
        "pearson_r_min": min(rs) if rs else None,
        "pearson_r_mean": mean(rs) if rs else None,
        "r2_min": min(r2s) if r2s else None,
        "r2_mean": mean(r2s) if r2s else None,
        "sdp_r2_min": min(sdp_r2s) if sdp_r2s else None,
        "sdp_r2_mean": mean(sdp_r2s) if sdp_r2s else None,
        "sdp_mae_max": max(sdp_maes) if sdp_maes else None,
        "sdp_mae_mean": mean(sdp_maes) if sdp_maes else None,
    }


def fmt(x: float | None, nd: int = 6) -> str:
    if x is None:
        return "-"
    return f"{x:.{nd}f}"


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Summarize warmup sweep RD/SDP results across warmup settings."
    )
    ap.add_argument(
        "--report-dir",
        type=Path,
        default=Path("outputs/report"),
        help="report directory (default: outputs/report)",
    )
    ap.add_argument("--base-prefix", type=str, required=True, help="base out-prefix")
    ap.add_argument(
        "--warmups",
        type=str,
        required=True,
        help="comma-separated warmups, e.g. 60,120,180",
    )
    ap.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="optional output JSON path",
    )
    args = ap.parse_args()

    warmups: list[float] = []
    for tok in args.warmups.split(","):
        tok = tok.strip()
        if not tok:
            continue
        warmups.append(float(tok))
    if not warmups:
        raise SystemExit("No valid warmups parsed from --warmups")

    rows = []
    for w in warmups:
        tag = warmup_tag(w)
        prefix = f"{args.base_prefix}.w{tag}"
        data_path = args.report_dir / f"{prefix}.segment_rd_compare.json"
        inst_path = args.report_dir / f"{prefix}.inst_segment_rd_compare.json"
        recovered_path = args.report_dir / f"{prefix}.recovered_segment_rd_compare.json"
        row = {
            "warmup_seconds": w,
            "prefix": prefix,
            "data_report": str(data_path),
            "inst_report": str(inst_path),
            "recovered_report": str(recovered_path),
        }
        try:
            data_obj = load_json(data_path)
            row["data"] = metric_summary(data_obj)
        except Exception as e:  # noqa: BLE001
            row["data_error"] = str(e)
        try:
            inst_obj = load_json(inst_path)
            row["inst"] = metric_summary(inst_obj)
        except Exception as e:  # noqa: BLE001
            row["inst_error"] = str(e)
        try:
            rec_obj = load_json(recovered_path)
            row["recovered"] = metric_summary(rec_obj)
        except Exception as e:  # noqa: BLE001
            row["recovered_error"] = str(e)
        rows.append(row)

    summary = {
        "base_prefix": args.base_prefix,
        "warmups": warmups,
        "rows": rows,
    }

    print("Warmup sweep summary (higher r2, lower sdp_mae is better):")
    print(
        "warmup | data_r2_min | inst_r2_min | rec_r2_min | data_mae_max | inst_mae_max | rec_mae_max | prefix"
    )
    for r in rows:
        data = r.get("data", {})
        inst = r.get("inst", {})
        rec = r.get("recovered", {})
        print(
            f"{r['warmup_seconds']:>6g} | "
            f"{fmt(data.get('r2_min')):>11} | "
            f"{fmt(inst.get('r2_min')):>11} | "
            f"{fmt(rec.get('r2_min')):>10} | "
            f"{fmt(data.get('sdp_mae_max')):>12} | "
            f"{fmt(inst.get('sdp_mae_max')):>12} | "
            f"{fmt(rec.get('sdp_mae_max')):>11} | "
            f"{r['prefix']}"
        )

    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"\nJSON summary: {args.json_out}")
    else:
        print("\nJSON summary not written (pass --json-out to save).")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
