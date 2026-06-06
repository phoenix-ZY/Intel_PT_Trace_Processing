#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from intel_pt_trace_processing.core.feature_groups import FEATURE_GROUP_ORDER, predefined_feature_groups
from intel_pt_trace_processing.core.features import load_json_object
from export_trace_features_to_excel import write_csv, write_xlsx


def _warmup_seconds_from_tag(tag: str) -> float:
    text = tag.strip().lower()
    if not text.endswith("s"):
        return float("nan")
    try:
        return float(text[:-1].replace("p", "."))
    except ValueError:
        return float("nan")


def _feature_col(group: str, name: str) -> str:
    return f"{group}_{name}"


def _number_or_zero(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    out = float(value)
    return out if math.isfinite(out) else 0.0


def iter_cases(output_base: Path) -> list[tuple[str, str, Path]]:
    cases: list[tuple[str, str, Path]] = []
    for profile_json in sorted(output_base.glob("**/report/*.trace_profile.json")):
        if profile_json.name.endswith(".sde.trace_profile.json"):
            continue
        report_dir = profile_json.parent
        warmup_tag = report_dir.parent.name
        bench = report_dir.parent.parent.name
        if report_dir.parent.parent.resolve() == output_base.resolve():
            bench = report_dir.parent.name
            warmup_tag = ""
        cases.append((bench, warmup_tag, profile_json))
    return cases


def build_row(
    *,
    bench: str,
    warmup_tag: str,
    profile_json: Path,
    predefined: dict[str, list[str]],
    strict_columns: bool,
) -> dict[str, Any] | None:
    profile = load_json_object(profile_json)
    features = profile.get("features")
    if not isinstance(features, dict):
        return None
    row: dict[str, Any] = {
        "bench": bench,
        "warmup_tag": warmup_tag,
        "warmup_seconds": _warmup_seconds_from_tag(warmup_tag),
        "trace_profile_json": str(profile_json),
    }
    for group in FEATURE_GROUP_ORDER:
        values = features.get(group)
        if not isinstance(values, dict):
            values = {}
        names = list(predefined.get(group, []))
        if not strict_columns:
            extra = sorted(str(name) for name in values if str(name) not in set(names))
            names.extend(extra)
        for name in names:
            row[_feature_col(group, name)] = _number_or_zero(values.get(name, 0.0))
    return row


def main() -> int:
    parser = argparse.ArgumentParser(description="Export trace-profile-v2 feature groups to CSV/XLSX.")
    parser.add_argument(
        "--output-base",
        type=Path,
        default=Path("/home/huangtianhao/Intel_PT_Trace_Processing/outputs/spec5_sde_perf_subset"),
        help="Output base containing **/report/*.trace_profile.json files.",
    )
    parser.add_argument("--access", type=str, default="all", help="Deprecated; accepted for runner compatibility.")
    parser.add_argument("--xlsx-out", type=Path, default=None)
    parser.add_argument("--csv-out", type=Path, default=None)
    parser.add_argument(
        "--strict-columns",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Only export predefined feature dimensions for stable schemas.",
    )
    args = parser.parse_args()

    cases = iter_cases(args.output_base)
    if not cases:
        print(f"[error] no cases found under {args.output_base}", file=sys.stderr)
        return 2

    predefined = predefined_feature_groups()
    rows: list[dict[str, Any]] = []
    for bench, warmup_tag, profile_json in cases:
        row = build_row(
            bench=bench,
            warmup_tag=warmup_tag,
            profile_json=profile_json,
            predefined=predefined,
            strict_columns=args.strict_columns,
        )
        if row is not None:
            rows.append(row)

    if not rows:
        print(f"[error] no trace-profile-v2 rows exported under {args.output_base}", file=sys.stderr)
        return 2

    headers = ["bench", "warmup_tag", "warmup_seconds", "trace_profile_json"]
    for group in FEATURE_GROUP_ORDER:
        cols = [_feature_col(group, name) for name in predefined.get(group, [])]
        if not args.strict_columns:
            seen = set(cols)
            extras = sorted({
                key
                for row in rows
                for key in row
                if key.startswith(f"{group}_") and key not in seen
            })
            cols.extend(extras)
        headers.extend(cols)

    for row in rows:
        for header in headers:
            row.setdefault(header, 0.0)

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
