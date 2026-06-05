#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import re
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape as xml_escape


def _warmup_seconds_from_tag(tag: str) -> float:
    # tag format from run_spec5_sde_perf_similarity.py warmup_tag(): "30s" or "12p5s".
    t = tag.strip().lower()
    if not t.endswith("s"):
        raise ValueError(f"bad warmup tag: {tag}")
    core = t[:-1].replace("p", ".")
    return float(core)


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
        if isinstance(v, (int, float)) and math.isfinite(float(v)):
            out[k] = float(v)
    return out


def _sanitize_sheet_name(name: str) -> str:
    # Excel sheet name constraints.
    bad = r'[:\\/?*\[\]]'
    n = re.sub(bad, "_", name)
    n = n.strip()
    if not n:
        n = "Sheet1"
    return n[:31]


def _col_letter(idx0: int) -> str:
    # 0 -> A
    n = idx0 + 1
    s = ""
    while n > 0:
        n, r = divmod(n - 1, 26)
        s = chr(ord("A") + r) + s
    return s


def _cell_xml(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return f'<c t="b"><v>{1 if value else 0}</v></c>'
    if isinstance(value, (int, float)):
        try:
            f = float(value)
        except Exception:
            pass
        else:
            if math.isfinite(f):
                # Number cell
                # Keep as raw numeric (no formatting) to avoid locale issues.
                if isinstance(value, int) or (isinstance(value, float) and value.is_integer()):
                    return f"<c><v>{int(f)}</v></c>"
                return f"<c><v>{f}</v></c>"
    # Inline string cell
    s = str(value)
    # Excel XML has issues with some control chars; keep it simple.
    s = "".join(ch for ch in s if ch == "\t" or ch == "\n" or ch == "\r" or ord(ch) >= 0x20)
    return f'<c t="inlineStr"><is><t xml:space="preserve">{xml_escape(s)}</t></is></c>'


def write_xlsx(path: Path, *, headers: list[str], rows: list[dict[str, Any]], sheet_name: str = "features") -> None:
    sheet_name = _sanitize_sheet_name(sheet_name)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Build sheet XML with inline strings (no sharedStrings.xml).
    # Note: We always output a dense rectangular region: headers + rows in same order.
    data_rows: list[list[Any]] = []
    data_rows.append(headers)
    for r in rows:
        data_rows.append([r.get(h, "") for h in headers])

    sheet_lines: list[str] = []
    sheet_lines.append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>')
    sheet_lines.append(
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
    )
    sheet_lines.append("<sheetData>")
    for ridx, row in enumerate(data_rows, start=1):
        sheet_lines.append(f'<row r="{ridx}">')
        for cidx0, v in enumerate(row):
            ref = f"{_col_letter(cidx0)}{ridx}"
            cell = _cell_xml(v)
            if cell:
                # Insert cell reference attribute.
                if cell.startswith("<c"):
                    cell = cell.replace("<c", f'<c r="{ref}"', 1)
                sheet_lines.append(cell)
        sheet_lines.append("</row>")
    sheet_lines.append("</sheetData>")
    sheet_lines.append("</worksheet>")
    sheet_xml = "\n".join(sheet_lines) + "\n"

    content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
</Types>
"""

    rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>
"""

    workbook = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="{xml_escape(sheet_name)}" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>
"""

    workbook_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>
"""

    # Minimal style sheet (required by some readers).
    styles = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="1"><font><sz val="11"/><color theme="1"/><name val="Calibri"/><family val="2"/></font></fonts>
  <fills count="1"><fill><patternFill patternType="none"/></fill></fills>
  <borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs>
  <cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>
"""

    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", rels)
        z.writestr("xl/workbook.xml", workbook)
        z.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        z.writestr("xl/worksheets/sheet1.xml", sheet_xml)
        z.writestr("xl/styles.xml", styles)


def write_csv(path: Path, *, headers: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    lines.append(",".join(_csv_escape(h) for h in headers))
    for r in rows:
        lines.append(",".join(_csv_escape(r.get(h, "")) for h in headers))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _csv_escape(v: Any) -> str:
    s = "" if v is None else str(v)
    if any(ch in s for ch in [",", '"', "\n", "\r"]):
        s = s.replace('"', '""')
        return f'"{s}"'
    return s


@dataclass
class BundleRow:
    bench: str
    warmup_tag: str
    warmup_seconds: float
    bundle_path: Path
    bundle: dict[str, Any]


def load_bundle_rows(output_base: Path) -> list[BundleRow]:
    rows: list[BundleRow] = []
    for bundle_path in sorted(output_base.glob("*/*/report/*.features.bundle.json")):
        # expected: <out>/<bench>/<tag>/report/<prefix>.features.bundle.json
        try:
            tag = bundle_path.parents[1].name
            bench = bundle_path.parents[2].name
            warmup_seconds = _warmup_seconds_from_tag(tag)
            obj = json.loads(bundle_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        rows.append(
            BundleRow(
                bench=bench,
                warmup_tag=tag,
                warmup_seconds=warmup_seconds,
                bundle_path=bundle_path,
                bundle=obj,
            )
        )
    return rows


def pick_representative_bundle_per_bench(rows: list[BundleRow]) -> list[BundleRow]:
    """
    The user treats 15s/30s as equivalent for each benchmark, so pick one representative
    bundle per bench. We choose the largest warmup_seconds; tie-breaker: lexicographically
    larger warmup_tag.
    """
    best: dict[str, BundleRow] = {}
    for r in rows:
        cur = best.get(r.bench)
        if cur is None:
            best[r.bench] = r
            continue
        if r.warmup_seconds > cur.warmup_seconds:
            best[r.bench] = r
            continue
        if r.warmup_seconds == cur.warmup_seconds and r.warmup_tag > cur.warmup_tag:
            best[r.bench] = r
            continue
    return [best[k] for k in sorted(best)]


def bundle_to_flat_row(br: BundleRow) -> dict[str, Any]:
    b = br.bundle
    out: dict[str, Any] = {
        "bench": br.bench,
        "warmup_tag": br.warmup_tag,
        "warmup_seconds": br.warmup_seconds,
        "bundle_path": str(br.bundle_path),
        "schema": b.get("schema", ""),
        "line_size": b.get("line_size", ""),
        "rd_definition": b.get("rd_definition", ""),
        "rd_hist_cap_lines": b.get("rd_hist_cap_lines", ""),
        "stride_bin_cap_lines": b.get("stride_bin_cap_lines", ""),
        "data_ref_path": b.get("data", {}).get("ref_path", ""),
        "data_test_path": b.get("data", {}).get("test_path", ""),
        "inst_ref_path": b.get("inst", {}).get("ref_path", ""),
        "inst_test_path": b.get("inst", {}).get("test_path", ""),
    }

    for kind in ("data", "inst"):
        block = b.get(kind, {})
        if not isinstance(block, dict):
            continue
        # ---- raw features (ref/test) ----
        for side, k in (("ref", "ref_features"), ("test", "test_features")):
            feats = block.get(k, {})
            if not isinstance(feats, dict):
                continue
            for access, feature_obj in feats.items():
                if not isinstance(feature_obj, dict):
                    continue
                flat = flatten_feature_vector(feature_obj)
                for dim, val in flat.items():
                    out[f"{kind}_{side}_{access}__{dim}"] = val

        # ---- compare metrics stored in bundle ----
        fm = block.get("feature_metrics", {})
        if isinstance(fm, dict):
            for access, access_obj in fm.items():
                if isinstance(access_obj, dict):
                    for mk, mv in access_obj.items():
                        if isinstance(mv, (int, float)) and math.isfinite(float(mv)):
                            out[f"{kind}_feature_metric_{access}__{mk}"] = float(mv)

        ovs = block.get("overall_vector_similarity", {})
        if isinstance(ovs, dict):
            for access, access_obj in ovs.items():
                if not isinstance(access_obj, dict):
                    continue
                dims = access_obj.get("dimensions")
                if isinstance(dims, int):
                    out[f"{kind}_overall_{access}__dimensions"] = dims
                metrics = access_obj.get("metrics", {})
                if isinstance(metrics, dict):
                    for mk, mv in metrics.items():
                        if mk == "overall_score_components":
                            comps = mv
                            if isinstance(comps, dict):
                                for ck, cv in comps.items():
                                    if isinstance(cv, (int, float)) and math.isfinite(float(cv)):
                                        out[f"{kind}_overall_{access}__component_{ck}"] = float(cv)
                            continue
                        if isinstance(mv, (int, float)) and math.isfinite(float(mv)):
                            out[f"{kind}_overall_{access}__{mk}"] = float(mv)
                led = access_obj.get("largest_error_dims", [])
                if isinstance(led, list) and led and isinstance(led[0], dict):
                    out[f"{kind}_overall_{access}__top1_dim"] = led[0].get("dimension", "")
                    out[f"{kind}_overall_{access}__top1_abs_diff"] = led[0].get("abs_diff", "")
                    top3 = [x.get("dimension", "") for x in led[:3] if isinstance(x, dict) and x.get("dimension")]
                    out[f"{kind}_overall_{access}__top3_dims"] = "|".join(top3)

    return out


def bundle_to_long_data_feature_rows(br: BundleRow) -> list[dict[str, Any]]:
    b = br.bundle
    data = b.get("data", {})
    if not isinstance(data, dict):
        return []

    ref_feats = data.get("ref_features", {})
    test_feats = data.get("test_features", {})
    if not isinstance(ref_feats, dict) or not isinstance(test_feats, dict):
        return []

    out_rows: list[dict[str, Any]] = []
    for access in sorted(set(ref_feats.keys()) | set(test_feats.keys())):
        rf = ref_feats.get(access)
        tf = test_feats.get(access)
        rf_flat = flatten_feature_vector(rf) if isinstance(rf, dict) else {}
        tf_flat = flatten_feature_vector(tf) if isinstance(tf, dict) else {}
        dims = sorted(set(rf_flat.keys()) | set(tf_flat.keys()))
        for dim in dims:
            out_rows.append(
                {
                    "bench": br.bench,
                    "access": access,
                    "source": "sde_ref",
                    "warmup_tag": br.warmup_tag,
                    "warmup_seconds": br.warmup_seconds,
                    "feature_dim": dim,
                    "value": rf_flat.get(dim, ""),
                }
            )
            out_rows.append(
                {
                    "bench": br.bench,
                    "access": access,
                    "source": "perf_recovered",
                    "warmup_tag": br.warmup_tag,
                    "warmup_seconds": br.warmup_seconds,
                    "feature_dim": dim,
                    "value": tf_flat.get(dim, ""),
                }
            )
    return out_rows


def bundle_to_wide_data_2rows(br: BundleRow, *, access: str = "all") -> tuple[dict[str, Any], dict[str, Any]] | None:
    b = br.bundle
    data = b.get("data", {})
    if not isinstance(data, dict):
        return None
    ref_feats = data.get("ref_features", {})
    test_feats = data.get("test_features", {})
    if not isinstance(ref_feats, dict) or not isinstance(test_feats, dict):
        return None
    rf = ref_feats.get(access)
    tf = test_feats.get(access)
    if not isinstance(rf, dict) or not isinstance(tf, dict):
        return None

    rf_flat = flatten_feature_vector(rf)
    tf_flat = flatten_feature_vector(tf)
    dims = sorted(set(rf_flat.keys()) | set(tf_flat.keys()))

    base = {
        "bench": br.bench,
        "access": access,
        "warmup_tag": br.warmup_tag,
        "warmup_seconds": br.warmup_seconds,
    }
    sde_row: dict[str, Any] = dict(base)
    sde_row["source"] = "sde_ref"
    rec_row: dict[str, Any] = dict(base)
    rec_row["source"] = "perf_recovered"
    for d in dims:
        sde_row[d] = rf_flat.get(d, "")
        rec_row[d] = tf_flat.get(d, "")
    return sde_row, rec_row


def main() -> int:
    ap = argparse.ArgumentParser(description="Export SDE vs perf per-benchmark feature vectors to Excel.")
    ap.add_argument(
        "--output-base",
        type=Path,
        default=Path("/home/huangtianhao/Intel_PT_Trace_Processing/outputs/spec5_sde_perf_subset"),
        help="outputs directory containing <bench>/<warmup>/report/*.features.bundle.json",
    )
    ap.add_argument(
        "--mode",
        choices=["wide", "long-data", "wide-data-2rows"],
        default="long-data",
        help=(
            "wide: one row per (bench,warmup) with many columns; "
            "long-data: only data features, 2 rows per (bench,feature_dim) [sde_ref/perf_recovered]; "
            "wide-data-2rows: per bench output 2 rows (sde_ref + perf_recovered), columns are all data feature dims"
        ),
    )
    ap.add_argument(
        "--xlsx-out",
        type=Path,
        default=None,
        help="output .xlsx path (default depends on --mode)",
    )
    ap.add_argument(
        "--csv-out",
        type=Path,
        default=None,
        help="output .csv path (default depends on --mode)",
    )
    args = ap.parse_args()

    output_base: Path = args.output_base
    bundles_all = load_bundle_rows(output_base)
    bundles = pick_representative_bundle_per_bench(bundles_all)
    if not bundles:
        print(f"[error] no bundles found under: {output_base}", file=sys.stderr)
        return 2

    if args.mode == "wide":
        flat_rows = [bundle_to_flat_row(b) for b in bundles]
        # Stable header order: key columns first, then the rest sorted.
        fixed = [
            "bench",
            "warmup_tag",
            "warmup_seconds",
            "bundle_path",
            "schema",
            "line_size",
            "rd_definition",
            "rd_hist_cap_lines",
            "stride_bin_cap_lines",
            "data_ref_path",
            "data_test_path",
            "inst_ref_path",
            "inst_test_path",
        ]
        all_keys: set[str] = set()
        for r in flat_rows:
            all_keys.update(r.keys())
        rest = sorted(k for k in all_keys if k not in fixed)
        headers = fixed + rest

        xlsx_out = args.xlsx_out or (output_base / "trace_features_wide.xlsx")
        csv_out = args.csv_out or (output_base / "trace_features_wide.csv")

        write_csv(csv_out, headers=headers, rows=flat_rows)
        write_xlsx(xlsx_out, headers=headers, rows=flat_rows, sheet_name="trace_features_wide")
        print(f"[ok] benches={len(bundles)} rows={len(flat_rows)} cols={len(headers)}")
        print(f"[ok] picked one warmup per bench (from {len(bundles_all)} bundles)")
        print(f"[ok] csv:  {csv_out}")
        print(f"[ok] xlsx: {xlsx_out}")
        return 0

    if args.mode == "wide-data-2rows":
        access = "all"
        rows: list[dict[str, Any]] = []
        dims_all: set[str] = set()
        for b in bundles:
            two = bundle_to_wide_data_2rows(b, access=access)
            if two is None:
                continue
            sde_row, rec_row = two
            rows.append(sde_row)
            rows.append(rec_row)
            for k in sde_row.keys():
                if k not in ("bench", "access", "source", "warmup_tag", "warmup_seconds"):
                    # candidate feature dim, but avoid metadata columns
                    if k not in ("bench", "access", "source", "warmup_tag", "warmup_seconds"):
                        pass
            # Just union from flattened vectors directly to avoid picking up metadata.
            dims_all.update(
                k
                for k in sde_row.keys()
                if k
                and k
                not in ("bench", "access", "source", "warmup_tag", "warmup_seconds")
            )
            dims_all.update(
                k
                for k in rec_row.keys()
                if k
                and k
                not in ("bench", "access", "source", "warmup_tag", "warmup_seconds")
            )

        if not rows:
            print("[error] no wide-data-2rows rows produced", file=sys.stderr)
            return 3

        fixed = ["bench", "access", "source"]
        # User requested only features; keep warmup info out by default.
        feature_cols = sorted(dims_all)
        headers = fixed + feature_cols

        xlsx_out = args.xlsx_out or (output_base / "trace_features_data_wide2.xlsx")
        csv_out = args.csv_out or (output_base / "trace_features_data_wide2.csv")
        write_csv(csv_out, headers=headers, rows=rows)
        write_xlsx(xlsx_out, headers=headers, rows=rows, sheet_name="data_features_wide2")
        print(f"[ok] benches={len(bundles)} rows={len(rows)} cols={len(headers)}")
        print(f"[ok] picked one warmup per bench (from {len(bundles_all)} bundles)")
        print(f"[ok] csv:  {csv_out}")
        print(f"[ok] xlsx: {xlsx_out}")
        return 0

    # long-data mode (requested)
    long_rows: list[dict[str, Any]] = []
    for b in bundles:
        long_rows.extend(bundle_to_long_data_feature_rows(b))
    if not long_rows:
        print("[error] no long rows produced (check bundle structure)", file=sys.stderr)
        return 3

    headers = ["bench", "access", "source", "warmup_tag", "warmup_seconds", "feature_dim", "value"]
    xlsx_out = args.xlsx_out or (output_base / "trace_features_data_long.xlsx")
    csv_out = args.csv_out or (output_base / "trace_features_data_long.csv")

    write_csv(csv_out, headers=headers, rows=long_rows)
    write_xlsx(xlsx_out, headers=headers, rows=long_rows, sheet_name="data_features_long")
    print(f"[ok] benches={len(bundles)} dims_rows={len(long_rows)} cols={len(headers)}")
    print(f"[ok] picked one warmup per bench (from {len(bundles_all)} bundles)")
    print(f"[ok] csv:  {csv_out}")
    print(f"[ok] xlsx: {xlsx_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

