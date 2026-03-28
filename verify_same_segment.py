#!/usr/bin/env python3
"""
Verify whether a PT insn trace looks like the same program segment as an SDE insn trace.

Method (stronger than one anchor + fixed offset):
  1) Rolling-hash checkpoints every --stride PT insns over a --window-wide insn-byte
     fingerprint (same spirit as align_insn_traces --ignore-ip).
  2) Search band around j ≈ pt_lo + (sde_start - pt_anchor); forward-only recovery if
     the symmetric band is empty after a large prior hit.
  3) Optional wide fallback scan (--max-fallback-scan) with earliest-hit semantics.
  4) --max-sde-jump rejects non-local hits (same byte window reused far away).
  5) Reports stretch (sde_delta / stride) and drift vs the 1:1 anchor prediction.
  6) Optional local subsequence DP on failure (--dp-refine).

Trace line format (same as align_insn_traces.py):
  <tid> <time>: <ip> insn: <hex bytes...>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import statistics
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

LINE_RE = re.compile(
    r"^\s*(?P<tid>\d+)\s+"
    r"(?P<time>[\d.]+):\s+"
    r"(?P<ip>[0-9a-fA-F]+)\s+"
    r"insn:\s+(?P<bytes>(?:[0-9a-fA-F]{2}\s*)+)\s*$"
)


def load_insn_codes(path: Path, max_insns: int | None) -> list[bytes]:
    out: list[bytes] = []
    with path.open("r", encoding="utf-8", errors="replace") as fp:
        for line in fp:
            m = LINE_RE.match(line)
            if not m:
                continue
            parts = m.group("bytes").strip().split()
            if not parts:
                continue
            out.append(bytes(int(b, 16) for b in parts))
            if max_insns is not None and len(out) >= max_insns:
                break
    return out


def u64_fp(code: bytes) -> int:
    return int.from_bytes(hashlib.blake2b(code, digest_size=8).digest(), "little")


def poly_window_hash(fps: list[int], lo: int, hi: int, mul: int, mod: int) -> int:
    """Hash fps[lo:hi] as H = sum_{t=0}^{L-1} fps[lo+t] * mul^t (mod mod)."""
    h = 0
    x = 1
    for i in range(lo, hi):
        h = (h + fps[i] * x) % mod
        x = (x * mul) % mod
    return h


def precompute_mul_pow(mul: int, w: int, mod: int) -> list[int]:
    out = [1] * (w + 1)
    for i in range(1, w + 1):
        out[i] = (out[i - 1] * mul) % mod
    return out


def rolling_collect_matches(
    sde_fps: list[int],
    sde_codes: list[bytes],
    pt_fps: list[int],
    pt_codes: list[bytes],
    pt_lo: int,
    w: int,
    search_lo: int,
    search_hi: int,
    mul: int,
    mod: int,
    mul_pow: list[int],
) -> list[int]:
    """
    All j in [search_lo, search_hi] where SDE[j:j+w] == PT[pt_lo:pt_lo+w] (byte verify).
    """
    if pt_lo + w > len(pt_codes) or search_lo < 0 or search_lo > search_hi:
        return []
    if search_hi + w > len(sde_codes):
        return []

    target = poly_window_hash(pt_fps, pt_lo, pt_lo + w, mul, mod)
    inv_mul = pow(mul, -1, mod)
    p_w1 = mul_pow[w - 1]

    hits: list[int] = []
    h = poly_window_hash(sde_fps, search_lo, search_lo + w, mul, mod)
    for j in range(search_lo, search_hi + 1):
        if h == target and _bytes_window_eq(sde_codes, pt_codes, j, pt_lo, w):
            hits.append(j)
        if j == search_hi:
            break
        fp_old = sde_fps[j]
        fp_new = sde_fps[j + w]
        h = (h - fp_old) % mod
        h = (h * inv_mul) % mod
        h = (h + fp_new * p_w1) % mod
    return hits


def _bytes_window_eq(
    sde_codes: list[bytes],
    pt_codes: list[bytes],
    sde_lo: int,
    pt_lo: int,
    w: int,
) -> bool:
    for t in range(w):
        if sde_codes[sde_lo + t] != pt_codes[pt_lo + t]:
            return False
    return True


def run_align_offset(script_dir: Path, pt: Path, sde: Path, ignore_ip: bool) -> int:
    cmd = [
        sys.executable,
        str(script_dir / "align_insn_traces.py"),
        "--pt",
        str(pt),
        "--sde",
        str(sde),
        "--mode",
        "pt-in-sde",
        "--anchor-len",
        "256",
        "--pt-start",
        "0",
        "--anchor-len-list",
        "256,128,64,32",
        "--pt-start-list",
        "0,256,1024,4096,8192,16384",
    ]
    if ignore_ip:
        cmd.append("--ignore-ip")
    p = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if p.returncode != 0:
        raise SystemExit(
            "align_insn_traces.py failed; stderr:\n" + (p.stderr or p.stdout or "")
        )
    line = (p.stdout or "").strip().splitlines()[-1] if (p.stdout or "").strip() else ""
    return int(line.strip())


def subsequence_dp_max_match(
    pt_codes: list[bytes],
    sde_codes: list[bytes],
    pt_lo: int,
    pt_hi: int,
    sde_lo: int,
    sde_hi: int,
) -> tuple[int, int]:
    """
    Longest prefix of pt[pt_lo:pt_hi) matchable as a subsequence of sde[sde_lo:sde_hi).
    Returns (matches, pt_len).
    """
    pt = pt_codes[pt_lo:pt_hi]
    sde = sde_codes[sde_lo:sde_hi]
    n, m = len(pt), len(sde)
    if n == 0:
        return 0, 0
    if m == 0:
        return 0, n
    neg = -10**9
    # dp[0][j] = 0; dp[i][0] = neg for i > 0
    prev = [0] * (m + 1)
    for i in range(1, n + 1):
        cur = [neg] * (m + 1)
        cur[0] = neg
        for j in range(1, m + 1):
            cur[j] = cur[j - 1]
            if pt[i - 1] == sde[j - 1] and prev[j - 1] != neg:
                cand = prev[j - 1] + 1
                if cand > cur[j]:
                    cur[j] = cand
        prev = cur
    best = prev[m]
    if best < 0:
        best = 0
    return best, n


@dataclass
class CheckpointResult:
    k: int
    pt_lo: int
    sde_match: int
    sde_delta_from_prev: int | None


def verify_checkpoints(
    pt_codes: list[bytes],
    sde_codes: list[bytes],
    sde_start: int,
    pt_anchor: int,
    window: int,
    stride: int,
    max_sde_gap: int,
    max_fallback_scan: int,
    max_sde_jump: int | None,
    drift_warn: int,
    mul: int,
    mod: int,
) -> tuple[list[CheckpointResult], dict[str, Any]]:
    if window <= 0 or stride <= 0:
        raise ValueError("window and stride must be > 0")
    if sde_start < 0 or sde_start + window > len(sde_codes):
        raise ValueError("sde_start or window incompatible with SDE length")

    sde_fps = [u64_fp(c) for c in sde_codes]
    pt_fps = [u64_fp(c) for c in pt_codes]
    mul_pow = precompute_mul_pow(mul, window, mod)

    results: list[CheckpointResult] = []
    last_match: int | None = None
    drifts: list[int] = []
    fallbacks = 0

    k = 0
    while True:
        pt_lo = k * stride
        if pt_lo + window > len(pt_codes):
            break

        # Hypothesis: 1:1 mapping around the initial anchor gives a soft expected SDE index.
        expected_j = (pt_lo - pt_anchor) + sde_start

        half = max(max_sde_gap // 2, stride * 8)
        if last_match is None:
            search_lo = sde_start
            search_hi = min(sde_start + max_sde_gap, len(sde_codes) - window)
        else:
            # Band around the 1:1 anchor prediction, but never move backwards in SDE.
            search_lo = max(last_match + 1, expected_j - half)
            search_hi = min(expected_j + max_sde_gap, len(sde_codes) - window)
            if search_lo > search_hi:
                # Forward-only recovery: huge last_match makes the symmetric band empty.
                search_lo = last_match + 1
                search_hi = min(last_match + max_fallback_scan, len(sde_codes) - window)
        if search_lo > search_hi:
            return results, {
                "ok": False,
                "reason": "search_range_empty",
                "failed_checkpoint": k,
                "pt_lo": pt_lo,
                "search_lo": search_lo,
                "search_hi": search_hi,
                "expected_j": expected_j,
            }

        hits = rolling_collect_matches(
            sde_fps,
            sde_codes,
            pt_fps,
            pt_codes,
            pt_lo,
            window,
            search_lo,
            search_hi,
            mul,
            mod,
            mul_pow,
        )
        used_fallback = False
        if not hits and last_match is not None:
            fb_lo = last_match + 1
            fb_hi = min(last_match + max_fallback_scan, len(sde_codes) - window)
            if fb_lo <= fb_hi:
                hits = rolling_collect_matches(
                    sde_fps,
                    sde_codes,
                    pt_fps,
                    pt_codes,
                    pt_lo,
                    window,
                    fb_lo,
                    fb_hi,
                    mul,
                    mod,
                    mul_pow,
                )
                used_fallback = bool(hits)
        if not hits:
            return results, {
                "ok": False,
                "reason": "no_match_in_gap",
                "failed_checkpoint": k,
                "pt_lo": pt_lo,
                "search_lo": search_lo,
                "search_hi": search_hi,
                "expected_j": expected_j,
            }

        if last_match is not None:
            ahead = [h for h in hits if h > last_match]
            pool = ahead if ahead else hits
            strict = [h for h in pool if h >= last_match + stride]
            pick_pool = strict if strict else pool
        else:
            pick_pool = hits
        if last_match is not None and max_sde_jump is not None:
            bounded = [h for h in pick_pool if h - last_match <= max_sde_jump]
            if not bounded:
                return results, {
                    "ok": False,
                    "reason": "exceeds_max_sde_jump",
                    "failed_checkpoint": k,
                    "pt_lo": pt_lo,
                    "last_match": last_match,
                    "max_sde_jump": max_sde_jump,
                    "candidates": pick_pool[:20],
                    "expected_j": expected_j,
                }
            pick_pool = bounded
        if used_fallback:
            fallbacks += 1
            j = min(pick_pool)
        else:
            # Prefer hits that respect a full stride step; otherwise fall back but stay near expected_j.
            j = min(pick_pool, key=lambda x: abs(x - expected_j))
        drifts.append(j - expected_j)

        delta = None if last_match is None else j - last_match
        results.append(CheckpointResult(k=k, pt_lo=pt_lo, sde_match=j, sde_delta_from_prev=delta))
        last_match = j
        k += 1

    stretches: list[float] = []
    for r in results:
        if r.sde_delta_from_prev is not None and stride > 0:
            stretches.append(r.sde_delta_from_prev / stride)

    summary: dict[str, Any] = {
        "ok": True,
        "checkpoints": len(results),
        "window": window,
        "stride": stride,
        "max_sde_gap": max_sde_gap,
        "sde_start": sde_start,
        "pt_anchor": pt_anchor,
        "fallback_checkpoints": fallbacks,
    }
    if drifts:
        ad = [abs(d) for d in drifts]
        summary["drift_vs_expected"] = {
            "min": min(drifts),
            "max": max(drifts),
            "mean": statistics.mean(drifts),
            "mean_abs": statistics.mean(ad),
            "median_abs": statistics.median(ad),
        }
        if statistics.median(ad) > drift_warn:
            summary["interpretation"] = (
                "Large median |drift| vs 1:1 anchor prediction: either PT drops a lot of insns, "
                "or these traces are not the same execution segment (repeated code / different run)."
            )
    if stretches:
        summary["stretch_sde_per_pt_stride"] = {
            "min": min(stretches),
            "max": max(stretches),
            "mean": statistics.mean(stretches),
            "median": statistics.median(stretches),
        }
    return results, summary


def main() -> int:
    ap = argparse.ArgumentParser(description="Advanced same-segment check (PT vs SDE insn traces).")
    ap.add_argument("--pt", type=Path, required=True)
    ap.add_argument("--sde", type=Path, required=True)
    ap.add_argument(
        "--sde-start",
        type=int,
        default=None,
        help="SDE index where PT[0:window) aligns (if omitted, use --offset-file or run align)",
    )
    ap.add_argument(
        "--offset-file",
        type=Path,
        default=None,
        help="File containing single integer offset = pt_start - sde_start (pt_start defaults to 0)",
    )
    ap.add_argument("--pt-start", type=int, default=0, help="PT start index implied by offset file")
    ap.add_argument(
        "--pt-anchor",
        type=int,
        default=0,
        help="PT index that sde-start refers to (usually 0; used for expected SDE index)",
    )
    ap.add_argument("--window", type=int, default=96, help="Checkpoint window (instructions)")
    ap.add_argument("--stride", type=int, default=1024, help="PT instructions between checkpoints")
    ap.add_argument(
        "--max-sde-gap",
        type=int,
        default=200_000,
        help=(
            "Half-band uses max_sde_gap//2 backward; forward search ends at expected_j + this value."
        ),
    )
    ap.add_argument(
        "--max-fallback-scan",
        type=int,
        default=6_000_000,
        help=(
            "If the tight band finds nothing, scan up to this many SDE insns after last_match "
            "and take the earliest hit (detects huge skew / repeated code)."
        ),
    )
    ap.add_argument(
        "--drift-warn",
        type=int,
        default=50_000,
        help="If median |j - expected_j| exceeds this, add an interpretation note to the report",
    )
    ap.add_argument(
        "--max-sde-jump",
        type=int,
        default=400_000,
        help=(
            "Reject checkpoint hits farther than this many SDE insns after the previous hit "
            "(catches accidental matches in unrelated code). Use 0 to disable."
        ),
    )
    ap.add_argument(
        "--max-pt-insns",
        type=int,
        default=2_000_000,
        help="Load at most this many PT insns (0 = all; needs RAM)",
    )
    ap.add_argument(
        "--max-sde-insns",
        type=int,
        default=12_000_000,
        help="Load at most this many SDE insns (0 = all)",
    )
    ap.add_argument(
        "--no-align",
        action="store_true",
        help="Do not run align_insn_traces.py when sde-start missing",
    )
    ap.add_argument(
        "--ignore-ip",
        action="store_true",
        default=True,
        help="When auto-aligning, pass --ignore-ip (default: on)",
    )
    ap.add_argument(
        "--dp-refine",
        action="store_true",
        help="On first checkpoint failure, run local subsequence DP (small, may be slow)",
    )
    ap.add_argument("--dp-pt-len", type=int, default=300, help="PT slice length for DP refine")
    ap.add_argument(
        "--dp-sde-len",
        type=int,
        default=20_000,
        help="SDE slice length for DP refine (keep * dp-pt-len modest for RAM)",
    )
    ap.add_argument("--json", type=Path, default=None, help="Write machine-readable report")
    args = ap.parse_args()

    script_dir = Path(__file__).resolve().parent
    max_pt = None if args.max_pt_insns == 0 else args.max_pt_insns
    max_sde = None if args.max_sde_insns == 0 else args.max_sde_insns

    print("Loading PT...", flush=True)
    pt_codes = load_insn_codes(args.pt, max_pt)
    print(f"  PT insns: {len(pt_codes)}", flush=True)
    print("Loading SDE...", flush=True)
    sde_codes = load_insn_codes(args.sde, max_sde)
    print(f"  SDE insns: {len(sde_codes)}", flush=True)

    sde_start = args.sde_start
    offset: int | None = None
    if sde_start is None and args.offset_file is not None:
        off_txt = args.offset_file.read_text(encoding="utf-8", errors="replace").strip().split()
        offset = int(off_txt[0])
        sde_start = args.pt_start - offset
    elif sde_start is None and not args.no_align:
        print("Running align_insn_traces.py for initial sde_start...", flush=True)
        offset = run_align_offset(script_dir, args.pt, args.sde, args.ignore_ip)
        sde_start = args.pt_start - offset
        print(f"  offset(pt_start - sde_start) = {offset}  =>  sde_start = {sde_start}", flush=True)
    elif sde_start is None:
        ap.error("Need --sde-start, or --offset-file, or allow auto align")

    mul = 0x9E3779B97F4A7C15 & ((1 << 63) - 1) | 1  # odd
    mod = (1 << 61) - 1

    results, summary = verify_checkpoints(
        pt_codes,
        sde_codes,
        sde_start=sde_start,
        pt_anchor=args.pt_anchor,
        window=args.window,
        stride=args.stride,
        max_sde_gap=args.max_sde_gap,
        max_fallback_scan=args.max_fallback_scan,
        max_sde_jump=(None if args.max_sde_jump <= 0 else args.max_sde_jump),
        drift_warn=args.drift_warn,
        mul=mul,
        mod=mod,
    )

    report: dict[str, Any] = {
        "pt": str(args.pt),
        "sde": str(args.sde),
        "sde_start": sde_start,
        "offset_pt_minus_sde": offset,
        "summary": summary,
        "checkpoints": [
            {
                "k": r.k,
                "pt_lo": r.pt_lo,
                "sde_match": r.sde_match,
                "sde_delta_from_prev": r.sde_delta_from_prev,
            }
            for r in results
        ],
    }

    if not summary.get("ok", False):
        print("CHECKPOINT VERIFICATION FAILED", file=sys.stderr)
        print(json.dumps(summary, indent=2), file=sys.stderr)
        if args.dp_refine:
            pt_lo = int(summary.get("pt_lo", 0))
            fl = int(summary.get("failed_checkpoint", 0))
            # Align dp window to failed checkpoint start
            pt_dp_lo = max(0, fl * args.stride)
            pt_dp_hi = min(len(pt_codes), pt_dp_lo + args.dp_pt_len)
            s_dp_lo = max(0, int(summary.get("search_lo", sde_start)) - 1000)
            s_dp_hi = min(len(sde_codes), s_dp_lo + args.dp_sde_len)
            print(
                f"\nDP refine: PT[{pt_dp_lo}:{pt_dp_hi}) vs SDE[{s_dp_lo}:{s_dp_hi}) ...",
                flush=True,
            )
            n_cells = (pt_dp_hi - pt_dp_lo) * (s_dp_hi - s_dp_lo)
            if n_cells > 12_000_000:
                print(
                    f"  skip DP (estimated {n_cells} cells > 12e6); shrink --dp-pt-len / --dp-sde-len",
                    flush=True,
                )
                if args.json:
                    args.json.write_text(json.dumps(report, indent=2), encoding="utf-8")
                return 2
            matches, npt = subsequence_dp_max_match(
                pt_codes, sde_codes, pt_dp_lo, pt_dp_hi, s_dp_lo, s_dp_hi
            )
            ratio = matches / max(1, npt)
            print(f"  subsequence matches: {matches}/{npt} ({100.0 * ratio:.2f}%)", flush=True)
            report["dp_refine"] = {
                "pt_lo": pt_dp_lo,
                "pt_hi": pt_dp_hi,
                "sde_lo": s_dp_lo,
                "sde_hi": s_dp_hi,
                "matches": matches,
                "pt_len": npt,
                "match_ratio": ratio,
            }
        if args.json:
            args.json.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return 2

    sc = summary.get("stretch_sde_per_pt_stride") or {}
    print("CHECKPOINT VERIFICATION OK")
    print(f"  checkpoints: {summary['checkpoints']}  window={args.window} stride={args.stride}")
    if sc:
        print(
            "  stretch (SDE advance / PT stride): "
            f"min={sc['min']:.3f} max={sc['max']:.3f} "
            f"mean={sc['mean']:.3f} median={sc['median']:.3f}"
        )
        if sc["mean"] > 1.05:
            print(
                "  note: mean > 1 suggests SDE often advances more than PT between checkpoints\n"
                "        (consistent with PT dropping instructions).",
                flush=True,
            )
        if sc["mean"] < 0.98:
            print(
                "  note: mean < 1 is unusual for a strict subsequence model; inspect false matches.",
                flush=True,
            )
    if summary.get("fallback_checkpoints", 0):
        print(
            f"  fallback wide scans used: {summary['fallback_checkpoints']} checkpoint(s) "
            "(band miss; earliest far hit — check drift_vs_expected)",
            flush=True,
        )
    dv = summary.get("drift_vs_expected") or {}
    if dv:
        print(
            f"  drift vs 1:1 expected index: mean_abs={dv['mean_abs']:.1f} "
            f"median_abs={dv['median_abs']:.1f}",
            flush=True,
        )
    if summary.get("interpretation"):
        print(f"  interpretation: {summary['interpretation']}", flush=True)

    if args.json:
        args.json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
