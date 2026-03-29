#!/usr/bin/env python3
"""
Unified PT/SDE instruction-trace alignment tool.

Input trace format:
  <tid> <time>: <ip> insn: <hex bytes...>

Two modes:
1) offset-only (default): compute one offset
   offset = pt_index - sde_index
2) verify (--verify): run checkpoint consistency checks to judge whether PT/SDE
   likely correspond to the same execution segment.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any, Iterator


LINE_RE = re.compile(
    r"^\s*(?P<tid>\d+)\s+"
    r"(?P<time>[\d.]+):\s+"
    r"(?P<ip>[0-9a-fA-F]+)\s+"
    r"insn:\s+(?P<bytes>(?:[0-9a-fA-F]{2}\s*)+)\s*$"
)


@dataclass(frozen=True)
class Insn:
    ip: int
    code: bytes


@dataclass
class CheckpointResult:
    k: int
    pt_lo: int
    sde_match: int
    sde_delta_from_prev: int | None


def iter_insns(fp: IO[str]) -> Iterator[Insn]:
    for line in fp:
        m = LINE_RE.match(line)
        if not m:
            continue
        ip = int(m.group("ip"), 16)
        code = bytes(int(b, 16) for b in m.group("bytes").strip().split())
        if not code:
            continue
        yield Insn(ip=ip, code=code)


def load_insn_codes(path: Path, max_insns: int | None) -> list[bytes]:
    out: list[bytes] = []
    with path.open("r", encoding="utf-8", errors="replace") as fp:
        for insn in iter_insns(fp):
            out.append(insn.code)
            if max_insns is not None and len(out) >= max_insns:
                break
    return out


def insn_digest(insn: Insn) -> bytes:
    return insn.ip.to_bytes(8, "little", signed=False) + insn.code


def insn_digest_bytes_only(insn: Insn) -> bytes:
    return insn.code


def sha1(x: bytes) -> bytes:
    return hashlib.sha1(x).digest()


def parse_int_list_arg(s: str) -> list[int]:
    out: list[int] = []
    for tok in s.split(","):
        tok = tok.strip()
        if not tok:
            continue
        out.append(int(tok))
    return out


def try_match_offset_sde_in_pt(
    pt_path: Path,
    sde_path: Path,
    anchor_len: int,
    sde_start: int,
    pt_scan_limit: int,
    digest_fn,
) -> int | None:
    anchor: list[Insn] = []
    with sde_path.open("r", encoding="utf-8", errors="replace") as fp:
        for i, insn in enumerate(iter_insns(fp)):
            if i < sde_start:
                continue
            anchor.append(insn)
            if len(anchor) >= anchor_len:
                break
    if len(anchor) < anchor_len:
        return None

    anchor_digests = [sha1(digest_fn(x)) for x in anchor]
    anchor_window = sha1(b"".join(anchor_digests))
    ring: list[bytes] = []
    pt_idx = -1
    with pt_path.open("r", encoding="utf-8", errors="replace") as fp:
        for insn in iter_insns(fp):
            pt_idx += 1
            ring.append(sha1(digest_fn(insn)))
            if len(ring) > anchor_len:
                ring.pop(0)
            if len(ring) < anchor_len:
                continue
            if sha1(b"".join(ring)) != anchor_window:
                if pt_scan_limit and pt_idx >= pt_scan_limit:
                    break
                continue
            if ring != anchor_digests:
                continue
            pt_start = pt_idx - anchor_len + 1
            return pt_start - sde_start
    return None


def try_match_offset_pt_in_sde(
    pt_path: Path,
    sde_path: Path,
    anchor_len: int,
    pt_start: int,
    digest_fn,
) -> int | None:
    anchor: list[Insn] = []
    with pt_path.open("r", encoding="utf-8", errors="replace") as fp:
        for i, insn in enumerate(iter_insns(fp)):
            if i < pt_start:
                continue
            anchor.append(insn)
            if len(anchor) >= anchor_len:
                break
    if len(anchor) < anchor_len:
        return None

    anchor_digests = [sha1(digest_fn(x)) for x in anchor]
    anchor_window = sha1(b"".join(anchor_digests))
    ring: list[bytes] = []
    sde_idx = -1
    with sde_path.open("r", encoding="utf-8", errors="replace") as fp:
        for insn in iter_insns(fp):
            sde_idx += 1
            ring.append(sha1(digest_fn(insn)))
            if len(ring) > anchor_len:
                ring.pop(0)
            if len(ring) < anchor_len:
                continue
            if sha1(b"".join(ring)) != anchor_window:
                continue
            if ring != anchor_digests:
                continue
            sde_start = sde_idx - anchor_len + 1
            return pt_start - sde_start
    return None


def try_resolve_offset(args: argparse.Namespace, digest_fn) -> int:
    anchor_lens = [args.anchor_len]
    pt_starts = [args.pt_start]
    sde_starts = [0 if args.sde_start is None else args.sde_start]
    if args.anchor_len_list:
        anchor_lens.extend(parse_int_list_arg(args.anchor_len_list))
    if args.pt_start_list:
        pt_starts.extend(parse_int_list_arg(args.pt_start_list))
    if args.sde_start_list:
        sde_starts.extend(parse_int_list_arg(args.sde_start_list))
    anchor_lens = list(dict.fromkeys(anchor_lens))
    pt_starts = list(dict.fromkeys(pt_starts))
    sde_starts = list(dict.fromkeys(sde_starts))

    if args.mode == "pt-in-sde":
        for pt_start in pt_starts:
            for anchor_len in anchor_lens:
                off = try_match_offset_pt_in_sde(
                    pt_path=args.pt,
                    sde_path=args.sde,
                    anchor_len=anchor_len,
                    pt_start=pt_start,
                    digest_fn=digest_fn,
                )
                if off is not None:
                    return off
        raise SystemExit("No alignment match found after trying all (pt-start,anchor-len) pairs.")

    for sde_start in sde_starts:
        for anchor_len in anchor_lens:
            off = try_match_offset_sde_in_pt(
                pt_path=args.pt,
                sde_path=args.sde,
                anchor_len=anchor_len,
                sde_start=sde_start,
                pt_scan_limit=args.pt_scan_limit,
                digest_fn=digest_fn,
            )
            if off is not None:
                return off
    raise SystemExit("No alignment match found after trying all (sde-start,anchor-len) pairs.")


def u64_fp(code: bytes) -> int:
    return int.from_bytes(hashlib.blake2b(code, digest_size=8).digest(), "little")


def poly_window_hash(fps: list[int], lo: int, hi: int, mul: int, mod: int) -> int:
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


def _bytes_window_eq(sde_codes: list[bytes], pt_codes: list[bytes], sde_lo: int, pt_lo: int, w: int) -> bool:
    for t in range(w):
        if sde_codes[sde_lo + t] != pt_codes[pt_lo + t]:
            return False
    return True


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
        expected_j = (pt_lo - pt_anchor) + sde_start
        half = max(max_sde_gap // 2, stride * 8)
        if last_match is None:
            search_lo = sde_start
            search_hi = min(sde_start + max_sde_gap, len(sde_codes) - window)
        else:
            search_lo = max(last_match + 1, expected_j - half)
            search_hi = min(expected_j + max_sde_gap, len(sde_codes) - window)
            if search_lo > search_hi:
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
                "Large median |drift| vs 1:1 anchor prediction: PT drop or non-matching segment."
            )
    if stretches:
        summary["stretch_sde_per_pt_stride"] = {
            "min": min(stretches),
            "max": max(stretches),
            "mean": statistics.mean(stretches),
            "median": statistics.median(stretches),
        }
    return results, summary


def subsequence_dp_max_match(
    pt_codes: list[bytes],
    sde_codes: list[bytes],
    pt_lo: int,
    pt_hi: int,
    sde_lo: int,
    sde_hi: int,
) -> tuple[int, int]:
    pt = pt_codes[pt_lo:pt_hi]
    sde = sde_codes[sde_lo:sde_hi]
    n, m = len(pt), len(sde)
    if n == 0:
        return 0, 0
    if m == 0:
        return 0, n
    neg = -10**9
    prev = [0] * (m + 1)
    for i in range(1, n + 1):
        cur = [neg] * (m + 1)
        for j in range(1, m + 1):
            cur[j] = cur[j - 1]
            if pt[i - 1] == sde[j - 1] and prev[j - 1] != neg:
                cur[j] = max(cur[j], prev[j - 1] + 1)
        prev = cur
    return max(0, prev[m]), n


def main() -> int:
    ap = argparse.ArgumentParser(description="Align PT/SDE traces (offset only or verify mode).")
    ap.add_argument("--pt", type=Path, required=True, help="PT-decoded insn trace text")
    ap.add_argument("--sde", type=Path, required=True, help="SDE-derived insn trace text")
    ap.add_argument("--verify", action="store_true", help="run checkpoint same-segment verification")
    ap.add_argument("--anchor-len", type=int, default=256)
    ap.add_argument("--mode", type=str, default="pt-in-sde", choices=["pt-in-sde", "sde-in-pt"])
    ap.add_argument("--pt-start", type=int, default=0)
    ap.add_argument("--sde-start", type=int, default=None)
    ap.add_argument("--pt-scan-limit", type=int, default=0)
    ap.add_argument("--ignore-ip", action="store_true", help="match by instruction bytes only")
    ap.add_argument("--anchor-len-list", type=str, default="")
    ap.add_argument("--sde-start-list", type=str, default="")
    ap.add_argument("--pt-start-list", type=str, default="")

    # verify mode options
    ap.add_argument("--offset-file", type=Path, default=None)
    ap.add_argument("--pt-anchor", type=int, default=0)
    ap.add_argument("--window", type=int, default=96)
    ap.add_argument("--stride", type=int, default=1024)
    ap.add_argument("--max-sde-gap", type=int, default=200_000)
    ap.add_argument("--max-fallback-scan", type=int, default=6_000_000)
    ap.add_argument("--drift-warn", type=int, default=50_000)
    ap.add_argument("--max-sde-jump", type=int, default=400_000)
    ap.add_argument("--max-pt-insns", type=int, default=2_000_000)
    ap.add_argument("--max-sde-insns", type=int, default=12_000_000)
    ap.add_argument("--no-auto-offset", action="store_true")
    ap.add_argument("--dp-refine", action="store_true")
    ap.add_argument("--dp-pt-len", type=int, default=300)
    ap.add_argument("--dp-sde-len", type=int, default=20_000)
    ap.add_argument("--json", type=Path, default=None, help="write machine-readable report")
    args = ap.parse_args()

    if not args.pt.is_file():
        raise SystemExit(f"pt not found: {args.pt}")
    if not args.sde.is_file():
        raise SystemExit(f"sde not found: {args.sde}")

    digest_fn = insn_digest_bytes_only if args.ignore_ip else insn_digest
    offset: int | None = None

    if not args.verify:
        print(try_resolve_offset(args, digest_fn))
        return 0

    # verify mode
    max_pt = None if args.max_pt_insns == 0 else args.max_pt_insns
    max_sde = None if args.max_sde_insns == 0 else args.max_sde_insns
    print("Loading PT...", flush=True)
    pt_codes = load_insn_codes(args.pt, max_pt)
    print(f"  PT insns: {len(pt_codes)}", flush=True)
    print("Loading SDE...", flush=True)
    sde_codes = load_insn_codes(args.sde, max_sde)
    print(f"  SDE insns: {len(sde_codes)}", flush=True)

    sde_start = args.sde_start
    if sde_start is None and args.offset_file is not None:
        off_txt = args.offset_file.read_text(encoding="utf-8", errors="replace").strip().split()
        offset = int(off_txt[0])
        sde_start = args.pt_start - offset
    elif sde_start is None and not args.no_auto_offset:
        print("Resolving initial offset...", flush=True)
        offset = try_resolve_offset(args, digest_fn)
        sde_start = args.pt_start - offset
        print(f"  offset(pt-sde)={offset} => sde_start={sde_start}", flush=True)
    elif sde_start is None:
        ap.error("Need --sde-start or --offset-file (or allow auto offset)")

    mul = 0x9E3779B97F4A7C15 & ((1 << 63) - 1) | 1
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
            fl = int(summary.get("failed_checkpoint", 0))
            pt_dp_lo = max(0, fl * args.stride)
            pt_dp_hi = min(len(pt_codes), pt_dp_lo + args.dp_pt_len)
            s_dp_lo = max(0, int(summary.get("search_lo", sde_start)) - 1000)
            s_dp_hi = min(len(sde_codes), s_dp_lo + args.dp_sde_len)
            n_cells = (pt_dp_hi - pt_dp_lo) * (s_dp_hi - s_dp_lo)
            if n_cells <= 12_000_000:
                matches, npt = subsequence_dp_max_match(
                    pt_codes, sde_codes, pt_dp_lo, pt_dp_hi, s_dp_lo, s_dp_hi
                )
                report["dp_refine"] = {
                    "pt_lo": pt_dp_lo,
                    "pt_hi": pt_dp_hi,
                    "sde_lo": s_dp_lo,
                    "sde_hi": s_dp_hi,
                    "matches": matches,
                    "pt_len": npt,
                    "match_ratio": matches / max(1, npt),
                }
        if args.json:
            args.json.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return 2

    print("CHECKPOINT VERIFICATION OK")
    print(f"  checkpoints={summary['checkpoints']} window={args.window} stride={args.stride}")
    dv = summary.get("drift_vs_expected") or {}
    if dv:
        print(f"  drift mean_abs={dv['mean_abs']:.1f} median_abs={dv['median_abs']:.1f}")
    if args.json:
        args.json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

