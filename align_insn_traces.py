#!/usr/bin/env python3
"""
Align two instruction traces in the format:
  <tid> <time>: <ip> insn: <hex bytes...>

We compute an instruction-index offset by finding a unique "anchor" sequence
from SDE inside the PT trace. Output:
  offset = pt_index - sde_index

Notes:
- By default, we ignore tid and align the flattened stream order.
- For very large traces, PT is scanned streaming with a rolling hash.
"""

from __future__ import annotations

import argparse
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Iterator


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


def iter_insns(fp: IO[str]) -> Iterator[Insn]:
    for line in fp:
        m = LINE_RE.match(line)
        if not m:
            continue
        ip = int(m.group("ip"), 16)
        byte_str = m.group("bytes").strip().split()
        code = bytes(int(b, 16) for b in byte_str)
        if not code:
            continue
        yield Insn(ip=ip, code=code)


def insn_digest(insn: Insn) -> bytes:
    # 8 bytes ip + raw bytes
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


def main() -> int:
    ap = argparse.ArgumentParser(description="Align PT and SDE insn traces (anchor sequence match).")
    ap.add_argument("--pt", type=Path, required=True, help="PT-decoded insn trace text")
    ap.add_argument("--sde", type=Path, required=True, help="SDE-derived insn trace text")
    ap.add_argument(
        "--anchor-len",
        type=int,
        default=256,
        help="number of consecutive instructions used as anchor (default: 256)",
    )
    ap.add_argument(
        "--mode",
        type=str,
        default="pt-in-sde",
        choices=["pt-in-sde", "sde-in-pt"],
        help="alignment direction (default: pt-in-sde)",
    )
    ap.add_argument(
        "--pt-start",
        type=int,
        default=0,
        help="start insn index in PT stream to take anchor from (default: 0)",
    )
    ap.add_argument(
        "--sde-start",
        type=int,
        default=0,
        help="start insn index in SDE stream to take anchor from (used in mode=sde-in-pt)",
    )
    ap.add_argument(
        "--pt-scan-limit",
        type=int,
        default=0,
        help="optional max PT instructions to scan (0=no limit)",
    )
    ap.add_argument(
        "--ignore-ip",
        action="store_true",
        help="match anchors by instruction bytes only (ignore IP addresses)",
    )
    ap.add_argument(
        "--anchor-len-list",
        type=str,
        default="",
        help="optional comma-separated anchor lengths to try in order (e.g. 256,128,64,32)",
    )
    ap.add_argument(
        "--sde-start-list",
        type=str,
        default="",
        help="optional comma-separated SDE start indices to try in order (e.g. 0,256,1024,4096)",
    )
    ap.add_argument(
        "--pt-start-list",
        type=str,
        default="",
        help="optional comma-separated PT start indices to try in order (e.g. 0,256,1024,4096)",
    )
    args = ap.parse_args()

    if not args.pt.is_file():
        raise SystemExit(f"pt not found: {args.pt}")
    if not args.sde.is_file():
        raise SystemExit(f"sde not found: {args.sde}")
    if args.anchor_len <= 0:
        raise SystemExit("--anchor-len must be > 0")
    if args.pt_start < 0:
        raise SystemExit("--pt-start must be >= 0")
    if args.sde_start < 0:
        raise SystemExit("--sde-start must be >= 0")

    digest_fn = insn_digest_bytes_only if args.ignore_ip else insn_digest
    anchor_lens = [args.anchor_len]
    pt_starts = [args.pt_start]
    sde_starts = [args.sde_start]
    if args.anchor_len_list:
        anchor_lens.extend(parse_int_list_arg(args.anchor_len_list))
    if args.pt_start_list:
        pt_starts.extend(parse_int_list_arg(args.pt_start_list))
    if args.sde_start_list:
        sde_starts.extend(parse_int_list_arg(args.sde_start_list))

    # Keep order but deduplicate.
    anchor_lens = list(dict.fromkeys(anchor_lens))
    pt_starts = list(dict.fromkeys(pt_starts))
    sde_starts = list(dict.fromkeys(sde_starts))
    for al in anchor_lens:
        if al <= 0:
            raise SystemExit(f"invalid anchor-len in candidates: {al}")
    for ss in sde_starts:
        if ss < 0:
            raise SystemExit(f"invalid sde-start in candidates: {ss}")
    for ps in pt_starts:
        if ps < 0:
            raise SystemExit(f"invalid pt-start in candidates: {ps}")

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
                    print(off)
                    return 0
        raise SystemExit(
            "No alignment match found after trying all candidate (pt-start,anchor-len) pairs."
        )

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
                print(off)
                return 0
    raise SystemExit(
        "No alignment match found after trying all candidate (sde-start,anchor-len) pairs."
    )


if __name__ == "__main__":
    raise SystemExit(main())

