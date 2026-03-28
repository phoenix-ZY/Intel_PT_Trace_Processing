#!/usr/bin/env python3
"""
Convert `perf script --insn-trace` output into the canonical insn-trace format:

  <tid> <time>: <ip> insn: <hex bytes...>

Why:
- perf output format can vary across versions / perf script field selections.
- Our emulator `recover_mem_addrs.py` expects the canonical format above.

This converter tries to be permissive and extract:
- tid (int)
- time (float-ish token)
- ip (hex, without 0x prefix ok)
- instruction bytes (space-separated hex bytes)

If a line doesn't match, it's skipped.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path


# Common perf insn-trace patterns seen in the wild (best-effort).
# Example shapes:
#   1234  1.234567:  400123 insn: 55 48 89 e5
#   1234  1.234567:  0x400123:   55 48 89 e5
#   1234  1.234567:  400123:     55 48 89 e5
RE1 = re.compile(
    r"^\s*(?P<tid>\d+)\s+(?P<time>[\d.]+):\s+"
    r"(?P<ip>0x[0-9a-fA-F]+|[0-9a-fA-F]+)"
    r"(?:\s+insn:|\s*:)?\s+"
    r"(?P<bytes>(?:[0-9a-fA-F]{2}\s+)+[0-9a-fA-F]{2})\s*$"
)

# Fallback: sometimes perf includes comm/pid; we still try to find tid/time/ip/bytes.
#   nginx  1234 [001]  1.234: 400123 insn: 55 48 89 e5
RE2 = re.compile(
    r"^\s*(?P<comm>\S+)\s+(?P<tid>\d+)\s+\[[^\]]+\]\s+"
    r"(?P<time>[\d.]+):\s+"
    r"(?P<ip>0x[0-9a-fA-F]+|[0-9a-fA-F]+)"
    r"(?:\s+insn:|\s*:)?\s+"
    r"(?P<bytes>(?:[0-9a-fA-F]{2}\s+)+[0-9a-fA-F]{2})\s*$"
)


def normalize_ip(ip_s: str) -> str:
    ip_s = ip_s.strip()
    if ip_s.startswith("0x") or ip_s.startswith("0X"):
        return ip_s[2:]
    return ip_s


def main() -> int:
    ap = argparse.ArgumentParser(description="Convert perf insn-trace to recover_mem_addrs.py format")
    ap.add_argument("-i", "--input", type=Path, required=True, help="perf script --insn-trace output text")
    ap.add_argument("-o", "--output", type=Path, required=True, help="output canonical insn trace text")
    args = ap.parse_args()

    if not args.input.is_file():
        raise SystemExit(f"input not found: {args.input}")

    out_lines = 0
    skipped = 0
    with args.input.open("r", encoding="utf-8", errors="replace") as fp, args.output.open(
        "w", encoding="utf-8"
    ) as out:
        for line in fp:
            line = line.rstrip("\n")
            m = RE1.match(line) or RE2.match(line)
            if not m:
                skipped += 1
                continue
            tid = int(m.group("tid"))
            time = m.group("time")
            ip = normalize_ip(m.group("ip"))
            bs = " ".join(m.group("bytes").strip().split())
            out.write(f"{tid} {time}: {ip} insn: {bs}\n")
            out_lines += 1

    print(f"converted_insns: {out_lines}")
    print(f"skipped_lines: {skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

