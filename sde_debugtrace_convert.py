#!/usr/bin/env python3
"""
Convert Intel SDE debugtrace output into:
1) a "real" memory-access JSONL stream (for direct reuse-distance stats)
2) an instruction-bytes trace compatible with recover_mem_addrs.py

Input: SDE debugtrace output with -dt_print_tid 1 and -dt_rawinst 1, e.g.:
  TID0: Read 0x00000008 = *(UINT32*)0x7f... 
  TID0: INS 0x00007f... [488b10] BASE mov rdx, qword ptr [rax] | ...
  TID0: Write *(UINT64*)0x7f... = 0x...

Outputs:
  - mem JSONL: {"access": "read"|"write", "addr": "0x...", "size": N}
  - insn trace: "<tid> 0.0: <ip> insn: <bytes...>"
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


TID_PREFIX = r"(?:(?:TID(?P<tid>\d+):)\s+)?"
READ_RE = re.compile(
    rf"^{TID_PREFIX}Read\s+.*\*\(UINT(?P<bits>\d+)\*\)0x(?P<addr>[0-9a-fA-F]+)\s*$"
)
WRITE_RE = re.compile(
    rf"^{TID_PREFIX}Write\s+\*\(UINT(?P<bits>\d+)\*\)0x(?P<addr>[0-9a-fA-F]+)\s*=\s*.*$"
)
# Newer/other SDE builds may omit the raw instruction bytes: "[488b10]".
INS_RE = re.compile(
    rf"^{TID_PREFIX}INS\s+0x(?P<ip>[0-9a-fA-F]+)"
    r"(?:\s+\[(?P<raw>[0-9a-fA-F]+)\])?"
    r"\s+.*$"
)


def raw_hex_to_spaced_bytes(raw: str) -> str:
    raw = raw.strip()
    if len(raw) % 2 != 0:
        # Best-effort: drop trailing nibble if malformed.
        raw = raw[:-1]
    return " ".join(raw[i : i + 2] for i in range(0, len(raw), 2))


def main() -> int:
    ap = argparse.ArgumentParser(description="Convert SDE debugtrace to JSONL + insn trace.")
    ap.add_argument("-i", "--input", type=Path, required=True, help="SDE debugtrace text file")
    ap.add_argument(
        "--mem-out",
        type=Path,
        required=True,
        help="output JSONL for memory accesses (real addresses)",
    )
    ap.add_argument(
        "--insn-out",
        type=Path,
        required=True,
        help="output insn trace text for recover_mem_addrs.py",
    )
    args = ap.parse_args()

    mem_fp = args.mem_out.open("w", encoding="utf-8")
    insn_fp = args.insn_out.open("w", encoding="utf-8")

    mem_events = 0
    insn_events = 0
    insn_with_raw = 0

    # Track dynamic instruction index per thread (TID in SDE output).
    # Memory ops are attributed to the most recent INS of the same TID.
    insn_idx_by_tid: dict[int, int] = {}

    with args.input.open("r", encoding="utf-8", errors="replace") as fp:
        for line in fp:
            line = line.rstrip("\n")

            m = READ_RE.match(line)
            if m:
                bits = int(m.group("bits"))
                size = bits // 8
                addr = int(m.group("addr"), 16)
                tid_s = m.group("tid")
                tid = int(tid_s) if tid_s is not None else 0
                mem_fp.write(
                    json.dumps(
                        {
                            "access": "read",
                            "addr": f"0x{addr:x}",
                            "size": size,
                            "tid": tid,
                            "insn_idx": insn_idx_by_tid.get(tid, -1),
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )
                mem_events += 1
                continue

            m = WRITE_RE.match(line)
            if m:
                bits = int(m.group("bits"))
                size = bits // 8
                addr = int(m.group("addr"), 16)
                tid_s = m.group("tid")
                tid = int(tid_s) if tid_s is not None else 0
                mem_fp.write(
                    json.dumps(
                        {
                            "access": "write",
                            "addr": f"0x{addr:x}",
                            "size": size,
                            "tid": tid,
                            "insn_idx": insn_idx_by_tid.get(tid, -1),
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )
                mem_events += 1
                continue

            m = INS_RE.match(line)
            if m:
                ip = m.group("ip")
                raw = m.group("raw")
                tid_s = m.group("tid")
                tid = int(tid_s) if tid_s is not None else 0
                insn_idx_by_tid[tid] = insn_idx_by_tid.get(tid, -1) + 1
                if raw:
                    spaced = raw_hex_to_spaced_bytes(raw)
                    # recover_mem_addrs.py expects:
                    #   <tid> <time>:      <ip> insn: <hex bytes...>
                    insn_fp.write(f"{tid} 0.0: {ip} insn: {spaced}\n")
                    insn_with_raw += 1
                insn_events += 1
                continue

    mem_fp.close()
    insn_fp.close()

    print(f"mem events: {mem_events}")
    print(f"insns: {insn_events}")
    if insn_events and insn_with_raw == 0:
        print(
            "warning: no raw instruction bytes found in INS lines; "
            "insn trace for recover_mem_addrs.py was not generated (will be empty)."
        )
    elif insn_events:
        print(f"insns with raw bytes: {insn_with_raw}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

