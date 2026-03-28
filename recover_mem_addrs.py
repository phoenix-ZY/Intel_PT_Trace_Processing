#!/usr/bin/env python3
"""
Recover memory access addresses from a perf insn-trace stream by emulating each
instruction with Unicorn (x86_64).

Input format (one instruction per line), e.g.:
  <tid> <time>:      <ip> insn: <hex bytes...>

We do NOT have runtime register/memory state, so this tool constructs:
- virtual initial register values (zero or deterministic pseudo-random)
- a virtual stack
- a virtual memory space that is demand-mapped on access

It then single-steps each instruction and logs memory reads/writes observed by
Unicorn hooks.
"""

from __future__ import annotations

import argparse
import json
import hashlib
import random
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Iterable

from unicorn import Uc, UcError
from unicorn.x86_const import (
    UC_X86_REG_RAX,
    UC_X86_REG_RBX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDX,
    UC_X86_REG_RSI,
    UC_X86_REG_RDI,
    UC_X86_REG_RBP,
    UC_X86_REG_RSP,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_R10,
    UC_X86_REG_R11,
    UC_X86_REG_R12,
    UC_X86_REG_R13,
    UC_X86_REG_R14,
    UC_X86_REG_R15,
    UC_X86_REG_RIP,
)
from unicorn.unicorn_const import (
    UC_ARCH_X86,
    UC_MODE_64,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_WRITE,
    UC_HOOK_MEM_READ_UNMAPPED,
    UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_HOOK_MEM_FETCH_UNMAPPED,
    UC_PROT_ALL,
)

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OPT_DETAIL  # type: ignore
    from capstone.x86_const import X86_OP_MEM  # type: ignore
except Exception:  # pragma: no cover
    Cs = None  # type: ignore
    CS_ARCH_X86 = None  # type: ignore
    CS_MODE_64 = None  # type: ignore
    CS_OPT_DETAIL = None  # type: ignore
    X86_OP_MEM = None  # type: ignore


LINE_RE = re.compile(
    r"^\s*(?P<tid>\d+)\s+"
    r"(?P<time>[\d.]+):\s+"
    r"(?P<ip>[0-9a-fA-F]+)\s+"
    r"insn:\s+(?P<bytes>(?:[0-9a-fA-F]{2}\s*)+)\s*$"
)


@dataclass(frozen=True)
class TraceInsn:
    tid: int
    time_ns: str
    ip: int
    code: bytes


def parse_trace_lines(fp: IO[str]) -> Iterable[TraceInsn]:
    for line_no, line in enumerate(fp, 1):
        m = LINE_RE.match(line)
        if not m:
            continue
        tid = int(m.group("tid"))
        time_ns = m.group("time")
        ip = int(m.group("ip"), 16)
        byte_str = m.group("bytes").strip().split()
        code = bytes(int(b, 16) for b in byte_str)
        if not code:
            continue
        yield TraceInsn(tid=tid, time_ns=time_ns, ip=ip, code=code)


def align_down(x: int, a: int) -> int:
    return x & ~(a - 1)


def align_up(x: int, a: int) -> int:
    return (x + (a - 1)) & ~(a - 1)


class DemandPager:
    def __init__(self, uc: Uc, page_size: int):
        self.uc = uc
        self.page_size = page_size
        self.mapped_pages: set[int] = set()

    def ensure_mapped(self, addr: int) -> None:
        page = align_down(addr, self.page_size)
        if page in self.mapped_pages:
            return
        self.uc.mem_map(page, self.page_size, UC_PROT_ALL)
        self.uc.mem_write(page, b"\x00" * self.page_size)
        self.mapped_pages.add(page)

    def ensure_mapped_range(self, addr: int, size: int) -> None:
        if size <= 0:
            return
        start = align_down(addr, self.page_size)
        end = align_down(addr + size - 1, self.page_size)
        page = start
        while page <= end:
            self.ensure_mapped(page)
            page += self.page_size


class IPMapper:
    """
    Map arbitrary 64-bit IPs to a compact emulation code region.
    """

    def __init__(self, code_base: int, code_limit: int):
        self.code_base = code_base
        self.code_limit = code_limit
        self._next = code_base
        self._map: dict[int, int] = {}

    def get_or_add(self, ip: int, insn_len: int) -> int:
        if ip in self._map:
            return self._map[ip]
        addr = align_up(self._next, 16)
        next_addr = addr + insn_len
        if next_addr > self.code_limit:
            raise RuntimeError(
                f"code region exhausted: need 0x{next_addr:x}, limit 0x{self.code_limit:x}"
            )
        self._map[ip] = addr
        self._next = next_addr
        return addr

    def lookup(self, ip: int) -> int | None:
        return self._map.get(ip)


def init_registers(uc: Uc, *, mode: str, seed: int, stack_top: int) -> None:
    regs = [
        UC_X86_REG_RAX,
        UC_X86_REG_RBX,
        UC_X86_REG_RCX,
        UC_X86_REG_RDX,
        UC_X86_REG_RSI,
        UC_X86_REG_RDI,
        UC_X86_REG_R8,
        UC_X86_REG_R9,
        UC_X86_REG_R10,
        UC_X86_REG_R11,
        UC_X86_REG_R12,
        UC_X86_REG_R13,
        UC_X86_REG_R14,
        UC_X86_REG_R15,
    ]

    if mode == "zero":
        for r in regs:
            uc.reg_write(r, 0)
    elif mode == "random":
        rng = random.Random(seed)
        for r in regs:
            uc.reg_write(r, rng.getrandbits(64))
    else:
        raise ValueError(f"unknown init mode: {mode}")

    uc.reg_write(UC_X86_REG_RSP, stack_top)
    uc.reg_write(UC_X86_REG_RBP, stack_top)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Emulate perf --insn-trace stream and log memory accesses."
    )
    ap.add_argument(
        "-i",
        "--input",
        type=Path,
        required=True,
        help="perf script --insn-trace output text (can be huge; streamed)",
    )
    ap.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("mem_access.jsonl"),
        help="output JSONL file (default: mem_access.jsonl)",
    )
    ap.add_argument(
        "--append",
        action="store_true",
        help="append to output file instead of overwriting",
    )
    ap.add_argument(
        "--max-insns",
        type=int,
        default=0,
        help="max instructions to emulate (0 means no limit)",
    )
    ap.add_argument(
        "--skip-insns",
        type=int,
        default=0,
        help="skip first N instructions from input stream (default: 0)",
    )
    ap.add_argument(
        "--progress-every",
        type=int,
        default=0,
        help="print progress every N executed insns (0=disabled)",
    )
    ap.add_argument(
        "--minimal",
        action="store_true",
        help='write only {"access","addr","size"} per event',
    )
    ap.add_argument(
        "--record-bytes",
        choices=["none", "error", "all"],
        default="none",
        help="include instruction bytes hex in output events (default: none)",
    )
    ap.add_argument(
        "--salvage-invalid-mem",
        action="store_true",
        help=(
            "on UC_ERR_INSN_INVALID, decode instruction and emit synthetic "
            "memory access events (adds ip/insn_bytes/asm)"
        ),
    )
    ap.add_argument(
        "--salvage-fill-writes",
        action="store_true",
        help=(
            "when salvaging invalid instructions, fill salvaged memory writes "
            "with deterministic pseudo-random bytes (helps downstream patterns)"
        ),
    )
    ap.add_argument(
        "--salvage-fill-seed",
        type=int,
        default=1,
        help="seed for --salvage-fill-writes (default: 1)",
    )
    ap.add_argument(
        "--salvage-reads",
        action="store_true",
        help=(
            "when salvaging invalid instructions, also emit synthetic memory reads "
            "(default: off to reduce read-side noise)"
        ),
    )
    ap.add_argument(
        "--init-regs",
        choices=["zero", "random"],
        default="zero",
        help="virtual initial register values (default: zero)",
    )
    ap.add_argument("--seed", type=int, default=1, help="seed for random regs")
    ap.add_argument(
        "--stack-base",
        type=lambda s: int(s, 0),
        default=0x7000_0000_0000,
        help="virtual stack base address (default: 0x700000000000)",
    )
    ap.add_argument(
        "--stack-size",
        type=lambda s: int(s, 0),
        default=0x20_0000,
        help="virtual stack size bytes (default: 0x200000)",
    )
    ap.add_argument(
        "--code-base",
        type=lambda s: int(s, 0),
        default=0x1000_0000,
        help="emulated code region base (default: 0x10000000)",
    )
    ap.add_argument(
        "--code-size",
        type=lambda s: int(s, 0),
        default=0x2000_0000,
        help="emulated code region size bytes (default: 0x20000000)",
    )
    ap.add_argument(
        "--page-size",
        type=lambda s: int(s, 0),
        default=0x1000,
        help="page size for demand-mapped memory (default: 0x1000)",
    )
    ap.add_argument(
        "--io-batch-lines",
        type=int,
        default=1,
        metavar="N",
        help=(
            "buffer N JSONL records before each write (default: 1). "
            "Use 512-8192 to reduce Python/syscall overhead on huge runs."
        ),
    )
    ap.add_argument(
        "--output-buffer-bytes",
        type=int,
        default=8 << 20,
        metavar="BYTES",
        help="stdio buffer size for output file (default: 8MiB; 0 = system default)",
    )
    args = ap.parse_args()

    if args.page_size & (args.page_size - 1) != 0:
        print("page-size must be power of two", file=sys.stderr)
        return 2
    if args.io_batch_lines < 1:
        print("io-batch-lines must be >= 1", file=sys.stderr)
        return 2
    if not args.input.is_file():
        print(f"input not found: {args.input}", file=sys.stderr)
        return 2

    uc = Uc(UC_ARCH_X86, UC_MODE_64)

    cs = None
    if args.salvage_invalid_mem:
        if Cs is None:
            print(
                "capstone is required for --salvage-invalid-mem (pip install capstone)",
                file=sys.stderr,
            )
            return 2
        cs = Cs(CS_ARCH_X86, CS_MODE_64)
        cs.detail = True

    code_base = args.code_base
    code_limit = args.code_base + args.code_size
    uc.mem_map(code_base, args.code_size, UC_PROT_ALL)
    uc.mem_write(code_base, b"\x90" * min(args.code_size, 0x1000))  # safe NOP padding

    stack_base = align_down(args.stack_base, args.page_size)
    stack_size = align_up(args.stack_size, args.page_size)
    uc.mem_map(stack_base, stack_size, UC_PROT_ALL)
    uc.mem_write(stack_base, b"\x00" * min(stack_size, 0x1000))
    stack_top = stack_base + stack_size - 8

    init_registers(uc, mode=args.init_regs, seed=args.seed, stack_top=stack_top)

    pager = DemandPager(uc, page_size=args.page_size)
    ipmap = IPMapper(code_base=code_base + 0x1000, code_limit=code_limit)

    out_mode = "a" if args.append else "w"
    buf_kw: dict = {}
    if args.output_buffer_bytes and args.output_buffer_bytes > 0:
        buf_kw["buffering"] = args.output_buffer_bytes
    out_fp = args.output.open(out_mode, encoding="utf-8", **buf_kw)

    jsonl_buf: list[str] = []

    def flush_jsonl_buf() -> None:
        if jsonl_buf:
            out_fp.writelines(jsonl_buf)
            jsonl_buf.clear()

    current_trace_ip: int | None = None
    current_tid: int | None = None
    current_time: str | None = None
    current_code: bytes | None = None
    current_insn_idx: int | None = None

    def log_event(obj: dict) -> None:
        line = json.dumps(obj, ensure_ascii=False) + "\n"
        if args.io_batch_lines <= 1:
            out_fp.write(line)
            return
        jsonl_buf.append(line)
        if len(jsonl_buf) >= args.io_batch_lines:
            flush_jsonl_buf()

    def hook_mem(
        uc_: Uc, access: int, address: int, size: int, value: int, user_data
    ) -> None:
        nonlocal current_trace_ip, current_tid, current_time, current_code, current_insn_idx
        if current_trace_ip is None:
            trace_ip = None
        else:
            trace_ip = f"0x{current_trace_ip:x}"

        rip = uc_.reg_read(UC_X86_REG_RIP)
        # Don't rely on numeric 'access' values (they vary across Unicorn/QEMU builds).
        # We attach explicit kind via hook_add(user_data=...).
        if user_data in ("read", "write"):
            kind = user_data
        else:
            kind = "read" if access == 1 else "write"

        if args.minimal:
            evt = {
                "access": kind,
                "addr": f"0x{address:x}",
                "size": size,
            }
            if current_insn_idx is not None:
                evt["insn_idx"] = current_insn_idx
            if args.record_bytes == "all" and current_code is not None:
                evt["insn_bytes"] = current_code.hex()
            log_event(evt)
            return

        read_value = None
        write_value = None
        if kind == "read":
            try:
                data = uc_.mem_read(address, size)
                read_value = int.from_bytes(data, "little", signed=False)
            except UcError:
                read_value = None
        else:
            write_value = value

        evt = {
            "tid": current_tid,
            "time": current_time,
            "ip": trace_ip,
            "rip": f"0x{rip:x}",
            "insn_idx": current_insn_idx,
            "access": kind,
            "addr": f"0x{address:x}",
            "size": size,
            "read_value": read_value,
            "write_value": write_value,
        }
        if args.record_bytes == "all" and current_code is not None:
            evt["insn_bytes"] = current_code.hex()
        log_event(evt)

    def hook_unmapped(uc_: Uc, access: int, address: int, size: int, value: int, user_data):
        pager.ensure_mapped_range(address, size)
        return True

    uc.hook_add(UC_HOOK_MEM_READ, hook_mem, user_data="read")
    uc.hook_add(UC_HOOK_MEM_WRITE, hook_mem, user_data="write")
    uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_unmapped)
    uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, hook_unmapped)
    uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, hook_unmapped)

    def uc_read_gpr(reg_name: str) -> int:
        """
        Read a 64-bit GPR value from Unicorn by name as used by Capstone.
        Only covers the common x86-64 integer register set.
        """
        name = reg_name.lower()
        reg_map = {
            "rax": UC_X86_REG_RAX,
            "rbx": UC_X86_REG_RBX,
            "rcx": UC_X86_REG_RCX,
            "rdx": UC_X86_REG_RDX,
            "rsi": UC_X86_REG_RSI,
            "rdi": UC_X86_REG_RDI,
            "rbp": UC_X86_REG_RBP,
            "rsp": UC_X86_REG_RSP,
            "r8": UC_X86_REG_R8,
            "r9": UC_X86_REG_R9,
            "r10": UC_X86_REG_R10,
            "r11": UC_X86_REG_R11,
            "r12": UC_X86_REG_R12,
            "r13": UC_X86_REG_R13,
            "r14": UC_X86_REG_R14,
            "r15": UC_X86_REG_R15,
            "rip": UC_X86_REG_RIP,
        }
        ureg = reg_map.get(name)
        if ureg is None:
            return 0
        return int(uc.reg_read(ureg))

    def salvage_mem_events_from_bytes(
        *,
        ip: int,
        code: bytes,
        emu_rip: int,
        tid: int | None,
        time_s: str | None,
        err: str,
    ) -> bool:
        """
        Best-effort: decode instruction bytes and emit synthetic memory access events.
        Returns True if at least one mem event was emitted.
        """
        if cs is None:
            return False

        insns = list(cs.disasm(code, emu_rip, count=1))
        if not insns:
            return False
        insn = insns[0]
        asm = insn.mnemonic if not insn.op_str else f"{insn.mnemonic} {insn.op_str}"

        emitted = 0
        # Capstone provides operand access flags when detail is enabled.
        for op in getattr(insn, "operands", []):
            if op.type != X86_OP_MEM:
                continue
            mem = op.mem
            base_name = insn.reg_name(mem.base) if mem.base else ""
            index_name = insn.reg_name(mem.index) if mem.index else ""
            base_val = uc_read_gpr(base_name) if base_name else 0
            index_val = uc_read_gpr(index_name) if index_name else 0
            scale = int(mem.scale) if mem.scale else 1
            disp = int(mem.disp)

            # RIP-relative addressing: base will be RIP; use next RIP (emu_rip + insn.size).
            if base_name.lower() == "rip":
                base_val = emu_rip + int(insn.size)

            ea = (base_val + index_val * scale + disp) & 0xFFFF_FFFF_FFFF_FFFF
            size = int(getattr(op, "size", 0)) or len(code)

            access_flags = int(getattr(op, "access", 0))
            kinds: list[str] = []
            # Capstone uses CS_AC_READ=1, CS_AC_WRITE=2, CS_AC_INVALID=0.
            if access_flags & 1:
                kinds.append("read")
            if access_flags & 2:
                kinds.append("write")
            if not kinds:
                # Fallback: assume load when unknown.
                kinds = ["read"]

            for kind in kinds:
                if kind == "read" and not args.salvage_reads:
                    continue
                if args.salvage_fill_writes and kind == "write":
                    # Keep the virtual memory state "non-trivial" and deterministic
                    # even when we can't execute the instruction semantics.
                    pager.ensure_mapped_range(ea, size)
                    h = hashlib.blake2b(
                        digest_size=16,
                        key=args.salvage_fill_seed.to_bytes(8, "little", signed=True),
                    )
                    h.update(ip.to_bytes(8, "little", signed=False))
                    h.update(ea.to_bytes(8, "little", signed=False))
                    h.update(size.to_bytes(4, "little", signed=False))
                    seed_bytes = h.digest()
                    rng = random.Random(int.from_bytes(seed_bytes, "little"))
                    data = bytes(rng.getrandbits(8) for _ in range(size))
                    try:
                        uc.mem_write(ea, data)
                    except UcError:
                        # If this fails, we still keep the logged event.
                        pass

                log_event(
                    {
                        "tid": tid,
                        "time": time_s,
                        "ip": f"0x{ip:x}",
                        "insn_idx": current_insn_idx,
                        "access": kind,
                        "addr": f"0x{ea:x}",
                        "size": size,
                        "insn_bytes": code.hex(),
                        "asm": asm,
                        "salvaged": True,
                        "error": err,
                    }
                )
                emitted += 1

        return emitted > 0

    executed = 0
    try:
        with args.input.open("r", encoding="utf-8", errors="replace") as fp:
            it = iter(parse_trace_lines(fp))
            prev: TraceInsn | None = None
            skipped = 0
            for insn in it:
                if args.skip_insns and skipped < args.skip_insns:
                    skipped += 1
                    continue
                if prev is None:
                    prev = insn
                    continue

                # Ensure both current and next instruction are materialized in code memory.
                cur_addr = ipmap.get_or_add(prev.ip, len(prev.code))
                nxt_addr = ipmap.get_or_add(insn.ip, len(insn.code))
                uc.mem_write(cur_addr, prev.code)
                uc.mem_write(nxt_addr, insn.code)

                current_trace_ip = prev.ip
                current_tid = prev.tid
                current_time = prev.time_ns
                current_code = prev.code
                current_insn_idx = executed

                if args.progress_every and executed % args.progress_every == 0:
                    print(
                        f"[progress] executed={executed} ip=0x{prev.ip:x} len={len(prev.code)} bytes={prev.code.hex()}",
                        file=sys.stderr,
                        flush=True,
                    )

                uc.reg_write(UC_X86_REG_RIP, cur_addr)

                try:
                    # Single-step exactly one instruction.
                    uc.emu_start(cur_addr, cur_addr + len(prev.code), count=1)
                except UcError as e:
                    err = str(e)
                    if (
                        args.salvage_invalid_mem
                        and "UC_ERR_INSN_INVALID" in err
                        and salvage_mem_events_from_bytes(
                            ip=prev.ip,
                            code=prev.code,
                            emu_rip=cur_addr,
                            tid=current_tid,
                            time_s=current_time,
                            err=err,
                        )
                    ):
                        # We salvaged at least one mem event; still continue the trace.
                        pass
                    evt = {
                        "tid": current_tid,
                        "time": current_time,
                        "ip": f"0x{prev.ip:x}",
                        "rip": f"0x{cur_addr:x}",
                        "insn_idx": current_insn_idx,
                        "error": err,
                    }
                    if args.record_bytes in ("error", "all"):
                        evt["insn_bytes"] = prev.code.hex()
                        evt["insn_len"] = len(prev.code)
                    log_event(evt)

                # Force RIP to follow the trace, regardless of control-flow.
                uc.reg_write(UC_X86_REG_RIP, nxt_addr)

                executed += 1
                if args.max_insns and executed >= args.max_insns:
                    break

                prev = insn

            # Last instruction: we can still emulate it once.
            if prev is not None and (not args.max_insns or executed < args.max_insns):
                last_addr = ipmap.get_or_add(prev.ip, len(prev.code))
                uc.mem_write(last_addr, prev.code)
                current_trace_ip = prev.ip
                current_tid = prev.tid
                current_time = prev.time_ns
                current_code = prev.code
                current_insn_idx = executed
                uc.reg_write(UC_X86_REG_RIP, last_addr)
                try:
                    uc.emu_start(last_addr, last_addr + len(prev.code), count=1)
                except UcError as e:
                    evt = {
                        "tid": current_tid,
                        "time": current_time,
                        "ip": f"0x{prev.ip:x}",
                        "rip": f"0x{last_addr:x}",
                        "insn_idx": current_insn_idx,
                        "error": str(e),
                    }
                    if args.record_bytes in ("error", "all"):
                        evt["insn_bytes"] = prev.code.hex()
                        evt["insn_len"] = len(prev.code)
                    log_event(evt)

    finally:
        flush_jsonl_buf()
        out_fp.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

