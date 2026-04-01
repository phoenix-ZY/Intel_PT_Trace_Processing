#!/usr/bin/env python3
"""
Build an instruction-trace portrait from `perf script --insn-trace --xed` output.

Expects lines similar to:
  3270685 [115] 7936883.546339900:  72e49281f8e5  jnbe 0x...  IPC: 0.03 (4/122)

Also tolerates compact -F tid,ip,insn,ipc layouts when present.

GPR RAW/WAW/WAR distances use a heuristic AT&T operand model (see report notes);
SIMD and ambiguous forms are approximated. Instruction mix / branch / syscall
counts are derived from decoded text and are more reliable.
"""

from __future__ import annotations

import argparse
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Iterable, Sequence, Set, Tuple

# Full perf line: tid, optional [cpu], timestamp, ip, asm, optional IPC tail.
LINE_VERBOSE = re.compile(
    r"^\s*(\d+)\s+(?:\[(\d+)\]\s+)?([\d.]+):\s+([0-9a-fA-F]+)\s+(.+?)\s*$",
    re.DOTALL,
)
IPC_SUFFIX = re.compile(
    r"(.+?)\s+IPC:\s*([0-9.]+)(?:\s*\((\d+)/(\d+)\))?\s*$",
    re.DOTALL,
)

# Control-flow target: try to parse an immediate hex target (direct branches/calls/jmps).
HEX_TARGET = re.compile(r"\b0x([0-9a-fA-F]+)\b")

# Compact: tid ip asm...
LINE_COMPACT = re.compile(
    r"^\s*(\d+)\s+([0-9a-fA-F]+)\s+(.+?)\s*$",
    re.DOTALL,
)

# OLD dataset format: tid [cpu] ip category asm... IPC: (n/d)
LINE_OLD = re.compile(
    r"^\s*(\d+)\s+\[(\d+)\]\s+([0-9a-fA-F]+)\s+\S+\s+(.+?)\s*$",
    re.DOTALL,
)

REG_TOKEN = re.compile(
    r"%([a-zA-Z][a-zA-Z0-9]*)",
)

# Conditional branch mnemonics (AT&T, common)
COND_BRANCH = frozenset(
    f"j{x}"
    for x in (
        "a",
        "ae",
        "b",
        "be",
        "c",
        "cxz",
        "ecxz",
        "e",
        "g",
        "ge",
        "l",
        "le",
        "na",
        "nae",
        "nb",
        "nbe",
        "nc",
        "ne",
        "ng",
        "nge",
        "nl",
        "nle",
        "no",
        "np",
        "ns",
        "nz",
        "o",
        "p",
        "pe",
        "po",
        "rcxz",
        "s",
        "z",
    )
)

SYSCALL_MNEMS = frozenset({"syscall", "sysenter"})
INT_INSN = re.compile(r"^int\s+", re.I)

FENCE_MNEMS = frozenset({"lfence", "mfence", "sfence"})
SERIALIZE_MNEMS = frozenset({"cpuid", "rdtsc", "rdtscp", "serialize"})


def operand_kind(op: str) -> str:
    o = op.strip()
    if not o:
        return "none"
    if "%" in o:
        # mem operands also contain regs; mem check first.
        if "(" in o:
            return "mem"
        return "reg"
    if "(" in o:
        return "mem"
    if o.startswith("$"):
        return "imm"
    if o.startswith("0x") or o[0].isdigit():
        return "imm"
    return "other"


def simd_class(asm: str, mnem: str) -> str:
    a = asm.lower()
    m = mnem.lower()
    if "%zmm" in a:
        return "avx512"
    if "%ymm" in a:
        return "avx"
    if "%xmm" in a:
        # Could be SSE or AVX with xmm regs; use mnemonic hint.
        if m.startswith("v"):
            return "avx_xmm"
        return "sse"
    if m.startswith("v"):
        return "avx_other"
    return "none"


def alu_subclass(mnem: str) -> str:
    m = mnem.lower()
    if m.startswith(("add", "sub", "adc", "sbb", "inc", "dec", "neg")):
        return "addsub"
    if m.startswith(("and", "or", "xor", "not", "test")):
        return "logic"
    if m.startswith(("shl", "shr", "sar", "rol", "ror", "shld", "shrd")):
        return "shift"
    if m.startswith(("mul", "imul", "div", "idiv")):
        return "muldiv"
    if m.startswith(("cmp",)):
        return "compare"
    return "other"


def classify_submix(mnem: str, asm: str) -> str:
    m = mnem.lower()
    if m in FENCE_MNEMS:
        return "barrier_fence"
    if m in SERIALIZE_MNEMS:
        return "barrier_serialize"
    if m == "pause":
        return "barrier_pause"
    if m in SYSCALL_MNEMS or INT_INSN.match(mnem):
        return "syscall"
    if m.startswith("cmov"):
        return "cmov"
    if m.startswith("set"):
        return "setcc"
    if m.startswith("lea"):
        return "lea"
    if m.startswith("mov") or m in ("movabs",):
        if "(" in asm:
            return "mov_mem"
        return "mov_reg"
    if m.startswith(("jmp",)) or (m.startswith("j") and m in COND_BRANCH):
        return "branch"
    if m.startswith("call"):
        return "call"
    if m.startswith("ret"):
        return "ret"
    if m.startswith("rep"):
        return "prefix_rep"
    if m.startswith("lock"):
        return "prefix_lock"
    sc = simd_class(asm, mnem)
    if sc != "none":
        return f"simd_{sc}"
    if any(m.startswith(p) for p in ("add", "sub", "adc", "sbb", "imul", "mul", "div", "idiv", "inc", "dec", "neg", "not", "and", "or", "xor", "shl", "shr", "sar", "rol", "ror")):
        return f"alu_{alu_subclass(mnem)}"
    if m.startswith("cmp") or m.startswith("test"):
        return "compare"
    return "other"


def _split_ops(rest: str) -> list[str]:
    """Comma-split respecting parentheses."""
    rest = rest.strip()
    if not rest:
        return []
    parts: list[str] = []
    cur: list[str] = []
    depth = 0
    for ch in rest:
        if ch == "(":
            depth += 1
            cur.append(ch)
        elif ch == ")":
            depth = max(0, depth - 1)
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur).strip())
    return [p for p in parts if p]


def _regs_in(s: str) -> Set[str]:
    return {normalize_reg(m.group(1)) for m in REG_TOKEN.finditer(s)}


def split_regs(regs: Set[str]) -> tuple[Set[str], Set[str]]:
    gpr: Set[str] = set()
    vec: Set[str] = set()
    for r in regs:
        rr = r.lower()
        if rr.startswith(("xmm", "ymm", "zmm", "mm")):
            vec.add(rr)
        else:
            gpr.add(rr)
    return gpr, vec


def normalize_reg(name: str) -> str:
    n = name.lower()
    eight = {
        "al": "rax",
        "ah": "rax",
        "ax": "rax",
        "eax": "rax",
        "rax": "rax",
        "bl": "rbx",
        "bh": "rbx",
        "bx": "rbx",
        "ebx": "rbx",
        "rbx": "rbx",
        "cl": "rcx",
        "ch": "rcx",
        "cx": "rcx",
        "ecx": "rcx",
        "rcx": "rcx",
        "dl": "rdx",
        "dh": "rdx",
        "dx": "rdx",
        "edx": "rdx",
        "rdx": "rdx",
        "sil": "rsi",
        "si": "rsi",
        "esi": "rsi",
        "rsi": "rsi",
        "dil": "rdi",
        "di": "rdi",
        "edi": "rdi",
        "rdi": "rdi",
        "bpl": "rbp",
        "bp": "rbp",
        "ebp": "rbp",
        "rbp": "rbp",
        "spl": "rsp",
        "sp": "rsp",
        "esp": "rsp",
        "rsp": "rsp",
    }
    if n in eight:
        return eight[n]
    if re.fullmatch(r"r[89]|r1[0-5]", n):
        return n
    if re.fullmatch(r"r[89][dwb]|r1[0-5][dwb]", n):
        return n[:-1] if len(n) > 3 else n
    return n


def infer_reg_rw(mnem: str, ops: list[str]) -> Tuple[Set[str], Set[str]]:
    """
    Return (read_set, write_set) for GPR-level dependency tracking.
    """
    reads: Set[str] = set()
    writes: Set[str] = set()
    m = mnem.lower()

    def is_mem(op: str) -> bool:
        # AT&T mem operands typically look like disp(base,index,scale) and contain '('.
        return "(" in op

    if m in ("nop", "ud2", "hlt", "pause", "lfence", "mfence", "sfence"):
        return reads, writes

    if m in SYSCALL_MNEMS or INT_INSN.match(mnem):
        reads |= _regs_in(",".join(ops))
        return reads, writes

    if m == "ret" or m == "retq" or m.startswith("ret"):
        reads |= _regs_in(",".join(ops))
        reads.add("rsp")
        writes.add("rsp")
        return reads, writes

    if m == "call" or m == "callq":
        reads |= _regs_in(",".join(ops))
        reads.add("rsp")
        writes.add("rsp")
        return reads, writes

    if m == "push" or m == "pushq":
        if ops:
            reads |= _regs_in(ops[0])
        reads.add("rsp")
        writes.add("rsp")
        return reads, writes

    if m == "pop" or m == "popq":
        if ops:
            writes |= _regs_in(ops[0])
        reads.add("rsp")
        writes.add("rsp")
        return reads, writes

    if m.startswith("j") and m in COND_BRANCH:
        reads |= _regs_in(",".join(ops))
        return reads, writes

    if m == "jmp" or m.startswith("jmp"):
        reads |= _regs_in(",".join(ops))
        return reads, writes

    if m in ("cmp", "test", "cmpb", "cmpw", "cmpl", "cmpq", "testb", "testw", "testl", "testq"):
        for o in ops:
            reads |= _regs_in(o)
        return reads, writes

    if m.startswith("mov") or m in ("movabs", "lea", "leaq"):
        if len(ops) >= 2:
            # AT&T: src, dst (common in perf --xed output)
            src, dst = ops[0], ops[1]
            if m.startswith("lea"):
                # lea src, dst: reads address regs in src; writes dst reg.
                reads |= _regs_in(src)
                writes |= _regs_in(dst)
                return reads, writes

            # mov src, dst:
            # - src regs are read (including address regs if src is memory)
            # - dst regs: if dst is a register -> written; if dst is memory -> its address regs are read
            reads |= _regs_in(src)
            if is_mem(dst):
                reads |= _regs_in(dst)
            else:
                writes |= _regs_in(dst)
            return reads, writes

        if len(ops) == 1:
            reads |= _regs_in(ops[0])
        return reads, writes

    # Conditional move: cmovcc src, dst (read both, write dst)
    if m.startswith("cmov"):
        if len(ops) >= 2:
            src, dst = ops[0], ops[1]
            reads |= _regs_in(src)
            if is_mem(dst):
                reads |= _regs_in(dst)
            else:
                reads |= _regs_in(dst)
                writes |= _regs_in(dst)
        elif len(ops) == 1:
            reads |= _regs_in(ops[0])
        return reads, writes

    # setcc: writes 8-bit reg/mem operand; if mem, address regs are read.
    if m.startswith("set"):
        if ops:
            dst = ops[0]
            if is_mem(dst):
                reads |= _regs_in(dst)
            else:
                writes |= _regs_in(dst)
        return reads, writes

    # Shifts/rotates by CL: shl/shr/sar/rol/ror $imm, dst OR %cl, dst
    if m in ("shl", "shr", "sar", "rol", "ror", "shld", "shrd"):
        if len(ops) >= 2:
            count_op = ops[0]
            dst = ops[-1]
            reads |= _regs_in(count_op)
            # CL implies rcx is read (normalize_reg maps cl/ecx->rcx)
            reads |= _regs_in(dst)
            if is_mem(dst):
                # memory RMW: address regs read
                reads |= _regs_in(dst)
            else:
                writes |= _regs_in(dst)
        elif len(ops) == 1:
            dst = ops[0]
            reads |= _regs_in(dst)
            if not is_mem(dst):
                writes |= _regs_in(dst)
        return reads, writes

    # mul/div family has implicit rax/rdx semantics (very common hot path).
    # We only model GPR deps, ignoring flags.
    if m in ("mul", "mulq", "mull", "mulw", "mulb"):
        # unsigned: RDX:RAX <- RAX * src
        reads.add("rax")
        if ops:
            reads |= _regs_in(ops[0])
        writes.add("rax")
        writes.add("rdx")
        return reads, writes
    if m in ("imul", "imulq", "imull", "imulw", "imulb"):
        # Forms:
        # 1-op: imul src  (implicit rax/rdx)
        # 2-op: imul src, dst (RMW on dst)
        # 3-op: imul imm, src, dst (read src, write dst)
        if len(ops) == 1:
            reads.add("rax")
            reads |= _regs_in(ops[0])
            writes.add("rax")
            writes.add("rdx")
            return reads, writes
        if len(ops) >= 3:
            imm, src, dst = ops[0], ops[1], ops[2]
            reads |= _regs_in(imm)
            reads |= _regs_in(src)
            if is_mem(dst):
                reads |= _regs_in(dst)
            else:
                writes |= _regs_in(dst)
            return reads, writes
        if len(ops) == 2:
            src, dst = ops[0], ops[1]
            reads |= _regs_in(src)
            reads |= _regs_in(dst)
            if is_mem(dst):
                reads |= _regs_in(dst)
            else:
                writes |= _regs_in(dst)
            return reads, writes
        return reads, writes
    if m in ("div", "divq", "divl", "divw", "divb", "idiv", "idivq", "idivl", "idivw", "idivb"):
        # quotient/remainder in rax/rdx; reads rax/rdx and divisor op
        reads.add("rax")
        reads.add("rdx")
        if ops:
            reads |= _regs_in(ops[0])
        writes.add("rax")
        writes.add("rdx")
        return reads, writes

    if m in ("xchg",):
        # xchg reg, reg: both read+write; xchg mem, reg: address regs read; reg read+write.
        for o in ops:
            r = _regs_in(o)
            reads |= r
            if is_mem(o):
                continue
            writes |= r
        return reads, writes

    # Default: any insn with explicit regs — last operand often destination for ALU.
    regs_list = [_regs_in(o) for o in ops]
    flat = [x for rs in regs_list for x in rs]
    if not flat:
        return reads, writes
    if len(ops) >= 2:
        dst_op = ops[-1]
        dst_regs = _regs_in(dst_op)
        src_regs: Set[str] = set()
        for o in ops[:-1]:
            src_regs |= _regs_in(o)
        reads |= src_regs | dst_regs
        # If destination is memory, its regs are address regs (reads), not writes.
        if not is_mem(dst_op):
            writes |= dst_regs
    else:
        op0 = ops[0]
        reads |= _regs_in(op0)
        if not is_mem(op0):
            writes |= _regs_in(op0)
    return reads, writes


def classify_instruction(mnem: str, full_asm: str) -> str:
    m = mnem.lower()
    if m in SYSCALL_MNEMS or INT_INSN.match(mnem):
        return "syscall_class"
    if m.startswith("j") and m in COND_BRANCH:
        return "branch_conditional"
    if m == "jmp" or m.startswith("jmp"):
        if "*" in full_asm or "(" in full_asm:
            return "branch_indirect"
        return "branch_unconditional"
    if m.startswith("call"):
        if "*" in full_asm or "(" in full_asm:
            return "call_indirect"
        return "call_direct"
    if m.startswith("ret"):
        return "return"
    if m.startswith("mov") or m in ("movabs", "lea", "leaq"):
        if "(" in full_asm:
            if m.startswith("lea"):
                return "lea"
            return "load_store_mov"
        return "mov_reg"
    if m.startswith("cmp") or m.startswith("test"):
        return "compare"
    if any(m.startswith(p) for p in ("add", "sub", "adc", "sbb", "imul", "mul", "div", "idiv", "inc", "dec", "neg", "not", "and", "or", "xor", "shl", "shr", "sar", "rol", "ror")):
        return "alu"
    if m.startswith("v") or m.startswith("p") and len(m) > 2:
        return "simd_or_vec_hint"
    return "other"


def bucket_dist(d: int) -> str:
    if d <= 0:
        return "0"
    if d <= 4:
        return "1-4"
    if d <= 16:
        return "5-16"
    if d <= 64:
        return "17-64"
    return "65+"


def _quantiles(xs: list[float], qs: Sequence[float]) -> dict[str, float]:
    if not xs:
        return {f"p{int(q*100)}": 0.0 for q in qs}
    ys = sorted(xs)
    n = len(ys)
    out: dict[str, float] = {}
    for q in qs:
        idx = min(n - 1, max(0, int(math.floor(q * (n - 1)))))
        out[f"p{int(q*100)}"] = float(ys[idx])
    return out


def _h2(p: float) -> float:
    # Binary entropy in bits.
    if p <= 0.0 or p >= 1.0:
        return 0.0
    return -(p * math.log2(p) + (1.0 - p) * math.log2(1.0 - p))


def analyze_lines(
    lines: Iterable[str],
    *,
    max_insns: int = 0,
) -> dict:
    mix = Counter()
    submix = Counter()
    opmix = Counter()
    barriers = Counter()
    branch_detail = Counter()
    ipc_values: list[float] = []
    ipc_retire_nums: list[int] = []
    ipc_retire_dens: list[int] = []

    raw_dists: list[int] = []
    waw_dists: list[int] = []
    war_dists: list[int] = []

    vraw_dists: list[int] = []
    vwaw_dists: list[int] = []
    vwar_dists: list[int] = []

    last_write: dict[tuple[int, str], int] = {}
    last_read: dict[tuple[int, str], int] = {}
    vlast_write: dict[tuple[int, str], int] = {}
    vlast_read: dict[tuple[int, str], int] = {}
    insn_idx = 0
    parsed = 0
    skipped = 0
    ipc_lines = 0

    # Branch behavior (taken/transition/history patterns).
    branch_pending: dict[str, object] | None = None  # tid, ip, target
    site_taken: Counter[tuple[int, str]] = Counter()
    site_not_taken: Counter[tuple[int, str]] = Counter()
    site_unknown_next: Counter[tuple[int, str]] = Counter()
    site_transitions: Counter[tuple[int, str]] = Counter()
    site_last_outcome: dict[tuple[int, str], int] = {}
    site_outcomes: Counter[tuple[int, str]] = Counter()
    hist_max = 32
    site_hist: dict[tuple[int, str], tuple[int, int]] = {}  # (bits, seen)
    pat_Ls = (4, 8, 16, 32)
    pat_counts: dict[int, Counter[int]] = {L: Counter() for L in pat_Ls}

    for raw in lines:
        line = raw.rstrip("\n")
        if not line.strip():
            skipped += 1
            continue

        ipc_val = None
        ipc_n = None
        ipc_d = None
        m_ipc = IPC_SUFFIX.match(line)
        asm_body = line
        if m_ipc:
            asm_body = m_ipc.group(1).strip()
            if m_ipc.group(2):
                ipc_val = float(m_ipc.group(2))
            if m_ipc.group(3) and m_ipc.group(4):
                ipc_n = int(m_ipc.group(3))
                ipc_d = int(m_ipc.group(4))
                if ipc_val is None and ipc_d > 0:
                    ipc_val = float(ipc_n) / float(ipc_d)
            ipc_lines += 1
            if ipc_val is not None:
                ipc_values.append(ipc_val)
            if ipc_n is not None and ipc_d is not None and ipc_d > 0:
                ipc_retire_nums.append(ipc_n)
                ipc_retire_dens.append(ipc_d)

        tid = None
        ip_hex = None
        asm = None

        mv = LINE_VERBOSE.match(asm_body)
        if mv:
            tid = int(mv.group(1))
            ip_hex = mv.group(4).lower()
            asm = mv.group(5).strip()
        else:
            mc = LINE_COMPACT.match(asm_body)
            if mc:
                tid = int(mc.group(1))
                ip_hex = mc.group(2).lower()
                asm = mc.group(3).strip()
            else:
                # Try OLD dataset format: tid [cpu] ip category asm...
                mo = LINE_OLD.match(asm_body)
                if mo:
                    tid = int(mo.group(1))
                    ip_hex = mo.group(3).lower()
                    asm = mo.group(4).strip()

        if tid is None or not asm:
            skipped += 1
            continue

        # Resolve previous pending direct branch outcome using current IP as "next".
        if branch_pending is not None:
            b_tid = int(branch_pending["tid"])
            b_ip = str(branch_pending["ip"])
            b_target = int(branch_pending["target"])
            key = (b_tid, b_ip)
            if tid == b_tid:
                next_ip = int(ip_hex, 16) if ip_hex is not None else 0
                taken = 1 if (next_ip == b_target) else 0
                site_outcomes[key] += 1
                if taken:
                    site_taken[key] += 1
                else:
                    site_not_taken[key] += 1
                last = site_last_outcome.get(key)
                if last is not None and last != taken:
                    site_transitions[key] += 1
                site_last_outcome[key] = taken
                # History patterns (TAGE-like summaries, not a predictor).
                bits, seen_bits = site_hist.get(key, (0, 0))
                bits = ((bits << 1) | taken) & ((1 << hist_max) - 1)
                seen_bits = min(hist_max, seen_bits + 1)
                site_hist[key] = (bits, seen_bits)
                for L in pat_Ls:
                    if seen_bits >= L:
                        pat_counts[L][bits & ((1 << L) - 1)] += 1
            else:
                site_unknown_next[key] += 1
            branch_pending = None

        sp = asm.find(" ")
        if sp < 0:
            mnem, rest = asm, ""
        else:
            mnem, rest = asm[:sp], asm[sp + 1 :]
        mnem = mnem.strip()
        ops = _split_ops(rest)

        cat = classify_instruction(mnem, asm)
        mix[cat] += 1
        submix[classify_submix(mnem, asm)] += 1
        if ops:
            # Operand-type mix: for 2-op AT&T format use src,dst; else just join kinds.
            if len(ops) >= 2:
                src_k, dst_k = operand_kind(ops[0]), operand_kind(ops[1])
                opmix[f"{src_k}_to_{dst_k}"] += 1
            else:
                opmix[operand_kind(ops[0])] += 1
        else:
            opmix["none"] += 1

        if mnem.lower() in FENCE_MNEMS:
            barriers["fence"] += 1
        if mnem.lower() in SERIALIZE_MNEMS:
            barriers["serialize"] += 1
        if mnem.lower() == "pause":
            barriers["pause"] += 1
        if mnem.lower() in SYSCALL_MNEMS or INT_INSN.match(mnem):
            barriers["syscall_like"] += 1
        if cat.startswith("branch") or cat.startswith("call") or cat == "return":
            branch_detail[cat] += 1

        # Track direct control-flow candidates to compute taken/not-taken on next IP.
        mm = mnem.lower()
        is_direct_cflow = False
        if (mm.startswith("j") and mm in COND_BRANCH) or mm.startswith("jmp") or mm.startswith("call"):
            is_direct_cflow = True
        if is_direct_cflow:
            mt = HEX_TARGET.search(asm)
            if mt:
                branch_pending = {
                    "tid": tid,
                    "ip": ip_hex or "",
                    "target": int(mt.group(1), 16),
                }

        reads_all, writes_all = infer_reg_rw(mnem, ops)
        reads_gpr, reads_vec = split_regs(reads_all)
        writes_gpr, writes_vec = split_regs(writes_all)
        tb = tid

        for r in reads_gpr:
            k = (tb, r)
            lw = last_write.get(k)
            if lw is not None:
                raw_dists.append(insn_idx - lw)

        for r in writes_gpr:
            k = (tb, r)
            lw = last_write.get(k)
            if lw is not None:
                waw_dists.append(insn_idx - lw)
            lr = last_read.get(k)
            if lr is not None:
                war_dists.append(insn_idx - lr)

        for r in reads_gpr:
            last_read[(tb, r)] = insn_idx
        for r in writes_gpr:
            last_write[(tb, r)] = insn_idx

        for r in reads_vec:
            k = (tb, r)
            lw = vlast_write.get(k)
            if lw is not None:
                vraw_dists.append(insn_idx - lw)
        for r in writes_vec:
            k = (tb, r)
            lw = vlast_write.get(k)
            if lw is not None:
                vwaw_dists.append(insn_idx - lw)
            lr = vlast_read.get(k)
            if lr is not None:
                vwar_dists.append(insn_idx - lr)
        for r in reads_vec:
            vlast_read[(tb, r)] = insn_idx
        for r in writes_vec:
            vlast_write[(tb, r)] = insn_idx

        insn_idx += 1
        parsed += 1
        if max_insns > 0 and parsed >= max_insns:
            break

    total_mix = sum(mix.values()) or 1
    mix_frac = {k: mix[k] / total_mix for k in mix}
    submix_frac = {k: submix[k] / total_mix for k in submix}
    opmix_frac = {k: opmix[k] / total_mix for k in opmix}

    def summarize_dists(name: str, ds: list[int]) -> dict:
        if not ds:
            return {"count": 0, "mean": 0.0, "median": 0.0, "buckets": {}}
        ds_sorted = sorted(ds)
        med = ds_sorted[len(ds_sorted) // 2]
        bk = Counter(bucket_dist(x) for x in ds)
        return {
            "count": len(ds),
            "mean": sum(ds) / len(ds),
            "median": float(med),
            "buckets": dict(bk),
        }

    ipc_summary: dict = {"annotated_blocks": ipc_lines, "values": {}}
    if ipc_values:
        ipc_summary["values"] = {
            "mean": sum(ipc_values) / len(ipc_values),
            **_quantiles(ipc_values, (0.5, 0.9, 0.99)),
        }
    if ipc_retire_nums and ipc_retire_dens:
        ratios = [n / d for n, d in zip(ipc_retire_nums, ipc_retire_dens) if d > 0]
        if ratios:
            ipc_summary["retire_ratio"] = {
                "mean": sum(ratios) / len(ratios),
                **_quantiles(ratios, (0.5, 0.9)),
            }
        total_ins = sum(ipc_retire_nums)
        total_cyc = sum(ipc_retire_dens)
        if total_cyc > 0:
            ipc_summary["total"] = {
                "insns": int(total_ins),
                "cycles": int(total_cyc),
                "ipc": float(total_ins / total_cyc),
            }

    return {
        "notes": {
            "gpr_dependencies": "Heuristic AT&T decode; per-TID; SIMD/flags not modeled.",
            "instruction_mix": "Textual mnemonic buckets; simd_or_vec_hint is coarse.",
        },
        "stats": {
            "parsed_instructions": parsed,
            "skipped_lines": skipped,
            "lines_with_ipc_annotation": ipc_lines,
        },
        "instruction_mix": {"counts": dict(mix), "fractions": mix_frac},
        "instruction_submix": {"counts": dict(submix), "fractions": submix_frac},
        "operand_mix": {"counts": dict(opmix), "fractions": opmix_frac},
        "barrier": {
            "detail_counts": dict(barriers),
            "per_1000_insns": {k: 1000.0 * v / total_mix for k, v in barriers.items()},
        },
        "branch": {
            "detail_counts": dict(branch_detail),
            "per_1000_insns": {k: 1000.0 * v / total_mix for k, v in branch_detail.items()},
        },
        "branch_behavior": _summarize_branch_behavior(
            site_taken=site_taken,
            site_not_taken=site_not_taken,
            site_unknown_next=site_unknown_next,
            site_transitions=site_transitions,
            site_outcomes=site_outcomes,
            pat_counts=pat_counts,
        ),
        "syscall": {
            "approx_insn_count": mix.get("syscall_class", 0),
            "per_1000_insns": 1000.0 * mix.get("syscall_class", 0) / total_mix,
        },
        "ipc": ipc_summary,
        "gpr_dependency_distance": {
            "raw": summarize_dists("raw", raw_dists),
            "waw": summarize_dists("waw", waw_dists),
            "war": summarize_dists("war", war_dists),
        },
        "vec_dependency_distance": {
            "raw": summarize_dists("raw", vraw_dists),
            "waw": summarize_dists("waw", vwaw_dists),
            "war": summarize_dists("war", vwar_dists),
        },
    }


def _summarize_branch_behavior(
    *,
    site_taken: Counter[tuple[int, str]],
    site_not_taken: Counter[tuple[int, str]],
    site_unknown_next: Counter[tuple[int, str]],
    site_transitions: Counter[tuple[int, str]],
    site_outcomes: Counter[tuple[int, str]],
    pat_counts: dict[int, Counter[int]],
) -> dict:
    sites = sorted(set(site_outcomes.keys()) | set(site_unknown_next.keys()))
    total_taken = sum(site_taken.values())
    total_not = sum(site_not_taken.values())
    total_known = total_taken + total_not
    total_unknown = sum(site_unknown_next.values())
    global_p = (total_taken / total_known) if total_known else 0.0

    # Site-level averages, weighted by known outcomes.
    w_sum = 0.0
    ent_sum = 0.0
    trans_sum = 0.0
    for s in sites:
        t = float(site_taken.get(s, 0))
        n = float(site_not_taken.get(s, 0))
        k = t + n
        if k <= 0:
            continue
        p = t / k
        ent = _h2(p)
        # transitions/(k-1) is per-site switching rate; use transitions count only over observed outcomes.
        tr = float(site_transitions.get(s, 0))
        tr_rate = tr / max(1.0, k - 1.0)
        w_sum += k
        ent_sum += ent * k
        trans_sum += tr_rate * k

    # Pattern summaries (global across sites).
    pat_summary: dict[str, dict[str, float | int]] = {}
    for L, c in pat_counts.items():
        total = sum(c.values())
        if total <= 0:
            pat_summary[str(L)] = {"total": 0, "distinct": 0, "top_mass": 0.0, "entropy": 0.0}
            continue
        ps = [v / total for v in c.values()]
        top = max(ps) if ps else 0.0
        ent = -sum(p * math.log2(p) for p in ps if p > 0.0)
        pat_summary[str(L)] = {
            "total": int(total),
            "distinct": int(len(c)),
            "top_mass": float(top),
            "entropy": float(ent),
        }

    return {
        "global": {
            "known_total": int(total_known),
            "unknown_next_ip_total": int(total_unknown),
            "taken_total": int(total_taken),
            "not_taken_total": int(total_not),
            "taken_rate": float(global_p),
            "entropy": float(_h2(global_p)),
        },
        "site_weighted": {
            "sites_with_known": int(sum(1 for s in sites if (site_taken.get(s, 0) + site_not_taken.get(s, 0)) > 0)),
            "entropy_mean": float(ent_sum / w_sum) if w_sum > 0 else 0.0,
            "transition_rate_mean": float(trans_sum / w_sum) if w_sum > 0 else 0.0,
        },
        "patterns": pat_summary,
    }


def analyze_file(path: Path, *, max_insns: int = 0) -> dict:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        return analyze_lines(f, max_insns=max_insns)


def flatten_portrait_metrics(report: dict, *, prefix: str = "portrait_") -> dict[str, float | int | str]:
    """Scalar metrics for CSV / batch summary."""
    out: dict[str, float | int | str] = {}
    st = report.get("stats", {})
    for k, v in st.items():
        if isinstance(v, (int, float)):
            out[f"{prefix}{k}"] = v
    mix = report.get("instruction_mix", {}).get("fractions", {})
    for k, v in mix.items():
        out[f"{prefix}mix_{k}"] = float(v)
    sub = report.get("instruction_submix", {}).get("fractions", {})
    for k, v in sub.items():
        out[f"{prefix}submix_{k}"] = float(v)
    opm = report.get("operand_mix", {}).get("fractions", {})
    for k, v in opm.items():
        out[f"{prefix}opmix_{k}"] = float(v)
    bar = report.get("barrier", {}).get("per_1000_insns", {})
    for k, v in bar.items():
        out[f"{prefix}barrier_{k}_per_1k"] = float(v)
    br = report.get("branch", {}).get("per_1000_insns", {})
    for k, v in br.items():
        out[f"{prefix}branch_{k}_per_1k"] = float(v)
    bb = report.get("branch_behavior", {})
    g = bb.get("global", {}) if isinstance(bb, dict) else {}
    if isinstance(g, dict):
        if isinstance(g.get("taken_rate"), (int, float)):
            out[f"{prefix}branch_taken_rate"] = float(g["taken_rate"])
        if isinstance(g.get("entropy"), (int, float)):
            out[f"{prefix}branch_taken_entropy"] = float(g["entropy"])
        if isinstance(g.get("unknown_next_ip_total"), (int, float)):
            out[f"{prefix}branch_unknown_next_ip_total"] = int(g["unknown_next_ip_total"])
    sw = bb.get("site_weighted", {}) if isinstance(bb, dict) else {}
    if isinstance(sw, dict):
        if isinstance(sw.get("entropy_mean"), (int, float)):
            out[f"{prefix}branch_site_entropy_mean"] = float(sw["entropy_mean"])
        if isinstance(sw.get("transition_rate_mean"), (int, float)):
            out[f"{prefix}branch_site_transition_rate_mean"] = float(sw["transition_rate_mean"])
    pats = bb.get("patterns", {}) if isinstance(bb, dict) else {}
    if isinstance(pats, dict):
        for L, pobj in pats.items():
            if not isinstance(pobj, dict):
                continue
            if isinstance(pobj.get("distinct"), (int, float)):
                out[f"{prefix}branch_pat{L}_distinct"] = int(pobj["distinct"])
            if isinstance(pobj.get("top_mass"), (int, float)):
                out[f"{prefix}branch_pat{L}_top_mass"] = float(pobj["top_mass"])
            if isinstance(pobj.get("entropy"), (int, float)):
                out[f"{prefix}branch_pat{L}_entropy"] = float(pobj["entropy"])
    sc = report.get("syscall", {})
    if "per_1000_insns" in sc:
        out[f"{prefix}syscall_per_1k"] = float(sc["per_1000_insns"])
    ipc = report.get("ipc", {})
    iv = ipc.get("values", {})
    for k, v in iv.items():
        if isinstance(v, (int, float)):
            out[f"{prefix}ipc_{k}"] = float(v)
    rr = ipc.get("retire_ratio", {})
    for k, v in rr.items():
        if isinstance(v, (int, float)):
            out[f"{prefix}ipc_retire_{k}"] = float(v)
    tot = ipc.get("total", {})
    if isinstance(tot, dict):
        if isinstance(tot.get("insns"), (int, float)):
            out[f"{prefix}ipc_total_insns"] = int(tot["insns"])
        if isinstance(tot.get("cycles"), (int, float)):
            out[f"{prefix}ipc_total_cycles"] = int(tot["cycles"])
        if isinstance(tot.get("ipc"), (int, float)):
            out[f"{prefix}ipc_total"] = float(tot["ipc"])
    for kind in ("raw", "waw", "war"):
        block = report.get("gpr_dependency_distance", {}).get(kind, {})
        for k, v in block.items():
            if k == "buckets":
                for bk, bv in (v or {}).items():
                    out[f"{prefix}{kind}_dist_bucket_{bk}"] = int(bv)
            elif k == "count" and isinstance(v, (int, float)):
                out[f"{prefix}{kind}_dist_count"] = int(v)
            elif isinstance(v, (int, float)):
                out[f"{prefix}{kind}_dist_{k}"] = float(v)
    for kind in ("raw", "waw", "war"):
        block = report.get("vec_dependency_distance", {}).get(kind, {})
        for k, v in block.items():
            if k == "buckets":
                for bk, bv in (v or {}).items():
                    out[f"{prefix}vec_{kind}_dist_bucket_{bk}"] = int(bv)
            elif k == "count" and isinstance(v, (int, float)):
                out[f"{prefix}vec_{kind}_dist_count"] = int(v)
            elif isinstance(v, (int, float)):
                out[f"{prefix}vec_{kind}_dist_{k}"] = float(v)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Instruction-trace portrait from perf script --xed output")
    ap.add_argument("--input", type=Path, required=True, help="Decoded insn trace (text)")
    ap.add_argument("--out-json", type=Path, required=True)
    ap.add_argument("--max-insns", type=int, default=0, help="Stop after N parsed instructions (0 = all)")
    args = ap.parse_args()
    rep = analyze_file(args.input, max_insns=max(0, args.max_insns))
    rep["input_path"] = str(args.input.resolve())
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(rep, indent=2, ensure_ascii=False), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
