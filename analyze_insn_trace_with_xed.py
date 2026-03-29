#!/usr/bin/env python3
import argparse
import json
import random
import re
import subprocess
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional


INSN_RE = re.compile(
    r"^\s*(?P<tid>\d+)\s+(?P<ts>[^:]+):\s+(?P<ip>[0-9a-fA-F]+)\s+insn:\s+(?P<bytes>[0-9a-fA-F ]+)\s*$"
)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Sample SDE insn.trace lines, decode bytes with xed, and summarize ISA categories."
    )
    p.add_argument("--insn-trace", required=True, help="Path to *.insn.trace.txt")
    p.add_argument(
        "--out-json",
        required=True,
        help="Where to write JSON summary report",
    )
    p.add_argument(
        "--xed-bin",
        default="/usr/bin/xed",
        help="Path to xed binary (default: /usr/bin/xed)",
    )
    p.add_argument(
        "--sample-size",
        type=int,
        default=5000,
        help="Reservoir sample size of candidate instructions (default: 5000)",
    )
    p.add_argument(
        "--seed",
        type=int,
        default=1,
        help="Random seed for sampling (default: 1)",
    )
    p.add_argument(
        "--max-lines",
        type=int,
        default=0,
        help="If >0, stop scanning after this many lines",
    )
    p.add_argument(
        "--prefix-filter",
        default="",
        help="Optional comma-separated first-byte hex filter, e.g. '62,c4,c5'",
    )
    return p.parse_args()


def parse_prefix_filter(s: str) -> Optional[set]:
    s = s.strip()
    if not s:
        return None
    out = set()
    for part in s.split(","):
        v = part.strip().lower()
        if not v:
            continue
        if len(v) != 2 or any(c not in "0123456789abcdef" for c in v):
            raise ValueError(f"Invalid prefix byte '{part}' in --prefix-filter")
        out.add(v)
    return out if out else None


def decode_with_xed(xed_bin: str, hex_bytes: str) -> Dict[str, str]:
    cmd = [xed_bin, "-64", "-d", hex_bytes]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        return {
            "decode_status": "error",
            "error": (proc.stderr or proc.stdout).strip()[:400],
        }

    fields: Dict[str, str] = {"decode_status": "ok"}
    for line in proc.stdout.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        key = k.strip()
        value = v.strip()
        if key in {"ICLASS", "CATEGORY", "EXTENSION", "ISA_SET", "SHORT"}:
            fields[key.lower()] = value
    return fields


def main() -> None:
    args = parse_args()
    random.seed(args.seed)

    prefix_filter = parse_prefix_filter(args.prefix_filter)
    trace_path = Path(args.insn_trace)
    out_path = Path(args.out_json)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    scanned_lines = 0
    parsed_insn_lines = 0
    candidate_lines = 0

    candidate_bytes_counter: Counter = Counter()
    reservoir: List[Dict[str, object]] = []

    with trace_path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, start=1):
            scanned_lines += 1
            if args.max_lines > 0 and scanned_lines > args.max_lines:
                break

            m = INSN_RE.match(line.rstrip("\n"))
            if not m:
                continue
            parsed_insn_lines += 1

            raw_bytes = "".join(m.group("bytes").split()).lower()
            if len(raw_bytes) < 2:
                continue

            first_byte = raw_bytes[:2]
            if prefix_filter is not None and first_byte not in prefix_filter:
                continue

            candidate_lines += 1
            candidate_bytes_counter[raw_bytes] += 1

            entry = {
                "line_no": line_no,
                "ip": m.group("ip").lower(),
                "bytes": raw_bytes,
                "first_byte": first_byte,
                "text": line.rstrip("\n"),
            }

            if len(reservoir) < args.sample_size:
                reservoir.append(entry)
            else:
                j = random.randint(1, candidate_lines)
                if j <= args.sample_size:
                    reservoir[j - 1] = entry

    # Decode unique byte strings in sampled reservoir only (keeps xed calls bounded).
    sampled_bytes = sorted({str(x["bytes"]) for x in reservoir})
    decode_cache: Dict[str, Dict[str, str]] = {}
    for b in sampled_bytes:
        decode_cache[b] = decode_with_xed(args.xed_bin, b)

    sample_counter = Counter(str(x["bytes"]) for x in reservoir)

    extension_counter = Counter()
    category_counter = Counter()
    isa_set_counter = Counter()
    iclass_counter = Counter()
    decode_status_counter = Counter()

    decoded_samples: List[Dict[str, object]] = []
    for item in reservoir:
        b = str(item["bytes"])
        dec = decode_cache.get(b, {"decode_status": "error", "error": "missing decode cache"})
        status = dec.get("decode_status", "unknown")
        decode_status_counter[status] += 1

        ext = dec.get("extension", "UNKNOWN")
        cat = dec.get("category", "UNKNOWN")
        isa = dec.get("isa_set", "UNKNOWN")
        iclass = dec.get("iclass", "UNKNOWN")
        extension_counter[ext] += 1
        category_counter[cat] += 1
        isa_set_counter[isa] += 1
        iclass_counter[iclass] += 1

        decoded_samples.append(
            {
                "line_no": item["line_no"],
                "ip": item["ip"],
                "bytes": b,
                "first_byte": item["first_byte"],
                "sample_count_same_bytes": sample_counter[b],
                "global_count_same_bytes": candidate_bytes_counter.get(b, 0),
                "decode": dec,
            }
        )

    report = {
        "input": {
            "insn_trace": str(trace_path),
            "xed_bin": args.xed_bin,
            "sample_size": args.sample_size,
            "seed": args.seed,
            "max_lines": args.max_lines,
            "prefix_filter": sorted(prefix_filter) if prefix_filter else [],
        },
        "stats": {
            "scanned_lines": scanned_lines,
            "parsed_insn_lines": parsed_insn_lines,
            "candidate_lines": candidate_lines,
            "sampled_lines": len(reservoir),
            "sampled_unique_byte_strings": len(sampled_bytes),
            "decode_status": dict(decode_status_counter.most_common()),
            "top_extension": dict(extension_counter.most_common(20)),
            "top_category": dict(category_counter.most_common(20)),
            "top_isa_set": dict(isa_set_counter.most_common(30)),
            "top_iclass": dict(iclass_counter.most_common(30)),
            "top_candidate_bytes_global": [
                {"bytes": b, "count": c} for b, c in candidate_bytes_counter.most_common(30)
            ],
        },
        "samples": decoded_samples,
    }

    with out_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
        f.write("\n")

    print(f"wrote: {out_path}")
    print(
        json.dumps(
            {
                "candidate_lines": candidate_lines,
                "sampled_lines": len(reservoir),
                "sampled_unique": len(sampled_bytes),
                "decode_status": dict(decode_status_counter),
                "top_extension": dict(extension_counter.most_common(5)),
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
