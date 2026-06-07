from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


CPU_LIST_RE = re.compile(r"^\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*$")


def normalize_cpu_spec(value: int | str) -> str:
    spec = str(value).strip()
    if not spec or not CPU_LIST_RE.fullmatch(spec):
        raise ValueError(
            f"invalid CPU list {value!r}; expected N, N-M, or comma-separated ranges"
        )
    for part in spec.split(","):
        if "-" not in part:
            continue
        start, end = (int(item) for item in part.split("-", 1))
        if end < start:
            raise ValueError(f"invalid descending CPU range {part!r}")
    return spec


@dataclass(frozen=True)
class PerfTarget:
    """CPU/core target selector for perf record/stat."""

    cpu: int | str

    @property
    def flag(self) -> str:
        return "-C"

    def args(self) -> list[str]:
        return [self.flag, normalize_cpu_spec(self.cpu)]

    def to_json(self) -> dict[str, int | str]:
        spec = normalize_cpu_spec(self.cpu)
        if spec.isdigit():
            return {"kind": "cpu", "flag": self.flag, "id": int(spec)}
        return {"kind": "cpu-list", "flag": self.flag, "id": spec}


def add_perf_target_args(
    parser: argparse.ArgumentParser,
    *,
    default_cpu: int = 6,
) -> None:
    parser.add_argument(
        "--perf-cpu",
        type=int,
        default=default_cpu,
        help="CPU/core id recorded with perf -C.",
    )


def validate_perf_target_args(args: argparse.Namespace) -> None:
    cpu = int(getattr(args, "perf_cpu", 0))
    if cpu < 0:
        raise SystemExit("--perf-cpu must be >= 0")


def cpu_perf_target(cpu: int | str) -> PerfTarget:
    return PerfTarget(cpu=normalize_cpu_spec(cpu))


def perf_record_cmd(
    *,
    perf_tool: str | Path,
    mmap_pages: str | int,
    event: str,
    output: Path,
    target: PerfTarget,
    duration_s: float,
    quiet: bool = False,
    cgroup: str | None = None,
    command_prefix: Sequence[str] = (),
) -> list[str]:
    cmd = [*command_prefix, str(perf_tool), "record"]
    if quiet:
        cmd.append("-q")
    cmd.extend(["-m", str(mmap_pages), "-e", event, "-o", str(output)])
    if cgroup:
        cmd.append("-a")
    cmd.extend(target.args())
    if cgroup:
        cmd.extend(["-G", cgroup])
    cmd.extend(["--", "sleep", str(duration_s)])
    return cmd


def perf_stat_cmd(
    *,
    perf_tool: str | Path,
    events: str,
    target: PerfTarget,
    duration_s: float,
    cgroup: str | None = None,
    command_prefix: Sequence[str] = (),
) -> list[str]:
    cmd = [
        *command_prefix,
        str(perf_tool),
        "stat",
        "-x",
        ",",
        "-e",
        events,
    ]
    if cgroup:
        cmd.append("-a")
    cmd.extend(target.args())
    if cgroup:
        cmd.extend(["-G", cgroup])
    cmd.extend(["--", "sleep", str(duration_s)])
    return cmd


def write_perf_stat_json(
    *,
    out_json: Path,
    out_txt: Path,
    raw: str,
    returncode: int,
    duration_s: float,
    events: str,
    target: PerfTarget,
    metrics: dict[str, float],
    unsupported_events: list[str],
    extra: dict | None = None,
) -> None:
    payload = {
        "schema": "perf-stat-v1",
        "target": target.to_json(),
        "duration_s": float(duration_s),
        "events": events,
        "returncode": int(returncode),
        "metrics": metrics,
        "unsupported_events": unsupported_events,
        "raw_path": str(out_txt),
    }
    if extra:
        payload.update(extra)
    out_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def run_perf_stat(
    *,
    perf_tool: str | Path,
    target: PerfTarget,
    duration_s: float,
    out_txt: Path,
    out_json: Path,
    events: str,
    parse_metrics,
    parse_unsupported,
    extra: dict | None = None,
    cgroup: str | None = None,
    command_prefix: Sequence[str] = (),
) -> tuple[int, int]:
    out_txt.parent.mkdir(parents=True, exist_ok=True)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    pr = subprocess.run(
        perf_stat_cmd(
            perf_tool=perf_tool,
            events=events,
            target=target,
            duration_s=duration_s,
            cgroup=cgroup,
            command_prefix=command_prefix,
        ),
        capture_output=True,
        text=True,
    )
    raw = (pr.stderr or "") + (("\n" + pr.stdout) if pr.stdout else "")
    out_txt.write_text(raw, encoding="utf-8", errors="replace")
    write_perf_stat_json(
        out_json=out_json,
        out_txt=out_txt,
        raw=raw,
        returncode=pr.returncode,
        duration_s=duration_s,
        events=events,
        target=target,
        metrics=parse_metrics(raw),
        unsupported_events=parse_unsupported(raw),
        extra=extra,
    )
    return pr.returncode, len(raw)
