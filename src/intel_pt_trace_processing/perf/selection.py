from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any


_FORK_RE = re.compile(r"PERF_RECORD_FORK\((\d+):\d+\):\((\d+):\d+\)")


def selection_sidecar_path(perf_data: Path) -> Path:
    return perf_data.with_name(f"{perf_data.name}.selection.json")


def write_selection_sidecar(perf_data: Path, selection: dict[str, Any]) -> Path:
    path = selection_sidecar_path(perf_data)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"schema": "trace-selection-v1", **selection}
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def load_selection_sidecar(perf_data: Path) -> dict[str, Any] | None:
    path = selection_sidecar_path(perf_data)
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def discover_process_tree_pids(
    *,
    perf_tool: str | Path,
    perf_data: Path,
    root_pid: int,
) -> list[int]:
    cmd = [
        str(perf_tool),
        "script",
        "-f",
        "--no-itrace",
        "--show-task-events",
        "-i",
        str(perf_data),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        detail = (result.stderr or "").strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        raise RuntimeError(f"cannot read perf task events (rc={result.returncode}){suffix}")

    children_by_parent: dict[int, set[int]] = {}
    for match in _FORK_RE.finditer(result.stdout or ""):
        child_pid = int(match.group(1))
        parent_pid = int(match.group(2))
        if child_pid != parent_pid:
            children_by_parent.setdefault(parent_pid, set()).add(child_pid)

    selected = {int(root_pid)}
    pending = [int(root_pid)]
    while pending:
        parent = pending.pop()
        for child in children_by_parent.get(parent, ()):
            if child not in selected:
                selected.add(child)
                pending.append(child)
    return sorted(selected)
