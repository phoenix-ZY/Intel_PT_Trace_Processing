from __future__ import annotations

import shlex
from pathlib import Path


def build_spec_shell_command(*, cmd_line: str, shrc: Path, cpuset: str | None) -> str:
    env_prefix = f"source {shlex.quote(str(shrc))} >/dev/null 2>&1 || true; " if shrc.exists() else ""
    launch = cmd_line
    if cpuset:
        launch = f"taskset -c {shlex.quote(str(cpuset))} {cmd_line}"
    return f"{env_prefix}exec {launch}"
