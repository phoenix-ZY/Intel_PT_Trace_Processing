from __future__ import annotations

import shlex
import subprocess
from pathlib import Path


def run_step(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    verbose: bool = False,
    stdout_path: Path | None = None,
    stderr_path: Path | None = None,
    append_logs: bool = False,
) -> None:
    if verbose:
        print("[cmd]", " ".join(shlex.quote(x) for x in cmd))
    out_fp = None
    err_fp = None
    try:
        if stdout_path is not None:
            stdout_path.parent.mkdir(parents=True, exist_ok=True)
            out_fp = stdout_path.open("a" if append_logs else "w", encoding="utf-8")
        if stderr_path is not None:
            stderr_path.parent.mkdir(parents=True, exist_ok=True)
            err_fp = stderr_path.open("a" if append_logs else "w", encoding="utf-8")
        subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            check=True,
            text=True,
            stdout=out_fp if out_fp is not None else (None if verbose else subprocess.DEVNULL),
            stderr=err_fp if err_fp is not None else (None if verbose else subprocess.DEVNULL),
        )
    finally:
        if out_fp is not None:
            out_fp.close()
        if err_fp is not None:
            err_fp.close()
