from __future__ import annotations

import shlex


def docker_cpuset_arg(cpuset: str | None) -> str:
    if not cpuset:
        return ""
    return f"--cpuset-cpus={shlex.quote(str(cpuset))} "
