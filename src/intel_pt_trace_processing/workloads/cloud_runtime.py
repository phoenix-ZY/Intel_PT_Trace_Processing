"""Docker + cgroup helpers for Intel PT collection. Workload config lives in CBS."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from intel_pt_trace_processing.workloads.cbs_images import default_cbs_root, ensure_cbs_image_env

ensure_cbs_image_env()

NETWORK_NAME = "perf-net"
BENCH_CONTAINER = "bench-client"


def default_workload_config_path() -> Path:
    if os.environ.get("CLOUD_WORKLOAD_CONFIG"):
        return Path(os.environ["CLOUD_WORKLOAD_CONFIG"])
    cbs_path = default_cbs_root() / "cloud_bench_configs" / "workloads.cloud.json"
    if not cbs_path.is_file():
        raise FileNotFoundError(
            f"CBS workload config not found: {cbs_path}. "
            "Set CBS_ROOT or COLOCATION_BENCH_SUITE_DIR to colocation-bench-suite."
        )
    return cbs_path


def _import_cbs_workload_lib():
    cbs_root = default_cbs_root()
    scripts = cbs_root / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import cloud_workload_lib as cwl

    return cwl


def load_workload_config_file(path: Path, project_dir: Path | None = None) -> dict[str, list[dict]]:
    del project_dir  # CBS launchers resolve paths via {colocation_bench_suite_dir}
    return _import_cbs_workload_lib().load_workload_config_file(path)


def merge_config_matrix(base: dict[str, list[dict]], extra: dict[str, list[dict]]) -> dict[str, list[dict]]:
    return _import_cbs_workload_lib().merge_config_matrix(base, extra)


def workload_container_names(matrix: dict[str, list[dict]]) -> list[str]:
    return _import_cbs_workload_lib().workload_container_names(matrix)


def log(icon: str, msg: str) -> None:
    print(f"  {icon}  {msg}", flush=True)


def run_cmd(cmd: list[str] | str, shell: bool = False, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, shell=shell, **kwargs)


def docker_exec(container: str, cmd: str) -> subprocess.CompletedProcess:
    return run_cmd(f"docker exec {container} {cmd}", shell=True)


def docker_stop_rm(name: str) -> None:
    run_cmd(f"docker stop {name}", shell=True)
    run_cmd(f"docker rm -f {name}", shell=True)


def docker_inspect_pid(container: str) -> int | None:
    result = run_cmd(["docker", "inspect", "-f", "{{.State.Pid}}", container])
    pid_str = result.stdout.strip()
    if pid_str and pid_str.isdigit() and int(pid_str) > 0:
        return int(pid_str)
    return None


def docker_perf_event_cgroup(container_pid: int) -> str | None:
    try:
        lines = Path(f"/proc/{container_pid}/cgroup").read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
    except OSError:
        return None
    for line in lines:
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        cgroup = parts[2].strip().lstrip("/")
        if not cgroup:
            continue
        controllers = parts[1].split(",")
        if not parts[1]:
            if (Path("/sys/fs/cgroup") / cgroup).is_dir():
                return cgroup
            continue
        if "perf_event" not in controllers:
            continue
        if not (Path("/sys/fs/cgroup/perf_event") / cgroup).is_dir():
            continue
        return cgroup
    return None


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except OSError:
        return False
