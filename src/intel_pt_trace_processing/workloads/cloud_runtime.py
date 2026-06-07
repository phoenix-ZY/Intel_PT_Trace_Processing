from __future__ import annotations

import os
import json
import subprocess
import sys
import time
from pathlib import Path

from intel_pt_trace_processing.workloads.cloud import docker_cpuset_arg

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_WORKLOAD_CONFIG = Path(
    os.environ.get(
        "CLOUD_WORKLOAD_CONFIG",
        str(REPO_ROOT / "cloud_bench_configs" / "workloads.default.json"),
    )
)
NETWORK_NAME = "perf-net"
NETWORK_SUBNET = "172.30.0.0/24"
NETWORK_GATEWAY = "172.30.0.1"
BENCH_CONTAINER = "bench-client"
BENCH_IP = "172.30.0.20"

DOCKER_BENCH_CLIENT_IMAGE = os.environ.get(
    "DOCKER_BENCH_CLIENT_IMAGE",
    "local/bench-client-full:latest",
)


def log(icon: str, msg: str):
    print(f"  {icon}  {msg}", flush=True)

def run_cmd(cmd: list[str] | str, shell: bool = False, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, shell=shell, **kwargs)

def docker_run(args: str) -> subprocess.CompletedProcess:
    return run_cmd(f"docker run {args}", shell=True)

def docker_exec(container: str, cmd: str) -> subprocess.CompletedProcess:
    return run_cmd(f"docker exec {container} {cmd}", shell=True)

def docker_stop_rm(name: str):
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
        # Process exists but we lack permission to signal it (common when not running as root).
        return True
    except OSError:
        return False

def mysql_ready_from_bench_client(host: str, *, timeout_s: int = 120) -> bool:
    """
    Verify MySQL is reachable from BENCH_CONTAINER network namespace.
    This avoids false positives where mysqld is 'ready' internally but not reachable from bench-client.
    """
    deadline = time.monotonic() + float(timeout_s)
    while time.monotonic() < deadline:
        # mysqladmin is available in bench-client image; use TCP connect + auth.
        cmd = f"mysqladmin ping -h {host} -uroot -ppassword --silent"
        pr = docker_exec(BENCH_CONTAINER, cmd)
        if pr.returncode == 0:
            return True
        time.sleep(1)
    return False

def nginx_ready_from_bench_client(host: str, path: str = "/index.html", *, timeout_s: int = 60) -> bool:
    """Verify Nginx is reachable from BENCH_CONTAINER (HTTP 2xx/3xx)."""
    deadline = time.monotonic() + float(timeout_s)
    url = f"http://{host}{path}"
    while time.monotonic() < deadline:
        # bench-client image may not ship wget; prefer curl when available.
        pr = docker_exec(
            BENCH_CONTAINER,
            "sh -lc "
            + "\""
            + f"(command -v curl >/dev/null 2>&1 && curl -fsS --max-time 2 {url} >/dev/null)"
            + " || "
            + f"(command -v wget >/dev/null 2>&1 && wget -q -O- --timeout=2 --tries=1 {url} >/dev/null)"
            + "\"",
        )
        if pr.returncode == 0:
            return True
        time.sleep(1)
    return False

def sysbench_output_looks_failed(out: str, err: str) -> bool:
    t = (out or "") + "\n" + (err or "")
    t = t.lower()
    # sysbench sometimes returns 0 even when Lua layer prints fatal errors.
    bad_markers = (
        "fatal:",
        "unable to connect",
        "connection creation failed",
        "lost connection to mysql server",
    )
    return any(m in t for m in bad_markers)

def ensure_network():
    result = run_cmd(["docker", "network", "inspect", NETWORK_NAME])
    if result.returncode != 0:
        log("🌐", f"Creating Docker network {NETWORK_NAME}")
        run_cmd([
            "docker", "network", "create",
            "--driver", "bridge",
            "--subnet", NETWORK_SUBNET,
            "--gateway", NETWORK_GATEWAY,
            NETWORK_NAME,
        ])

def cleanup_all(extra_containers: list[str] | None = None):
    """Stop and remove all known containers and the network."""
    log("🧹", "Cleaning up old resources...")
    containers = [
        "target-redis",
        "target-nginx",
        "target-mysql",
        "target-memcached",
        "target-haproxy",
        "target-postgres",
        "target-feedsim",
        "target-taobench-server",
        "target-nginx-helper",
        "helper-taobench-loadgen",
        BENCH_CONTAINER,
    ]
    for name in extra_containers or []:
        if name not in containers:
            containers.append(name)
    for name in containers:
        docker_stop_rm(name)
    run_cmd(["docker", "network", "rm", NETWORK_NAME])

def ensure_bench_client(project_dir: Path, *, cpuset: str | None = None):
    """Start the bench-client container if not running."""
    result = run_cmd(["docker", "ps", "--format", "{{.Names}}"])
    if BENCH_CONTAINER in result.stdout.splitlines():
        return
    log("🔧", "Starting bench-client container...")
    docker_run(
        f"-d --name {BENCH_CONTAINER} "
        f"{docker_cpuset_arg(cpuset)}"
        f"--network {NETWORK_NAME} --ip {BENCH_IP} "
        f"--ulimit nofile=655350:655350 "
        f"-v {project_dir}:/data "
        f"--entrypoint sleep "
        f"{DOCKER_BENCH_CLIENT_IMAGE} infinity"
    )
    time.sleep(3)

def wait_for_tool(tool: str, timeout: int = 60):
    """Wait until a tool is available inside the bench-client container."""
    log("⏳", f"Waiting for tool '{tool}' in bench-client...")
    for _ in range(timeout // 2):
        result = docker_exec(BENCH_CONTAINER, f"which {tool}")
        if result.returncode == 0:
            return
        time.sleep(2)
    sys.exit(f"❌ Tool '{tool}' not available in bench-client after {timeout}s")

def ensure_static_files(project_dir: Path):
    """Create www/ and certs/ directories with required files."""
    www_dir = project_dir / "www"
    certs_dir = project_dir / "certs"
    www_dir.mkdir(exist_ok=True)
    certs_dir.mkdir(exist_ok=True)

    index_file = www_dir / "index.html"
    if not index_file.exists():
        index_file.write_text("Benchmark Baseline\n")

    for name, size_kb in [("1k.bin", 1), ("64k.bin", 64)]:
        fpath = www_dir / name
        if not fpath.exists():
            run_cmd(
                f"dd if=/dev/urandom of={fpath} bs=1024 count={size_kb}",
                shell=True,
            )

    combined = certs_dir / "combined.pem"
    if not combined.exists():
        run_cmd(
            f"openssl req -x509 -nodes -days 365 -newkey rsa:2048 "
            f"-keyout {certs_dir}/server.key -out {certs_dir}/server.crt "
            f'-subj "/CN=target"',
            shell=True,
        )
        key_data = (certs_dir / "server.key").read_text()
        crt_data = (certs_dir / "server.crt").read_text()
        combined.write_text(crt_data + key_data)

def normalize_cloud_config(config: dict, project_dir: Path) -> dict:
    """Validate a JSON workload config and attach legacy access keys."""
    for key in ("service_type", "config_name", "target_role", "load_cmd"):
        if key not in config:
            raise ValueError(f"workload config missing {key!r}: {config!r}")
    target_role = config.get("target_role")
    if not isinstance(target_role, dict):
        raise ValueError(f"target_role must be an object: {config!r}")
    for key in ("container_name", "start_cmd"):
        if key not in target_role:
            raise ValueError(f"target_role missing {key!r}: {config!r}")

    config.setdefault("container_name", target_role["container_name"])
    config.setdefault("server_cmd", target_role["start_cmd"])
    config.setdefault("bench_cmd", config.get("load_cmd", ""))
    config.setdefault("helper_roles", [])
    config.setdefault("ready_checks", [])
    config.setdefault("prepare_steps", [])
    config.setdefault("startup_wait_s", 5)

    for key in ("startup_wait_s", "warmup_duration_s", "bench_duration_s"):
        if key in config and int(config[key]) < 0:
            raise ValueError(f"{key} must be >= 0: {config!r}")

    if not isinstance(config["helper_roles"], list):
        raise ValueError(f"helper_roles must be a list: {config!r}")
    for helper in config["helper_roles"]:
        if not isinstance(helper, dict):
            raise ValueError(f"helper role must be an object: {config!r}")
        for key in ("container_name", "start_cmd"):
            if key not in helper:
                raise ValueError(f"helper role missing {key!r}: {config!r}")
    return config


def normalize_cloud_config_matrix(matrix: dict[str, list[dict]], project_dir: Path) -> dict[str, list[dict]]:
    for configs in matrix.values():
        for config in configs:
            normalize_cloud_config(config, project_dir)
    return matrix


def load_workload_config_file(path: Path, project_dir: Path) -> dict[str, list[dict]]:
    """Load additional workload configs from JSON and normalize them like built-ins."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"failed to read workload config {path}: {exc}") from exc

    if isinstance(payload, list):
        workloads = payload
    elif isinstance(payload, dict) and isinstance(payload.get("workloads"), list):
        workloads = payload["workloads"]
    elif isinstance(payload, dict) and isinstance(payload.get("services"), dict):
        matrix = payload["services"]
        if not all(isinstance(v, list) for v in matrix.values()):
            raise ValueError(f"workload config {path} services values must be lists")
        return normalize_cloud_config_matrix(matrix, project_dir)
    else:
        raise ValueError(
            f"workload config {path} must be a list, {{'workloads': [...]}} or {{'services': {{...}}}}"
        )

    matrix: dict[str, list[dict]] = {}
    for idx, config in enumerate(workloads):
        if not isinstance(config, dict):
            raise ValueError(f"workload config {path} item {idx} is not an object")
        for key in ("service_type", "config_name", "target_role", "load_cmd"):
            if key not in config:
                raise ValueError(f"workload config {path} item {idx} missing {key!r}")
        matrix.setdefault(str(config["service_type"]), []).append(config)
    return normalize_cloud_config_matrix(matrix, project_dir)


def merge_config_matrix(base: dict[str, list[dict]], extra: dict[str, list[dict]]) -> dict[str, list[dict]]:
    """Merge workload configs, replacing service.config_name on conflict."""
    for service, configs in extra.items():
        existing = {cfg["config_name"]: i for i, cfg in enumerate(base.get(service, []))}
        if service not in base:
            base[service] = []
        for config in configs:
            config_name = config["config_name"]
            if config_name in existing:
                base[service][existing[config_name]] = config
            else:
                base[service].append(config)
                existing[config_name] = len(base[service]) - 1
    return base


def workload_container_names(matrix: dict[str, list[dict]]) -> list[str]:
    names: list[str] = []
    for configs in matrix.values():
        for config in configs:
            target_role = config.get("target_role", {})
            for name in (config.get("container_name"), target_role.get("container_name")):
                if name and name not in names:
                    names.append(str(name))
            for helper in config.get("helper_roles", []):
                name = helper.get("container_name") if isinstance(helper, dict) else None
                if name and name not in names:
                    names.append(str(name))
    return names


def build_config_matrix(project_dir: Path, *, target_cpuset: str | None = None) -> dict[str, list[dict]]:
    """
    Load the default cloud workload matrix from external JSON.

    target_cpuset is accepted for backward compatibility; the JSON commands use
    {target_cpuset} / {target_cpuset_arg} placeholders rendered at run time.
    """
    return load_workload_config_file(DEFAULT_WORKLOAD_CONFIG, project_dir)
