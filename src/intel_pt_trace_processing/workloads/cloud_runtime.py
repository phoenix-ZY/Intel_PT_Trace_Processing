from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

from intel_pt_trace_processing.workloads.cloud import docker_cpuset_arg

NETWORK_NAME = "perf-net"
NETWORK_SUBNET = "172.30.0.0/24"
NETWORK_GATEWAY = "172.30.0.1"
BENCH_CONTAINER = "bench-client"
BENCH_IP = "172.30.0.20"

SERVICE_IPS = {
    "redis": "172.30.0.10",
    "nginx": "172.30.0.11",
    "mysql": "172.30.0.12",
    "memcached": "172.30.0.13",
    "haproxy": "172.30.0.14",
    "postgres": "172.30.0.16",
}

DOCKER_MYSQL_IMAGE = "mysql:8.0"
DOCKER_MEMCACHED_IMAGE = "memcached:1.6"

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

def cleanup_all():
    """Stop and remove all known containers and the network."""
    log("🧹", "Cleaning up old resources...")
    containers = [
        "target-redis",
        "target-nginx",
        "target-mysql",
        "target-memcached",
        "target-haproxy",
        "target-postgres",
        "target-nginx-helper",
        BENCH_CONTAINER,
    ]
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
        f"local/bench-client-full:latest infinity"
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

def build_config_matrix(project_dir: Path, *, target_cpuset: str | None = None) -> dict[str, list[dict]]:
    """
    One representative configuration per cloud service in the matrix.
    """
    nginx_conf = project_dir / "cloud_bench_configs" / "nginx-http.conf"
    haproxy_cfg = project_dir / "cloud_bench_configs" / "haproxy-http.cfg"
    cpuset_arg = docker_cpuset_arg(target_cpuset)

    # Redis: vary persistence and load intensity.
    redis_server_base = (
        f"docker run -d --name target-redis "
        f"{cpuset_arg}"
        f"--network {NETWORK_NAME} --ip {SERVICE_IPS['redis']} "
        f"redis:7.2-alpine redis-server "
    )
    redis_bench_base = (
        f"docker exec {BENCH_CONTAINER} memtier_benchmark "
        f"-s {SERVICE_IPS['redis']} -p 6379 "
    )
    redis_configs = [
        {
            "config_name": "classic",
            "server_cmd": redis_server_base + "--save '' --appendonly no",
            "bench_cmd": redis_bench_base + "-c 50 --pipeline 32 --test-time {bench_duration}",
            "container_name": "target-redis",
            "service_type": "redis",
            "bench_tool": "memtier_benchmark",
        },
        {
            "config_name": "lowload",
            "server_cmd": redis_server_base + "--save '' --appendonly no",
            "bench_cmd": redis_bench_base + "-c 10 --pipeline 8 --test-time {bench_duration}",
            "container_name": "target-redis",
            "service_type": "redis",
            "bench_tool": "memtier_benchmark",
        },
        {
            "config_name": "highload",
            "server_cmd": redis_server_base + "--save '' --appendonly no",
            "bench_cmd": redis_bench_base + "-c 200 --pipeline 64 --test-time {bench_duration}",
            "container_name": "target-redis",
            "service_type": "redis",
            "bench_tool": "memtier_benchmark",
        },
        {
            "config_name": "aof",
            "server_cmd": redis_server_base + "--save '' --appendonly yes --appendfsync everysec",
            "bench_cmd": redis_bench_base + "-c 50 --pipeline 32 --test-time {bench_duration}",
            "container_name": "target-redis",
            "service_type": "redis",
            "bench_tool": "memtier_benchmark",
        },
        {
            "config_name": "maxmem256m",
            "server_cmd": redis_server_base + "--save '' --appendonly no --maxmemory 256mb --maxmemory-policy allkeys-lru",
            "bench_cmd": redis_bench_base + "-c 50 --pipeline 32 --test-time {bench_duration}",
            "container_name": "target-redis",
            "service_type": "redis",
            "bench_tool": "memtier_benchmark",
        },
    ]

    # Nginx: vary worker count and request size/connection pressure.
    nginx_server_base = (
        f"docker run -d --name target-nginx "
        f"{cpuset_arg}"
        f"--network {NETWORK_NAME} --ip {SERVICE_IPS['nginx']} "
        f"-v {project_dir}/www:/usr/share/nginx/html:ro "
        f"-v {nginx_conf}:/etc/nginx/nginx.conf:ro "
        f"nginx:alpine "
    )
    nginx_configs = [
        {
            "config_name": "w1_small",
            "server_cmd": nginx_server_base.replace("nginx:alpine ", "-e NGINX_WORKER_PROCESSES=1 nginx:alpine "),
            "bench_cmd": f"docker exec {BENCH_CONTAINER} wrk -t2 -c 30 -d {{bench_duration}}s http://{SERVICE_IPS['nginx']}/index.html",
            "container_name": "target-nginx",
            "service_type": "nginx",
            "bench_tool": "wrk",
        },
        {
            "config_name": "w4_small",
            "server_cmd": nginx_server_base.replace("nginx:alpine ", "-e NGINX_WORKER_PROCESSES=4 nginx:alpine "),
            "bench_cmd": f"docker exec {BENCH_CONTAINER} wrk -t2 -c 50 -d {{bench_duration}}s http://{SERVICE_IPS['nginx']}/index.html",
            "container_name": "target-nginx",
            "service_type": "nginx",
            "bench_tool": "wrk",
        },
        {
            "config_name": "w8_small",
            "server_cmd": nginx_server_base.replace("nginx:alpine ", "-e NGINX_WORKER_PROCESSES=8 nginx:alpine "),
            "bench_cmd": f"docker exec {BENCH_CONTAINER} wrk -t4 -c 200 -d {{bench_duration}}s http://{SERVICE_IPS['nginx']}/index.html",
            "container_name": "target-nginx",
            "service_type": "nginx",
            "bench_tool": "wrk",
        },
        {
            "config_name": "w4_1k",
            "server_cmd": nginx_server_base.replace("nginx:alpine ", "-e NGINX_WORKER_PROCESSES=4 nginx:alpine "),
            "bench_cmd": f"docker exec {BENCH_CONTAINER} wrk -t2 -c 80 -d {{bench_duration}}s http://{SERVICE_IPS['nginx']}/1k.bin",
            "container_name": "target-nginx",
            "service_type": "nginx",
            "bench_tool": "wrk",
        },
        {
            "config_name": "w4_64k",
            "server_cmd": nginx_server_base.replace("nginx:alpine ", "-e NGINX_WORKER_PROCESSES=4 nginx:alpine "),
            "bench_cmd": f"docker exec {BENCH_CONTAINER} wrk -t2 -c 30 -d {{bench_duration}}s http://{SERVICE_IPS['nginx']}/64k.bin",
            "container_name": "target-nginx",
            "service_type": "nginx",
            "bench_tool": "wrk",
        },
    ]

    # HAProxy: vary concurrency and thread mode via env (config file may or may not use it; still changes runtime).
    haproxy_server_base = (
        f"docker run -d --name target-haproxy "
        f"{cpuset_arg}"
        f"--network {NETWORK_NAME} --ip {SERVICE_IPS['haproxy']} "
        f"-v {haproxy_cfg}:/usr/local/etc/haproxy/haproxy.cfg:ro "
        f"haproxy:2.8"
    )
    haproxy_configs = [
        {
            "config_name": "lowconn",
            "server_cmd": haproxy_server_base,
            "bench_cmd": f"docker exec {BENCH_CONTAINER} wrk -t2 -c 30 -d {{bench_duration}}s http://{SERVICE_IPS['haproxy']}:9000/",
            "container_name": "target-haproxy",
            "service_type": "haproxy",
            "bench_tool": "wrk",
            "needs_nginx_backend": True,
        },
        {
            "config_name": "classic",
            "server_cmd": haproxy_server_base,
            "bench_cmd": f"docker exec {BENCH_CONTAINER} wrk -t2 -c 100 -d {{bench_duration}}s http://{SERVICE_IPS['haproxy']}:9000/",
            "container_name": "target-haproxy",
            "service_type": "haproxy",
            "bench_tool": "wrk",
            "needs_nginx_backend": True,
        },
        {
            "config_name": "highconn",
            "server_cmd": haproxy_server_base,
            "bench_cmd": f"docker exec {BENCH_CONTAINER} wrk -t4 -c 400 -d {{bench_duration}}s http://{SERVICE_IPS['haproxy']}:9000/",
            "container_name": "target-haproxy",
            "service_type": "haproxy",
            "bench_tool": "wrk",
            "needs_nginx_backend": True,
        },
        {
            "config_name": "shortreq",
            "server_cmd": haproxy_server_base,
            "bench_cmd": f"docker exec {BENCH_CONTAINER} wrk -t2 -c 150 -d {{bench_duration}}s http://{SERVICE_IPS['haproxy']}:9000/1k.bin",
            "container_name": "target-haproxy",
            "service_type": "haproxy",
            "bench_tool": "wrk",
            "needs_nginx_backend": True,
        },
        {
            "config_name": "largereq",
            "server_cmd": haproxy_server_base,
            "bench_cmd": f"docker exec {BENCH_CONTAINER} wrk -t2 -c 50 -d {{bench_duration}}s http://{SERVICE_IPS['haproxy']}:9000/64k.bin",
            "container_name": "target-haproxy",
            "service_type": "haproxy",
            "bench_tool": "wrk",
            "needs_nginx_backend": True,
        },
    ]

    # PostgreSQL: vary shared_buffers and client pressure.
    pg_server = (
        f"docker run -d --name target-postgres "
        f"{cpuset_arg}"
        f"--network {NETWORK_NAME} --ip {SERVICE_IPS['postgres']} "
        f"-e POSTGRES_PASSWORD=password "
        f"postgres:15-alpine postgres "
    )
    postgres_configs = [
        {
            "config_name": "buf128_c2",
            "server_cmd": pg_server + "-c shared_buffers=128MB",
            "bench_cmd": f"docker exec target-postgres pgbench -c 2 -j 2 -T {{bench_duration}} -N -h localhost -U postgres postgres",
            "container_name": "target-postgres",
            "service_type": "postgres",
            "bench_tool": "pgbench",
            "needs_pgbench_init": True,
        },
        {
            "config_name": "buf512_c4",
            "server_cmd": pg_server + "-c shared_buffers=512MB",
            "bench_cmd": f"docker exec target-postgres pgbench -c 4 -j 2 -T {{bench_duration}} -N -h localhost -U postgres postgres",
            "container_name": "target-postgres",
            "service_type": "postgres",
            "bench_tool": "pgbench",
            "needs_pgbench_init": True,
        },
        {
            "config_name": "buf1g_c8",
            "server_cmd": pg_server + "-c shared_buffers=1GB",
            "bench_cmd": f"docker exec target-postgres pgbench -c 8 -j 4 -T {{bench_duration}} -N -h localhost -U postgres postgres",
            "container_name": "target-postgres",
            "service_type": "postgres",
            "bench_tool": "pgbench",
            "needs_pgbench_init": True,
        },
        {
            "config_name": "ro_c8",
            "server_cmd": pg_server + "-c shared_buffers=512MB",
            "bench_cmd": f"docker exec target-postgres pgbench -c 8 -j 4 -T {{bench_duration}} -S -h localhost -U postgres postgres",
            "container_name": "target-postgres",
            "service_type": "postgres",
            "bench_tool": "pgbench",
            "needs_pgbench_init": True,
        },
        {
            "config_name": "rw_c8",
            "server_cmd": pg_server + "-c shared_buffers=512MB",
            "bench_cmd": f"docker exec target-postgres pgbench -c 8 -j 4 -T {{bench_duration}} -h localhost -U postgres postgres",
            "container_name": "target-postgres",
            "service_type": "postgres",
            "bench_tool": "pgbench",
            "needs_pgbench_init": True,
        },
    ]

    # MySQL: use sysbench from bench-client (time-based). The mysql:8.0 server image does not
    # ship mysqlslap by default, which would make the load exit immediately and yield 0 samples.
    # Prepare runs synchronously in run_single_config *before* the long-running bench Popen so that
    # --warmup-duration applies only to oltp_read_write run, not overlapping prepare.
    _sb_mysql_args = (
        f"--db-driver=mysql --mysql-host={SERVICE_IPS['mysql']} --mysql-user=root "
        f"--mysql-password=password --mysql-db=test --mysql-ssl=off "
        f"--tables=8 --table-size=10000 --threads=16"
    )
    mysql_server_base = (
        f"docker run -d --name target-mysql "
        f"{cpuset_arg}"
        f"--network {NETWORK_NAME} --ip {SERVICE_IPS['mysql']} "
        f"-e MYSQL_ROOT_PASSWORD=password "
        f"-e MYSQL_DATABASE=test "
        f"{DOCKER_MYSQL_IMAGE} "
    )
    mysql_cfgs = [
        ("buf256m_t8", "--innodb-buffer-pool-size=256M", "--threads=8"),
        ("buf256m_t32", "--innodb-buffer-pool-size=256M", "--threads=32"),
        ("buf1g_t16", "--innodb-buffer-pool-size=1G", "--threads=16"),
        ("t64", "--innodb-buffer-pool-size=512M", "--threads=64"),
        ("classic", "--innodb-buffer-pool-size=512M", "--threads=16"),
    ]
    mysql_configs = []
    for cfg_name, mysqld_args, sb_threads in mysql_cfgs:
        sb_args = (
            f"--db-driver=mysql --mysql-host={SERVICE_IPS['mysql']} --mysql-user=root "
            f"--mysql-password=password --mysql-db=test --mysql-ssl=off "
            f"--tables=8 --table-size=10000 {sb_threads}"
        )
        mysql_configs.append(
            {
                "config_name": cfg_name,
                "server_cmd": mysql_server_base + mysqld_args,
                "sysbench_mysql_prepare_cmd": (
                    f"docker exec {BENCH_CONTAINER} sh -lc "
                    f"\"set -e; sysbench oltp_read_write {sb_args} prepare\""
                ),
                "bench_cmd": (
                    f"docker exec {BENCH_CONTAINER} sh -lc "
                    f"\"set -e; "
                    f"sysbench oltp_read_write {sb_args} --time={{bench_duration}} --report-interval=10 run; "
                    f"sysbench oltp_read_write {sb_args} cleanup >/dev/null\""
                ),
                "container_name": "target-mysql",
                "service_type": "mysql",
                "bench_tool": "sysbench",
                "needs_mysql_ready": True,
            }
        )

    # Memcached: vary memory size, thread count, and client pressure.
    memc_server_base = (
        f"docker run -d --name target-memcached "
        f"{cpuset_arg}"
        f"--network {NETWORK_NAME} --ip {SERVICE_IPS['memcached']} "
        f"{DOCKER_MEMCACHED_IMAGE} "
    )
    memc_bench_base = (
        f"docker exec {BENCH_CONTAINER} memtier_benchmark "
        f"-s {SERVICE_IPS['memcached']} -p 11211 --protocol=memcache_binary "
    )
    memcached_configs = [
        {
            "config_name": "m64_t2_low",
            "server_cmd": memc_server_base + "-m 64 -t 2",
            "bench_cmd": memc_bench_base + "-c 20 --test-time {bench_duration}",
            "container_name": "target-memcached",
            "service_type": "memcached",
            "bench_tool": "memtier_benchmark",
        },
        {
            "config_name": "m256_t4",
            "server_cmd": memc_server_base + "-m 256 -t 4",
            "bench_cmd": memc_bench_base + "-c 50 --test-time {bench_duration}",
            "container_name": "target-memcached",
            "service_type": "memcached",
            "bench_tool": "memtier_benchmark",
        },
        {
            "config_name": "m512_t4",
            "server_cmd": memc_server_base + "-m 512 -t 4",
            "bench_cmd": memc_bench_base + "-c 50 --test-time {bench_duration}",
            "container_name": "target-memcached",
            "service_type": "memcached",
            "bench_tool": "memtier_benchmark",
        },
        {
            "config_name": "m256_t8",
            "server_cmd": memc_server_base + "-m 256 -t 8",
            "bench_cmd": memc_bench_base + "-c 80 --test-time {bench_duration}",
            "container_name": "target-memcached",
            "service_type": "memcached",
            "bench_tool": "memtier_benchmark",
        },
        {
            "config_name": "m256_t4_high",
            "server_cmd": memc_server_base + "-m 256 -t 4",
            "bench_cmd": memc_bench_base + "-c 200 --test-time {bench_duration}",
            "container_name": "target-memcached",
            "service_type": "memcached",
            "bench_tool": "memtier_benchmark",
        },
    ]

    return {
        "redis": redis_configs,
        "nginx": nginx_configs,
        "haproxy": haproxy_configs,
        "postgres": postgres_configs,
        "mysql": mysql_configs,
        "memcached": memcached_configs,
    }
