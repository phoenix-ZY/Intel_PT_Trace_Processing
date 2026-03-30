#!/usr/bin/env python3
"""
Cloud Application Intel PT Trace Collector + perf post-analysis

Runs Redis, Nginx, HAProxy, PostgreSQL, MySQL, and Memcached — each with one
classic benchmark configuration inside Docker, a bench-client (and ephemeral
MySQL client for mysqlslap), and Intel PT traces from a single worker thread.

After each configuration, runs the same perf-only pipeline as
run_spec5_sde_perf_similarity.py (with --no-enable-sde): perf script decode,
instruction-trace extraction, memory recovery via recover_mem_addrs_uc, and
data/inst locality JSON reports. SDE is not used.

Trace file naming (unchanged):
    perf.<service>.<config>.<sample_index>.data

Per-config analysis layout under the output directory:
    <service>.<config>/intermediate/  — script / insn trace (script removed after extract)
    <service>.<config>/mem/          — recovered memory JSONL
    <service>.<config>/report/       — *.perf.*.analysis.json, stderr logs

Usage:
    sudo python3 collect_cloud_traces.py [--output-dir DIR] [--perf-tool PATH]
                                         [--interval SEC] [--record-duration SEC]
                                         [--bench-duration SEC] [--samples-per-config N]
                                         [--service NAME] [--no-post-process] ...
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path
import shutil

# Reuse perf post steps from the SPEC batch driver (perf-only path).
from run_spec5_sde_perf_similarity import (
    extract_perf_insn_trace,
    parse_perf_script_health,
    run_step,
)

# ─── Defaults ────────────────────────────────────────────────────────────────

DEFAULT_OUTPUT_DIR = Path("/home/huangtianhao/Intel_PT_Trace_Processing/outputs/cloud_trace")
DEFAULT_PERF_TOOL = Path("/usr/bin/perf")

DEFAULT_INTERVAL = 10          # seconds between successive PT recordings
DEFAULT_RECORD_DURATION = 0.001  # seconds of PT recording per sample
DEFAULT_BENCH_DURATION = 120   # seconds to run each benchmark load
DEFAULT_SAMPLES_PER_CONFIG = 1
DEFAULT_WARMUP_DURATION = 30   # seconds to warm up before first sample

# perf record -m: data_pages,aux_pages (each a power of two). Intel PT uses the AUX ring; defaults are
# small and hot threads (e.g. mysqld) often overflow → lost chunks → empty insn decode.
DEFAULT_PERF_MMAP_PAGES = "2048,16384"

NETWORK_NAME = "perf-net"
NETWORK_SUBNET = "172.30.0.0/24"
NETWORK_GATEWAY = "172.30.0.1"
BENCH_CONTAINER = "bench-client"
BENCH_IP = "172.30.0.20"

SCRIPT_DIR = Path(__file__).resolve().parent

# ─── Service IP assignments ──────────────────────────────────────────────────

SERVICE_IPS = {
    "redis": "172.30.0.10",
    "nginx": "172.30.0.11",
    "mysql": "172.30.0.12",
    "memcached": "172.30.0.13",
    "haproxy": "172.30.0.14",
    "postgres": "172.30.0.16",
}

# Official-style images (override if your local tags differ).
DOCKER_MYSQL_IMAGE = "mysql:8.0"
DOCKER_MEMCACHED_IMAGE = "memcached:1.6"

# ─── Helpers ─────────────────────────────────────────────────────────────────

def log(icon: str, msg: str):
    print(f"  {icon}  {msg}", flush=True)


def normalize_perf_mmap_pages(spec: str) -> str:
    """
    Build perf record -m argument: data_pages[,aux_pages]. One number applies to both.
    Each count must be a positive power of two (Linux perf mmap page units).
    """
    parts = [p.strip() for p in spec.strip().split(",") if p.strip()]
    if len(parts) == 1:
        parts = [parts[0], parts[0]]
    if len(parts) != 2:
        raise ValueError("expected PAGES or DATA_PAGES,AUX_PAGES")
    out: list[str] = []
    for p in parts:
        n = int(p, 10)
        if n <= 0 or (n & (n - 1)) != 0:
            raise ValueError(f"each value must be a positive power of two (got {p!r})")
        out.append(str(n))
    return f"{out[0]},{out[1]}"


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
    except OSError:
        return False

def get_child_pids(parent_pid: int) -> list[dict]:
    """Get child processes sorted by CPU usage descending."""
    result = run_cmd(
        f"ps --ppid {parent_pid} -o pid=,pcpu=,comm=,args= --sort=-pcpu",
        shell=True,
    )
    children = []
    for line in result.stdout.strip().splitlines():
        parts = line.strip().split(None, 3)
        if len(parts) >= 3 and parts[0].isdigit():
            children.append({
                "pid": int(parts[0]),
                "cpu": float(parts[1]),
                "comm": parts[2],
                "args": parts[3] if len(parts) > 3 else "",
            })
    return children

def get_thread_tids(pid: int) -> list[dict]:
    """
    Get all threads of a process via ps -T, sorted by CPU usage descending.
    Each entry has 'tid', 'cpu', and 'comm'.

    We sort in Python: some ps versions ignore --sort=-pcpu with -T, so the
    first row is not reliably the busiest thread.
    """
    result = run_cmd(
        f"ps -T -p {pid} -o spid=,pcpu=,comm= --sort=-pcpu",
        shell=True,
    )
    threads = []
    for line in result.stdout.strip().splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) >= 2 and parts[0].isdigit():
            threads.append({
                "tid": int(parts[0]),
                "cpu": float(parts[1]),
                "comm": parts[2] if len(parts) > 2 else "",
            })
    threads.sort(key=lambda t: t["cpu"], reverse=True)
    return threads

def log_threads_under_pid(bench_name: str, pid: int, *, max_lines: int = 64) -> None:
    """Print all threads of pid (same source as get_busiest_tid): ps -T sorted by CPU desc."""
    threads = get_thread_tids(pid)
    log("🧵", f"{bench_name}: {len(threads)} thread(s) under PID {pid} (ps -T, pcpu↓)")
    for t in threads[:max_lines]:
        log("🧵", f"    tid={t['tid']:<8} pcpu={t['cpu']:>6} comm={t['comm']}")
    if len(threads) > max_lines:
        log("🧵", f"    ... and {len(threads) - max_lines} more")


def get_busiest_tid(pid: int) -> int:
    """
    Among all threads of a given PID, return the TID with the highest CPU
    usage. Falls back to the PID itself (main thread) if no threads found.
    """
    threads = get_thread_tids(pid)
    if threads:
        return threads[0]["tid"]
    return pid

def get_active_worker_tid(service_type: str, main_pid: int) -> int:
    """
    Find the best single worker TID to trace for a given service.

    Strategy:
      1. Find the correct worker *process* (for multi-process services like
         Nginx and PostgreSQL, skip master/background processes).
      2. Within that process, pick the thread with the highest CPU usage.

    For single-process multi-thread services (Redis, HAProxy in nbthread
    mode), step 1 returns the main PID, and step 2 picks the busiest
    thread inside it.
    """
    children = get_child_pids(main_pid)

    target_pid = main_pid  # default: trace threads of the main process

    if service_type == "postgres":
        # Exclude background helper processes, pick active connection process
        exclude_patterns = (
            "walwriter", "autovacuum", "bgworker", "stats",
            "logger", "checkpointer", "archiver", "logical",
            "wal receiver",
        )
        candidates = [
            child for child in children
            if not any(pat in child["args"].lower() for pat in exclude_patterns)
        ]
        busy = [c for c in candidates if "idle" not in c["args"].lower()]
        if busy:
            target_pid = busy[0]["pid"]
        elif candidates:
            target_pid = candidates[0]["pid"]

    elif service_type in ("nginx", "haproxy"):
        # For multi-process mode: pick a worker process (not master)
        workers = [c for c in children if "master" not in c["comm"].lower()]
        if workers:
            target_pid = workers[0]["pid"]
        # For single-process multi-thread mode (no children): main_pid is fine

    elif service_type == "redis":
        # Redis command processing is single-threaded on the main thread
        target_pid = main_pid

    elif service_type == "mysql":
        # mysqld is usually one multi-threaded process; busiest thread is a good proxy.
        target_pid = main_pid

    elif service_type == "memcached":
        # memcached -t N: libevent listener often sits at TID==PID with low user CPU while
        # worker threads serve requests; prefer the hottest non-main thread.
        threads = get_thread_tids(main_pid)
        workers_only = [t for t in threads if t["tid"] != main_pid]
        if workers_only:
            workers_only.sort(key=lambda t: t["cpu"], reverse=True)
            return workers_only[0]["tid"]
        return get_busiest_tid(main_pid)

    # Now pick the busiest thread within the target process
    return get_busiest_tid(target_pid)

# ─── Network & Environment ───────────────────────────────────────────────────

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


def ensure_bench_client(project_dir: Path):
    """Start the bench-client container if not running."""
    result = run_cmd(["docker", "ps", "--format", "{{.Names}}"])
    if BENCH_CONTAINER in result.stdout.splitlines():
        return
    log("🔧", "Starting bench-client container...")
    docker_run(
        f"-d --name {BENCH_CONTAINER} "
        f"--network {NETWORK_NAME} --ip {BENCH_IP} "
        f"--cpuset-cpus=6-10 "
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


# ─── Configuration Matrix (one classic scenario per service) ────────────────

def build_config_matrix(project_dir: Path) -> dict[str, list[dict]]:
    """
    One representative configuration per cloud service in the matrix.
    """
    nginx_conf = project_dir / "cloud_bench_configs" / "nginx-http.conf"
    haproxy_cfg = project_dir / "cloud_bench_configs" / "haproxy-http.cfg"

    # Redis: in-memory only, moderate concurrency + pipelining (typical cache load).
    redis_configs = [{
        "config_name": "classic",
        "server_cmd": (
            f"docker run -d --name target-redis "
            f"--network {NETWORK_NAME} --ip {SERVICE_IPS['redis']} "
            f"redis:7.2-alpine redis-server --save '' --appendonly no"
        ),
        "bench_cmd": (
            f"docker exec {BENCH_CONTAINER} memtier_benchmark "
            f"-s {SERVICE_IPS['redis']} -p 6379 "
            f"-c 50 --pipeline 32 --test-time {{bench_duration}}"
        ),
        "container_name": "target-redis",
        "service_type": "redis",
        "bench_tool": "memtier_benchmark",
    }]

    # Nginx: multi-worker static small file (common edge pattern).
    nginx_configs = [{
        "config_name": "classic",
        "server_cmd": (
            f"docker run -d --name target-nginx "
            f"--network {NETWORK_NAME} --ip {SERVICE_IPS['nginx']} "
            f"-v {project_dir}/www:/usr/share/nginx/html:ro "
            f"-v {nginx_conf}:/etc/nginx/nginx.conf:ro "
            f"-e NGINX_WORKER_PROCESSES=4 "
            f"nginx:alpine"
        ),
        "bench_cmd": (
            f"docker exec {BENCH_CONTAINER} wrk "
            f"-t2 -c 50 -d {{bench_duration}}s "
            f"http://{SERVICE_IPS['nginx']}/index.html"
        ),
        "container_name": "target-nginx",
        "service_type": "nginx",
        "bench_tool": "wrk",
    }]

    # HAProxy: L7 HTTP to backend nginx, moderate connections.
    haproxy_configs = [{
        "config_name": "classic",
        "server_cmd": (
            f"docker run -d --name target-haproxy "
            f"--network {NETWORK_NAME} --ip {SERVICE_IPS['haproxy']} "
            f"-v {haproxy_cfg}:/usr/local/etc/haproxy/haproxy.cfg:ro "
            f"haproxy:2.8"
        ),
        "bench_cmd": (
            f"docker exec {BENCH_CONTAINER} wrk "
            f"-t2 -c 100 -d {{bench_duration}}s "
            f"http://{SERVICE_IPS['haproxy']}:9000/"
        ),
        "container_name": "target-haproxy",
        "service_type": "haproxy",
        "bench_tool": "wrk",
        "needs_nginx_backend": True,
    }]

    # PostgreSQL: small read/write pgbench after init-scale 2.
    postgres_configs = [{
        "config_name": "classic",
        "server_cmd": (
            f"docker run -d --name target-postgres "
            f"--network {NETWORK_NAME} --ip {SERVICE_IPS['postgres']} "
            f"-e POSTGRES_PASSWORD=password "
            f"postgres:15-alpine postgres -c shared_buffers=512MB"
        ),
        "bench_cmd": (
            f"docker exec target-postgres pgbench "
            f"-c 4 -j 2 -T {{bench_duration}} -N "
            f"-h localhost -U postgres postgres"
        ),
        "container_name": "target-postgres",
        "service_type": "postgres",
        "bench_tool": "pgbench",
        "needs_pgbench_init": True,
    }]

    # MySQL: use sysbench from bench-client (time-based). The mysql:8.0 server image does not
    # ship mysqlslap by default, which would make the load exit immediately and yield 0 samples.
    # Prepare runs synchronously in run_single_config *before* the long-running bench Popen so that
    # --warmup-duration applies only to oltp_read_write run, not overlapping prepare.
    _sb_mysql_args = (
        f"--db-driver=mysql --mysql-host={SERVICE_IPS['mysql']} --mysql-user=root "
        f"--mysql-password=password --mysql-db=test --mysql-ssl=off "
        f"--tables=8 --table-size=10000 --threads=16"
    )
    mysql_configs = [{
        "config_name": "classic",
        "server_cmd": (
            f"docker run -d --name target-mysql "
            f"--network {NETWORK_NAME} --ip {SERVICE_IPS['mysql']} "
            f"-e MYSQL_ROOT_PASSWORD=password "
            f"-e MYSQL_DATABASE=test "
            f"{DOCKER_MYSQL_IMAGE}"
        ),
        "sysbench_mysql_prepare_cmd": (
            f"docker exec {BENCH_CONTAINER} sh -lc "
            f"\"set -e; sysbench oltp_read_write {_sb_mysql_args} prepare\""
        ),
        "bench_cmd": (
            f"docker exec {BENCH_CONTAINER} sh -lc "
            f"\"set -e; "
            f"sysbench oltp_read_write {_sb_mysql_args} --time={{bench_duration}} --report-interval=10 run; "
            f"sysbench oltp_read_write {_sb_mysql_args} cleanup >/dev/null\""
        ),
        "container_name": "target-mysql",
        "service_type": "mysql",
        "bench_tool": "sysbench",
        "needs_mysql_ready": True,
    }]

    # Memcached: multi-threaded daemon; memtier speaks memcache_binary (same bench-client as Redis).
    memcached_configs = [{
        "config_name": "classic",
        "server_cmd": (
            f"docker run -d --name target-memcached "
            f"--network {NETWORK_NAME} --ip {SERVICE_IPS['memcached']} "
            f"{DOCKER_MEMCACHED_IMAGE} -m 256 -t 4"
        ),
        "bench_cmd": (
            f"docker exec {BENCH_CONTAINER} memtier_benchmark "
            f"-s {SERVICE_IPS['memcached']} -p 11211 "
            f"--protocol=memcache_binary "
            f"-c 50 --test-time {{bench_duration}}"
        ),
        "container_name": "target-memcached",
        "service_type": "memcached",
        "bench_tool": "memtier_benchmark",
    }]

    return {
        "redis": redis_configs,
        "nginx": nginx_configs,
        "haproxy": haproxy_configs,
        "postgres": postgres_configs,
        "mysql": mysql_configs,
        "memcached": memcached_configs,
    }


# ─── Perf post-process (aligned with run_spec5_sde_perf_similarity, perf-only) ─

def iter_perf_data_files(output_dir: Path, bench_name: str) -> list[tuple[int, Path]]:
    """Sorted (sample_index, path) for perf.<bench_name>.<n>.data files."""
    out: list[tuple[int, Path]] = []
    prefix = f"perf.{bench_name}."
    for p in sorted(output_dir.iterdir()):
        if not p.is_file() or not p.name.startswith(prefix) or not p.name.endswith(".data"):
            continue
        mid = p.name[len(prefix) : -len(".data")]
        if mid.isdigit():
            out.append((int(mid), p))
    return out


def cloud_postprocess_reports_complete(output_dir: Path, bench_name: str) -> bool:
    """True if every perf sample under output_dir has recover_mem_addrs_uc analysis JSONs in report/."""
    samples = iter_perf_data_files(output_dir, bench_name)
    if not samples:
        return False
    slug = bench_name.replace(".", "_")
    report_dir = output_dir / bench_name / "report"
    if not report_dir.is_dir():
        return False
    for idx, _ in samples:
        data_json = report_dir / f"{slug}_s{idx}.perf.recovered.data.analysis.json"
        inst_json = report_dir / f"{slug}_s{idx}.perf.inst.analysis.json"
        if not data_json.is_file() or not inst_json.is_file():
            return False
    return True


def cloud_run_perf_postprocess(
    *,
    script_dir: Path,
    output_dir: Path,
    bench_name: str,
    perf_tool: Path,
    args: argparse.Namespace,
) -> None:
    """
    perf script --insn-trace → insn trace extract → recover_mem_addrs_uc
    (same tool chain as run_spec5 with --no-enable-sde).
    """
    recover_bin = script_dir / "recover_mem_addrs_uc"
    if not recover_bin.is_file() or not os.access(recover_bin, os.X_OK):
        raise RuntimeError(
            f"missing executable {recover_bin}; build it first (e.g. build_recover_mem_addrs_uc.sh)"
        )

    data_files = iter_perf_data_files(output_dir, bench_name)
    if not data_files:
        log("⚠️", f"No perf.data files for {bench_name}; skipping post-process.")
        return

    # <output-base>/<bench>/{intermediate,mem,report} — fixed path; re-runs overwrite outputs.
    case_root = output_dir / bench_name
    intermediate = case_root / "intermediate"
    mem_dir = case_root / "mem"
    report_dir = case_root / "report"
    for d in (intermediate, mem_dir, report_dir):
        d.mkdir(parents=True, exist_ok=True)

    slug = bench_name.replace(".", "_")
    for sample_idx, perf_data in data_files:
        prefix = f"{slug}_s{sample_idx}"
        perf_data_copy = intermediate / f"{prefix}.perf.data"
        perf_script = intermediate / f"{prefix}.perf.script.txt"
        perf_script_stderr = report_dir / f"{prefix}.perf.script.stderr.txt"
        perf_insn = intermediate / f"{prefix}.perf.insn.trace.txt"
        perf_rec_mem = mem_dir / f"{prefix}.perf.mem.recovered.jsonl"
        perf_data_analysis = report_dir / f"{prefix}.perf.recovered.data.analysis.json"
        perf_inst_analysis = report_dir / f"{prefix}.perf.inst.analysis.json"

        # Always refresh copy so re-collected perf.data replaces stale files.
        shutil.copy2(perf_data, perf_data_copy)

        log("📜", f"Post-process sample {sample_idx}: perf script → insn trace …")
        run_step(
            [
                str(perf_tool),
                "script",
                "--insn-trace",
                "-F",
                "tid,time,ip,insn,ipc",
                "-i",
                str(perf_data_copy),
            ],
            verbose=args.verbose_post,
            stdout_path=perf_script,
            stderr_path=perf_script_stderr,
        )
        aux_lost, trace_err = parse_perf_script_health(perf_script_stderr)
        ninsn = extract_perf_insn_trace(perf_script, perf_insn, args.perf_max_insn_lines)
        try:
            perf_script.unlink()
        except FileNotFoundError:
            pass
        if ninsn < 1:
            raise RuntimeError(
                f"no insn lines extracted for {perf_data.name} "
                f"(aux_lost={aux_lost}, trace_errors={trace_err})"
            )

        recover_cmd = [
            str(recover_bin),
            "-i",
            str(perf_insn),
            "-o",
            str(perf_rec_mem),
            "--init-regs",
            args.recover_init_regs,
            "--reg-staging",
            args.recover_reg_staging,
            "--mvs",
            args.recover_mvs,
            "--seed",
            str(args.recover_fill_seed),
            "--page-init",
            args.recover_page_init,
            "--page-init-seed",
            str(args.recover_page_init_seed),
            "--progress-every",
            str(args.recover_progress_every),
            "--inst-analysis-out",
            str(perf_inst_analysis),
            "--data-analysis-out",
            str(perf_data_analysis),
            "--analysis-line-size",
            str(args.line_size),
            "--analysis-sdp-max-lines",
            "262144",
            "--analysis-rd-definition",
            "stack_depth",
            "--analysis-rd-hist-cap-lines",
            str(args.analysis_rd_hist_cap_lines),
            "--analysis-stride-bin-cap-lines",
            str(args.analysis_stride_bin_cap_lines),
        ]
        if args.recover_salvage_invalid_mem:
            recover_cmd.append("--salvage-invalid-mem")
            if args.recover_salvage_reads:
                recover_cmd.append("--salvage-reads")

        log("🔬", f"Post-process sample {sample_idx}: recover_mem_addrs_uc ({ninsn} insn lines) …")
        run_step(recover_cmd, verbose=args.verbose_post)

        if not perf_data_analysis.is_file() or not perf_inst_analysis.is_file():
            raise RuntimeError("recover_mem_addrs_uc did not write analysis JSON outputs")

        log(
            "✅",
            f"Sample {sample_idx}: data={perf_data_analysis.name} inst={perf_inst_analysis.name} "
            f"(pt_aux_lost={aux_lost}, pt_trace_err={trace_err})",
        )


# ─── Core Trace Collection ───────────────────────────────────────────────────

def collect_traces_for_config(
    perf_tool: Path,
    bench_name: str,
    worker_tid: int,
    output_dir: Path,
    interval: float,
    record_duration: float,
    max_samples: int,
    bench_process: subprocess.Popen,
    perf_mmap_pages: str,
    intel_pt_event: str,
):
    """
    Periodically record PT traces from a single worker thread (TID).
    Uses `perf record -t TID` to trace only the specified thread.
    Output files: perf.<bench_name>.<sample_index>.data
    """
    sample_count = 0
    start_time = time.time()

    log("📊", f"Sampling TID {worker_tid} every {interval}s (max {max_samples} samples)...")
    log("🔬", f"perf record -m {perf_mmap_pages} (data,aux mmap pages)")

    while sample_count < max_samples:
        # Check if the thread is still alive
        if not pid_alive(worker_tid):
            log("🏁", "Worker thread exited.")
            break

        # Check if the bench process has finished
        if bench_process.poll() is not None:
            log("🏁", "Benchmark load finished.")
            break

        sample_count += 1
        elapsed = time.time() - start_time
        pt_path = output_dir / f"perf.{bench_name}.{sample_count}.data"

        run_cmd([
            str(perf_tool), "record",
            "-m", perf_mmap_pages,
            "-e", intel_pt_event,
            "-t", str(worker_tid),
            "-o", str(pt_path),
            "--", "sleep", str(record_duration),
        ])

        log("✅", f"Sample {sample_count} @ {elapsed:.0f}s → {pt_path.name}")

        # Wait for the next interval
        wait_until = time.time() + interval
        while time.time() < wait_until:
            if not pid_alive(worker_tid) or bench_process.poll() is not None:
                log("🏁", "Worker/benchmark finished during wait.")
                return sample_count
            time.sleep(1)

    return sample_count


def run_single_config(
    config: dict,
    perf_tool: Path,
    output_dir: Path,
    project_dir: Path,
    interval: float,
    record_duration: float,
    bench_duration: int,
    max_samples: int,
    warmup_duration: int = DEFAULT_WARMUP_DURATION,
    cli_args: argparse.Namespace | None = None,
):
    """Run one service config: optional PT capture, then perf script + recover (unless disabled)."""
    service_type = config["service_type"]
    config_name = config["config_name"]
    container_name = config["container_name"]
    bench_name = f"{service_type}.{config_name}"

    has_perf = (output_dir / f"perf.{bench_name}.1.data").is_file()
    post_complete = cloud_postprocess_reports_complete(output_dir, bench_name)
    # Do not skip re-collection when perf.data is left over from a failed decode/recover run.
    skip_collect = has_perf and post_complete
    if skip_collect:
        log("⏭️", f"Skipping {bench_name} trace collection (perf + analysis already complete)")
    else:
        if has_perf and not post_complete:
            log("♻️", f"{bench_name}: perf.data exists but analysis missing — re-collecting PT")
        print(f"\n{'─' * 60}")
        print(f"  🧪  {bench_name}")
        print(f"{'─' * 60}")

    if not skip_collect:
        # ── Start nginx backend for HAProxy ─────────────────────────────
        if config.get("needs_nginx_backend"):
            docker_stop_rm("target-nginx-helper")
            nginx_conf = project_dir / "cloud_bench_configs" / "nginx-http.conf"
            docker_run(
                f"-d --name target-nginx-helper "
                f"--network {NETWORK_NAME} --ip {SERVICE_IPS['nginx']} "
                f"-v {nginx_conf}:/etc/nginx/nginx.conf:ro "
                f"nginx:alpine"
            )
            time.sleep(2)

        # ── Start the target service ─────────────────────────────────────
        docker_stop_rm(container_name)
        server_cmd = config["server_cmd"]
        log("⚙️", f"Starting {container_name}...")
        result = run_cmd(server_cmd, shell=True)
        if result.returncode != 0:
            log("❌", f"Failed to start {container_name}: {result.stderr.strip()}")
            return

        # Wait for service to be ready
        startup_wait = 5
        if config.get("needs_pgbench_init"):
            startup_wait = 10  # PostgreSQL needs more time
        time.sleep(startup_wait)

        # ── Wait for MySQL to accept connections ──────────────────────────
        if config.get("needs_mysql_ready"):
            log("⏳", "Waiting for MySQL to accept connections...")
            mysql_ready = False
            for _ in range(90):
                ping = docker_exec(container_name, "mysqladmin ping -ppassword --silent")
                if ping.returncode == 0:
                    mysql_ready = True
                    break
                time.sleep(1)
            if not mysql_ready:
                log("❌", "MySQL did not become ready in time")
                docker_stop_rm(container_name)
                return

        # ── sysbench prepare (MySQL): must finish before run+warmup+PT ─────────
        if config.get("sysbench_mysql_prepare_cmd"):
            live = cli_args is not None and cli_args.verbose_sysbench_prepare
            log(
                "📊",
                "Running sysbench oltp_read_write prepare …"
                + (" (live output on stdout/stderr)" if live else ""),
            )
            t_prep = time.monotonic()
            if live:
                pr = subprocess.run(
                    config["sysbench_mysql_prepare_cmd"],
                    shell=True,
                    text=True,
                )
            else:
                pr = run_cmd(config["sysbench_mysql_prepare_cmd"], shell=True)
            prep_elapsed = time.monotonic() - t_prep
            if pr.returncode != 0:
                err = (pr.stderr or "").strip() if pr.stderr is not None else ""
                if live and not err:
                    err = "(see messages above)"
                log("❌", f"sysbench prepare failed (rc={pr.returncode}): {err}")
                docker_stop_rm(container_name)
                return
            log("✅", f"sysbench prepare done in {prep_elapsed:.1f}s")
            if not live and pr.stdout and pr.stdout.strip():
                for line in pr.stdout.strip().splitlines()[-8:]:
                    log("📋", f"  prepare out: {line}")
            if not live and pr.stderr and pr.stderr.strip():
                for line in pr.stderr.strip().splitlines()[-8:]:
                    log("📋", f"  prepare err: {line}")

        # ── Initialize PostgreSQL if needed ───────────────────────────────
        if config.get("needs_pgbench_init"):
            log("🗄️", "Initializing pgbench database...")
            init_result = docker_exec(
                "target-postgres",
                "pgbench -i -s 2 -U postgres postgres",
            )
            if init_result.returncode != 0:
                log("⚠️", f"pgbench init warning: {init_result.stderr.strip()}")
            time.sleep(3)

        # ── Start the benchmark load ────────────────────────────────────
        bench_cmd = config["bench_cmd"].format(bench_duration=bench_duration)
        log("🔨", f"Starting load: {bench_cmd}")
        bench_process = subprocess.Popen(
            bench_cmd, shell=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        # Wait for load to warm up before tracing
        log("🔥", f"Warming up for {warmup_duration}s before tracing...")
        time.sleep(warmup_duration)

        # ── Find the worker PID to trace ─────────────────────────────────
        main_pid = docker_inspect_pid(container_name)
        if main_pid is None:
            log("❌", f"Cannot get PID for {container_name}")
            bench_process.kill()
            docker_stop_rm(container_name)
            return

        if cli_args is not None and cli_args.show_tids:
            log_threads_under_pid(bench_name, main_pid)
            children = get_child_pids(main_pid)
            if children:
                parts = [f"{c['pid']}({c['comm']})" for c in children[:20]]
                tail = f" …+{len(children) - 20}" if len(children) > 20 else ""
                log("🧵", f"  child processes ({len(children)}): {', '.join(parts)}{tail}")

        worker_tid = get_active_worker_tid(service_type, main_pid)
        log("🚀", f"Tracing worker TID {worker_tid} (main PID {main_pid})")

        if not pid_alive(worker_tid):
            log("⚠️", "Worker TID not alive — skipping.")
            bench_process.kill()
            docker_stop_rm(container_name)
            return

        # ── Collect PT traces ─────────────────────────────────────────────
        mmap_pages = (
            cli_args.perf_mmap_pages
            if cli_args is not None
            else DEFAULT_PERF_MMAP_PAGES
        )
        nrc = (
            int(cli_args.perf_pt_noretcomp)
            if cli_args is not None
            else 0
        )
        pt_event = f"intel_pt/cyc,noretcomp={nrc}/u"
        sample_count = collect_traces_for_config(
            perf_tool=perf_tool,
            bench_name=bench_name,
            worker_tid=worker_tid,
            output_dir=output_dir,
            interval=interval,
            record_duration=record_duration,
            max_samples=max_samples,
            bench_process=bench_process,
            perf_mmap_pages=mmap_pages,
            intel_pt_event=pt_event,
        )

        # ── Cleanup ───────────────────────────────────────────────────────
        bench_process.kill()
        bench_process.wait()
        docker_stop_rm(container_name)
        if config.get("needs_nginx_backend"):
            docker_stop_rm("target-nginx-helper")

        log("✅", f"{bench_name} done — {sample_count} samples collected.\n")

    if cli_args is not None and not cli_args.no_post_process:
        if iter_perf_data_files(output_dir, bench_name):
            try:
                cloud_run_perf_postprocess(
                    script_dir=SCRIPT_DIR,
                    output_dir=output_dir,
                    bench_name=bench_name,
                    perf_tool=perf_tool,
                    args=cli_args,
                )
            except Exception as e:
                log("❌", f"Post-process failed for {bench_name}: {e}")
                if cli_args.stop_on_post_error:
                    raise


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Collect Intel PT traces from cloud apps and run perf script + recover_mem_addrs_uc."
    )
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR,
                        help=f"Directory for PT data files (default: {DEFAULT_OUTPUT_DIR})")
    parser.add_argument("--perf-tool", type=Path, default=DEFAULT_PERF_TOOL,
                        help=f"Path to perf binary (default: {DEFAULT_PERF_TOOL})")
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL,
                        help=f"Seconds between samples (default: {DEFAULT_INTERVAL})")
    parser.add_argument("--record-duration", type=float, default=DEFAULT_RECORD_DURATION,
                        help=f"Seconds of PT recording per sample (default: {DEFAULT_RECORD_DURATION})")
    parser.add_argument("--bench-duration", type=int, default=DEFAULT_BENCH_DURATION,
                        help=f"Seconds to run each benchmark load (default: {DEFAULT_BENCH_DURATION})")
    parser.add_argument("--samples-per-config", type=int, default=DEFAULT_SAMPLES_PER_CONFIG,
                        help=f"Max samples per config (default: {DEFAULT_SAMPLES_PER_CONFIG})")
    parser.add_argument("--warmup-duration", type=int, default=DEFAULT_WARMUP_DURATION,
                        help=f"Seconds to warm up before first sample (default: {DEFAULT_WARMUP_DURATION})")
    parser.add_argument("--service", type=str, default="all",
                        choices=[
                            "all",
                            "redis",
                            "nginx",
                            "haproxy",
                            "postgres",
                            "mysql",
                            "memcached",
                        ],
                        help="Run only a specific service (default: all)")
    parser.add_argument(
        "--no-post-process",
        action="store_true",
        help="Skip perf script / insn extract / recover_mem_addrs_uc after each config",
    )
    parser.add_argument(
        "--stop-on-post-error",
        action="store_true",
        help="Abort the whole run if post-processing fails for one config",
    )
    parser.add_argument(
        "--verbose-post",
        action="store_true",
        help="Print post-process subprocess commands (perf script, recover_mem_addrs_uc)",
    )
    parser.add_argument(
        "--show-tids",
        action="store_true",
        help="Before PT, list threads under container main PID (ps -T, pcpu↓) and child PIDs",
    )
    parser.add_argument(
        "--verbose-sysbench-prepare",
        action="store_true",
        help="Stream MySQL sysbench oltp_read_write prepare to terminal (default: capture, log last lines + duration)",
    )
    parser.add_argument("--perf-max-insn-lines", type=int, default=500_000,
                        help="Max insn lines to keep from perf script (0 = unlimited)")
    parser.add_argument("--line-size", type=int, default=64,
                        help="Cache line size for locality analysis (power of two)")
    parser.add_argument("--recover-init-regs", choices=["zero", "random"], default="random")
    parser.add_argument("--recover-reg-staging", choices=["legacy", "dwt"], default="dwt")
    parser.add_argument("--recover-mvs", choices=["on", "off"], default="on")
    parser.add_argument("--recover-fill-seed", type=int, default=1)
    parser.add_argument("--recover-page-init", choices=["zero", "random", "stable"], default="zero")
    parser.add_argument("--recover-page-init-seed", type=int, default=1)
    parser.add_argument("--recover-progress-every", type=int, default=0)
    parser.add_argument(
        "--recover-salvage-invalid-mem",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    parser.add_argument(
        "--recover-salvage-reads",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    parser.add_argument("--analysis-rd-hist-cap-lines", type=int, default=262144)
    parser.add_argument("--analysis-stride-bin-cap-lines", type=int, default=262144)
    parser.add_argument(
        "--perf-mmap-pages",
        type=str,
        default=DEFAULT_PERF_MMAP_PAGES,
        help=(
            "perf record -m: DATA[,AUX] mmap page counts (powers of two); "
            "one value sets both. Larger AUX cuts intel_pt 'lost chunks' on hot threads."
        ),
    )
    parser.add_argument(
        "--perf-pt-noretcomp",
        type=int,
        choices=[0, 1],
        default=0,
        help="intel_pt noretcomp flag (1 reduces PT bandwidth vs 0; may help if AUX still overflows).",
    )
    args = parser.parse_args()

    try:
        args.perf_mmap_pages = normalize_perf_mmap_pages(args.perf_mmap_pages)
    except ValueError as e:
        sys.exit(f"❌ --perf-mmap-pages: {e}")

    if args.line_size <= 0 or (args.line_size & (args.line_size - 1)) != 0:
        sys.exit("❌ --line-size must be a positive power of two")
    if args.perf_max_insn_lines < 0:
        sys.exit("❌ --perf-max-insn-lines must be >= 0")
    if args.analysis_rd_hist_cap_lines < 0 or args.analysis_stride_bin_cap_lines < 0:
        sys.exit("❌ analysis cap lines must be >= 0")
    if args.recover_progress_every < 0:
        sys.exit("❌ --recover-progress-every must be >= 0")

    output_dir = args.output_dir.resolve()
    perf_tool = args.perf_tool.resolve()
    project_dir = SCRIPT_DIR

    if not perf_tool.is_file() or not os.access(perf_tool, os.X_OK):
        sys.exit(f"❌ perf tool not executable: {perf_tool}")

    output_dir.mkdir(parents=True, exist_ok=True)

    # Prepare environment
    ensure_static_files(project_dir)
    cleanup_all()
    ensure_network()
    ensure_bench_client(project_dir)

    # Build configuration matrix
    all_configs = build_config_matrix(project_dir)

    # Determine which services to run
    if args.service == "all":
        services_to_run = [
            "redis",
            "nginx",
            "haproxy",
            "postgres",
            "mysql",
            "memcached",
        ]
    else:
        services_to_run = [args.service]

    total_configs = sum(len(all_configs[s]) for s in services_to_run)
    print(f"\n📁 Output dir : {output_dir}")
    print(f"🔍 Services   : {', '.join(services_to_run)}")
    print(f"📦 Configs    : {total_configs} total (one classic profile per service)")
    print(f"⏱️  Interval   : {args.interval}s between samples")
    print(f"🕐 Bench dur  : {args.bench_duration}s per config")
    print(f"🔬 perf -m    : {args.perf_mmap_pages} (data,aux mmap pages)")
    print(f"🔬 intel_pt   : noretcomp={args.perf_pt_noretcomp}")
    print(f"📊 Post-process: {'off' if args.no_post_process else 'perf script + recover_mem_addrs_uc'}\n")

    config_index = 0
    for service_name in services_to_run:
        service_configs = all_configs[service_name]
        log("📦", f"=== Service: {service_name} ({len(service_configs)} configs) ===")

        for config in service_configs:
            config_index += 1
            log("📋", f"Config {config_index}/{total_configs}: "
                       f"{config['service_type']}.{config['config_name']}")

            run_single_config(
                config=config,
                perf_tool=perf_tool,
                output_dir=output_dir,
                project_dir=project_dir,
                interval=args.interval,
                record_duration=args.record_duration,
                bench_duration=args.bench_duration,
                max_samples=args.samples_per_config,
                warmup_duration=args.warmup_duration,
                cli_args=args,
            )

    # Final cleanup
    docker_stop_rm(BENCH_CONTAINER)
    run_cmd(["docker", "network", "rm", NETWORK_NAME])

    print(f"\n🎉 All cloud benchmarks finished! Data saved to: {output_dir}")


if __name__ == "__main__":
    main()
