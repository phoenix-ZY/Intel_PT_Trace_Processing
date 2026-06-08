#!/usr/bin/env python3
"""Rewrite cloud workload JSON start/load commands to CBS online launchers."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def _redis_load(cmd: str) -> str:
    m = re.search(
        r"memtier_benchmark\s+-s\s+\S+\s+-p\s+\d+"
        r"(?:\s+-t\s+(\d+))?\s+-c\s+(\d+)"
        r"(?:\s+--pipeline\s+(\d+))?"
        r"(?:\s+--ratio\s+(\S+))?",
        cmd,
    )
    if not m:
        return cmd
    threads, clients, pipeline, ratio = m.groups()
    parts = ["CBS_BENCH_MODE=exec"]
    if threads:
        parts.append(f"MEMTIER_THREADS={threads}")
    parts.append(f"MEMTIER_CLIENTS={clients}")
    if pipeline:
        parts.append(f"MEMTIER_PIPELINE={pipeline}")
    if ratio:
        parts.append(f"MEMTIER_RATIO={ratio}")
    parts.append("bash {colocation_bench_suite_dir}/online/redis/run_load.sh {bench_duration}")
    return " ".join(parts)


def _redis_start(cmd: str) -> str:
    extra = []
    if "maxmemory" in cmd:
        m = re.search(r"--maxmemory\s+(\S+)", cmd)
        if m:
            extra.append(f"REDIS_MAXMEMORY={m.group(1)}")
    if "appendonly yes" in cmd:
        extra.append("REDIS_APPENDONLY=yes")
    base = [
        "CBS_NETWORK_MODE=perf-net",
        "SIMPLE_SERVER_CONTAINER=target-redis",
        "SERVER_CPUSET={target_cpuset}",
        *extra,
        "bash {colocation_bench_suite_dir}/online/redis/start_server.sh",
    ]
    return " ".join(base)


def _nginx_start(cmd: str) -> str:
    m = re.search(r"worker_processes\s+(\d+)", cmd)
    workers = m.group(1) if m else "4"
    return (
        "CBS_NETWORK_MODE=perf-net CBS_CLOUD_PROJECT_DIR={project_dir} "
        f"SIMPLE_SERVER_CONTAINER=target-nginx SERVER_CPUSET={{target_cpuset}} "
        f"NGINX_WORKER_PROCESSES={workers} "
        "bash {colocation_bench_suite_dir}/online/nginx/start_server.sh"
    )


def _nginx_load(cmd: str) -> str:
    m = re.search(r"wrk\s+-t(\d+)\s+-c(\d+).*?http://[^/]+(/\S*)", cmd)
    if not m:
        return cmd
    threads, clients, path = m.groups()
    return (
        f"CBS_BENCH_MODE=exec NGINX_BENCH_THREADS={threads} CLIENT_CONCURRENCY={clients} "
        f"WRK_PATH={path} bash {{colocation_bench_suite_dir}}/online/nginx/run_load.sh {{bench_duration}}"
    )


def _mysql_start(cmd: str) -> str:
  parts = [
      "CBS_NETWORK_MODE=perf-net",
      "SIMPLE_SERVER_CONTAINER=target-mysql",
      "SERVER_CPUSET={target_cpuset}",
      "MYSQL_ROOT_PASSWORD=password",
      "MYSQL_DATABASE=test",
  ]
  m = re.search(r"innodb-buffer-pool-size=(\S+)", cmd)
  if m:
      parts.append(f"MYSQL_INNODB_BUFFER_POOL={m.group(1)}")
  m = re.search(r"max-connections=(\d+)", cmd)
  if m:
      parts.append(f"MYSQL_MAX_CONNECTIONS={m.group(1)}")
  parts.append("bash {colocation_bench_suite_dir}/online/mysql/start_server.sh")
  return " ".join(parts)


def _mysql_prepare(cmd: str) -> str:
    m = re.search(r"--tables=(\d+).*--table-size=(\d+).*--threads=(\d+)", cmd)
    if not m:
        return cmd
    tables, size, threads = m.groups()
    return (
        f"SYSBENCH_TABLES={tables} SYSBENCH_TABLE_SIZE={size} SYSBENCH_THREADS={threads} "
        "MYSQL_ROOT_PASSWORD=password MYSQL_DATABASE=test "
        "bash {colocation_bench_suite_dir}/online/mysql/run_prepare.sh"
    )


def _mysql_load(cmd: str) -> str:
    m = re.search(r"--tables=(\d+).*--table-size=(\d+).*--threads=(\d+)", cmd)
    if not m:
        return cmd
    tables, size, threads = m.groups()
    cleanup = "SYSBENCH_CLEANUP=0 " if "cleanup" not in cmd else ""
    return (
        f"CBS_BENCH_MODE=exec {cleanup}SYSBENCH_TABLES={tables} SYSBENCH_TABLE_SIZE={size} "
        f"SYSBENCH_THREADS={threads} MYSQL_ROOT_PASSWORD=password MYSQL_DATABASE=test "
        "bash {colocation_bench_suite_dir}/online/mysql/run_load.sh {bench_duration}"
    )


def _memcached_start(cmd: str) -> str:
    m = re.search(r"-m\s+(\d+)\s+-t\s+(\d+)", cmd)
    mem, threads = (m.groups() if m else ("256", "4"))
    return (
        "CBS_NETWORK_MODE=perf-net SIMPLE_SERVER_CONTAINER=target-memcached "
        f"SERVER_CPUSET={{target_cpuset}} MEMCACHED_MEMORY_MB={mem} MEMCACHED_THREADS={threads} "
        "bash {colocation_bench_suite_dir}/online/memcached/start_server.sh"
    )


def _memcached_load(cmd: str) -> str:
    m = re.search(
        r"memtier_benchmark\s+-s\s+\S+\s+-p\s+\d+\s+--protocol=\S+"
        r"(?:\s+-t\s+(\d+))?\s+-c\s+(\d+)"
        r"(?:\s+--pipeline\s+(\d+))?",
        cmd,
    )
    if not m:
        return cmd
    threads, clients, pipeline = m.groups()
    parts = ["CBS_BENCH_MODE=exec"]
    if threads:
        parts.append(f"MEMTIER_THREADS={threads}")
    parts.append(f"MEMTIER_CLIENTS={clients}")
    if pipeline:
        parts.append(f"MEMTIER_PIPELINE={pipeline}")
    parts.append("bash {colocation_bench_suite_dir}/online/memcached/run_load.sh {bench_duration}")
    return " ".join(parts)


def migrate_config(config: dict) -> dict:
    target = config.get("target_role", {})
    start = str(target.get("start_cmd", ""))
    service = config.get("service_type", "")

    if service == "redis" and start.startswith("docker run"):
        target["start_cmd"] = _redis_start(start)
    elif service == "nginx" and start.startswith("docker run"):
        target["start_cmd"] = _nginx_start(start)
    elif service == "mysql" and start.startswith("docker run"):
        target["start_cmd"] = _mysql_start(start)
    elif service == "memcached" and start.startswith("docker run"):
        target["start_cmd"] = _memcached_start(start)

    load = str(config.get("load_cmd", ""))
    if service == "redis" and "memtier_benchmark" in load:
        config["load_cmd"] = _redis_load(load)
    elif service == "nginx" and "wrk" in load:
        config["load_cmd"] = _nginx_load(load)
    elif service == "mysql" and "sysbench" in load and "prepare" not in load:
        config["load_cmd"] = _mysql_load(load)
    elif service == "memcached" and "memtier_benchmark" in load:
        config["load_cmd"] = _memcached_load(load)

    for step in config.get("prepare_steps", []):
        cmd = str(step.get("cmd", ""))
        if service == "mysql" and "sysbench" in cmd and "prepare" in cmd:
            step["cmd"] = _mysql_prepare(cmd)

    for helper in config.get("helper_roles", []):
        migrate_helper(helper)

    return config


def migrate_helper(helper: dict) -> None:
    start = str(helper.get("start_cmd", ""))
    if "target-nginx-helper" in start or "nginx-http.conf" in start:
        m = re.search(r"worker_processes\s+(\d+)", start)
        workers = m.group(1) if m else "8"
        helper["start_cmd"] = (
            "CBS_NETWORK_MODE=perf-net CBS_CLOUD_PROJECT_DIR={project_dir} "
            f"HELPER_CONTAINER=target-nginx-helper HELPER_CPUSET={{helper_cpuset}} "
            f"NGINX_WORKER_PROCESSES={workers} "
            "bash {colocation_bench_suite_dir}/online/haproxy/start_helper_nginx.sh"
        )
    elif "helper-postgres-loadgen" in start:
        helper["start_cmd"] = (
            "CBS_NETWORK_MODE=perf-net HELPER_CONTAINER=helper-postgres-loadgen "
            "HELPER_CPUSET={helper_cpuset} "
            "bash {colocation_bench_suite_dir}/online/postgres/start_helper.sh"
        )

    if "target-haproxy" in start or "haproxy-http.cfg" in start:
        m = re.search(r"nbthread\s+(\d+)", start)
        threads = m.group(1) if m else "8"
        helper.setdefault("_skip", False)

    for check in helper.get("ready_checks", []):
        pass


def migrate_file(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    services = data.get("services", data)
    for entries in services.values():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            migrate_config(entry)
            target = entry.get("target_role", {})
            start = str(target.get("start_cmd", ""))
            if "haproxy-http.cfg" in start:
                m = re.search(r"nbthread\s+(\d+)", start)
                threads = m.group(1) if m else "8"
                target["start_cmd"] = (
                    "CBS_NETWORK_MODE=perf-net CBS_CLOUD_PROJECT_DIR={project_dir} "
                    f"SIMPLE_SERVER_CONTAINER=target-haproxy SERVER_CPUSET={{target_cpuset}} "
                    f"HAPROXY_NBTHREAD={threads} "
                    "bash {colocation_bench_suite_dir}/online/haproxy/start_server.sh"
                )
            if entry.get("service_type") == "haproxy":
                load = str(entry.get("load_cmd", ""))
                m = re.search(r"wrk\s+-t(\d+)\s+-c(\d+).*?http://[^/]+(/\S*)", load)
                if m:
                    t, c, p = m.groups()
                    entry["load_cmd"] = (
                        f"CBS_BENCH_MODE=exec NGINX_BENCH_THREADS={t} CLIENT_CONCURRENCY={c} "
                        f"WRK_PATH={p} bash {{colocation_bench_suite_dir}}/online/haproxy/run_load.sh {{bench_duration}}"
                    )
            if entry.get("service_type") == "postgres":
                target = entry.get("target_role", {})
                if str(target.get("start_cmd", "")).startswith("docker run"):
                    target["start_cmd"] = (
                        "CBS_NETWORK_MODE=perf-net SIMPLE_SERVER_CONTAINER=target-postgres "
                        "SERVER_CPUSET={target_cpuset} "
                        "bash {colocation_bench_suite_dir}/online/postgres/start_server.sh"
                    )
                for step in entry.get("prepare_steps", []):
                    if "pgbench -i" in str(step.get("cmd", "")):
                        m = re.search(r"-s\s+(\d+)", step["cmd"])
                        scale = m.group(1) if m else "20"
                        step["cmd"] = (
                            f"PGBENCH_SCALE={scale} "
                            "bash {colocation_bench_suite_dir}/online/postgres/run_prepare.sh"
                        )
                load = str(entry.get("load_cmd", ""))
                m = re.search(r"pgbench\s+-c\s+(\d+)\s+-j\s+(\d+)", load)
                if m:
                    clients, jobs = m.groups()
                    entry["load_cmd"] = (
                        f"PGBENCH_CLIENTS={clients} PGBENCH_JOBS={jobs} "
                        "bash {colocation_bench_suite_dir}/online/postgres/run_load.sh {bench_duration}"
                    )

    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="+", type=Path)
    args = parser.parse_args()
    for path in args.files:
        migrate_file(path)
        print(f"updated {path}")


if __name__ == "__main__":
    main()
