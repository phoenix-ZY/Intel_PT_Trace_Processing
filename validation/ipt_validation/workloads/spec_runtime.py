from __future__ import annotations

import os
import shlex
import signal
import subprocess
import time
from pathlib import Path


def pid_alive(pid: int) -> bool:
    return (Path("/proc") / str(pid)).exists()


def read_proc_exe(pid: int) -> str:
    try:
        return str((Path("/proc") / str(pid) / "exe").resolve())
    except OSError:
        return ""


def read_proc_argv0_basename(pid: int) -> str:
    try:
        raw = (Path("/proc") / str(pid) / "cmdline").read_bytes()
    except OSError:
        return ""
    if not raw:
        return ""
    argv0_b = raw.split(b"\0", 1)[0]
    if not argv0_b:
        return ""
    argv0 = argv0_b.decode("utf-8", errors="replace").strip()
    return Path(argv0).name if argv0 else ""


def read_proc_ppid(pid: int) -> int:
    try:
        for line in (Path("/proc") / str(pid) / "status").read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("PPid:"):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return 0


def is_strict_descendant_of(pid: int, ancestor: int) -> bool:
    if pid <= 1 or ancestor <= 0 or pid == ancestor:
        return False
    cur = read_proc_ppid(pid)
    for _ in range(2048):
        if cur == ancestor:
            return True
        if cur <= 1:
            return False
        cur = read_proc_ppid(cur)
    return False


def read_ps_pcpu(pid: int) -> float:
    try:
        pr = subprocess.run(
            ["ps", "-p", str(pid), "-o", "pcpu=", "--no-headers"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return float(pr.stdout.strip() or "0")
    except (ValueError, subprocess.TimeoutExpired, OSError):
        return 0.0


def pick_hottest_pid_by_ps_pcpu(pids: list[int]) -> int:
    if not pids:
        raise ValueError("empty pids")
    if len(pids) == 1:
        return pids[0]
    best = pids[0]
    best_c = read_ps_pcpu(best)
    for pid in pids[1:]:
        c = read_ps_pcpu(pid)
        if c > best_c:
            best, best_c = pid, c
    return best


def scan_proc_benchmark_pid(
    run_dir: Path,
    exe_basename: str,
    prefer_under_pid: int,
) -> int | None:
    try:
        run_res = run_dir.resolve()
    except OSError:
        return None
    candidates: list[int] = []
    for p in Path("/proc").iterdir():
        if not p.name.isdigit():
            continue
        pid = int(p.name)
        try:
            cwd = Path(os.readlink(f"/proc/{pid}/cwd")).resolve()
        except OSError:
            continue
        if cwd != run_res:
            continue
        if read_proc_argv0_basename(pid) != exe_basename:
            continue
        candidates.append(pid)
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    in_tree = [p for p in candidates if p == prefer_under_pid or is_strict_descendant_of(p, prefer_under_pid)]
    return pick_hottest_pid_by_ps_pcpu(in_tree if in_tree else candidates)


def children_of(pid: int) -> list[int]:
    children_file = Path("/proc") / str(pid) / "task" / str(pid) / "children"
    try:
        raw = children_file.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return []
    if not raw:
        return []
    out: list[int] = []
    for tok in raw.split():
        try:
            out.append(int(tok))
        except ValueError:
            continue
    return out


def collect_matching_pids_under_launcher(
    launcher_pid: int,
    exe_basename: str | None,
    run_dir: Path | None,
) -> list[int]:
    out: list[int] = []
    if not exe_basename or not pid_alive(launcher_pid):
        return out

    def matches(pid: int) -> bool:
        cexe = read_proc_exe(pid)
        if cexe and Path(cexe).name == exe_basename:
            return True
        if read_proc_argv0_basename(pid) == exe_basename:
            return True
        if run_dir:
            try:
                cwd = os.readlink(f"/proc/{pid}/cwd")
                if (
                    cexe
                    and Path(cexe).is_file()
                    and str(Path(cexe).resolve()).startswith(str(run_dir.resolve()) + os.sep)
                    and Path(cwd).resolve() == run_dir.resolve()
                ):
                    return True
            except OSError:
                pass
        return False

    q = [launcher_pid]
    seen: set[int] = set()
    while q:
        pid = q.pop(0)
        if pid in seen:
            continue
        if len(seen) >= 4096:
            break
        seen.add(pid)
        if matches(pid):
            out.append(pid)
        for cpid in children_of(pid):
            if cpid not in seen:
                q.append(cpid)
    return out


def resolve_target_pid(
    launcher_pid: int,
    exe_basename: str | None = None,
    *,
    run_dir: Path | None = None,
    timeout_s: float = 8.0,
) -> int:
    end = time.time() + timeout_s
    while time.time() <= end:
        if pid_alive(launcher_pid) and exe_basename:
            cands = collect_matching_pids_under_launcher(launcher_pid, exe_basename, run_dir)
            if cands:
                return pick_hottest_pid_by_ps_pcpu(cands)
        time.sleep(0.02)
    if run_dir is not None and exe_basename:
        scanned = scan_proc_benchmark_pid(run_dir, exe_basename, launcher_pid)
        if scanned is not None:
            return scanned
    return launcher_pid


def pick_spec_benchmark_pid(
    launcher_pid: int,
    run_dir: Path,
    exe_basename: str,
    *,
    resolve_timeout: float = 8.0,
) -> int:
    scanned = scan_proc_benchmark_pid(run_dir, exe_basename, launcher_pid)
    if scanned is not None:
        return scanned
    return resolve_target_pid(launcher_pid, exe_basename, run_dir=run_dir, timeout_s=resolve_timeout)


def cleanup_pid(pid: int | None) -> None:
    if not pid or not pid_alive(pid):
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return
    deadline = time.time() + 5.0
    while time.time() < deadline:
        if not pid_alive(pid):
            return
        time.sleep(0.1)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def parse_run_list_entry(run_list: Path) -> tuple[str, Path]:
    if not run_list.is_file():
        raise FileNotFoundError(f"missing run/list: {run_list}")
    last: tuple[str, Path] | None = None
    for line in run_list.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line == "__END__":
            continue
        parts = line.split()
        run_id = parts[0]
        run_dir = None
        for p in parts[1:]:
            if p.startswith("dir="):
                run_dir = Path(p[len("dir=") :])
                break
        if run_dir is None:
            continue
        last = (run_id, run_dir)
        if run_dir.is_dir():
            return last
    if last is None:
        raise RuntimeError(f"no usable entry in {run_list}")
    raise FileNotFoundError(f"no existing run dir in {run_list}; last entry was {last[1]}")


def shutil_which_or_spec(spec_root: Path) -> str:
    path = subprocess.run(
        ["bash", "-lc", "command -v specinvoke"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ).stdout.strip()
    if path:
        return path
    candidate = spec_root / "bin" / "specinvoke"
    if candidate.exists() and os.access(candidate, os.X_OK):
        return str(candidate)
    raise RuntimeError("specinvoke not found")


def extract_cmd_line(spec_root: Path, bench_run_dir: Path) -> str:
    shrc = spec_root / "shrc"
    specinvoke = shutil_which_or_spec(spec_root)
    cmd = [specinvoke, "-n"]
    env = os.environ.copy()
    if shrc.exists():
        shell_cmd = f"source {shlex.quote(str(shrc))} >/dev/null 2>&1 || true; " + " ".join(
            shlex.quote(x) for x in cmd
        )
        out = subprocess.check_output(
            ["bash", "-lc", shell_cmd],
            cwd=bench_run_dir,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
    else:
        out = subprocess.check_output(
            cmd,
            cwd=bench_run_dir,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("../run_base"):
            return line
    raise RuntimeError(f"failed to extract command in {bench_run_dir}")
