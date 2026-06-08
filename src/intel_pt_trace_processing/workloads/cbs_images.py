from __future__ import annotations

import os
import subprocess
from pathlib import Path


def default_cbs_root() -> Path:
    for key in ("COLOCATION_BENCH_SUITE_DIR", "CBS_ROOT"):
        value = os.environ.get(key, "").strip()
        if value:
            return Path(value)
    return Path.home() / "colocation-bench-suite"


def ensure_cbs_image_env() -> Path | None:
    """Load CBS conf/images.env into os.environ (setdefault only)."""
    cbs_root = default_cbs_root()
    images_env = cbs_root / "conf" / "images.env"
    if not images_env.is_file():
        return None

    result = subprocess.run(
        ["bash", "-lc", f'source "{images_env}" && env -0'],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return None

    for entry in result.stdout.split(b"\0"):
        if not entry or b"=" not in entry:
            continue
        key, _, value = entry.partition(b"=")
        name = key.decode("utf-8", errors="replace")
        if not name.startswith(("CBS_", "DOCKER_")):
            continue
        os.environ.setdefault(name, value.decode("utf-8", errors="replace"))

    os.environ.setdefault("COLOCATION_BENCH_SUITE_DIR", str(cbs_root))
    os.environ.setdefault("CLAB_IMAGE", os.environ.get("CBS_OFFLINE_IMAGE", ""))
    os.environ.setdefault("DCPERF_V2_IMAGE", os.environ.get("CBS_DCPERF_V2_IMAGE", ""))
    os.environ.setdefault("TAO_CLAB_IMAGE", os.environ.get("CBS_DCPERF_V2_IMAGE", ""))
    os.environ.setdefault(
        "DOCKER_BENCH_CLIENT_IMAGE",
        os.environ.get("CBS_BENCH_CLIENT_IMAGE", "cbs-bench-client:ubuntu22"),
    )
    return cbs_root


def cloud_project_dir(cbs_root: Path | None = None) -> Path:
    """Directory for www/, certs/, and bench-client /data mount (canonical: CBS root)."""
    if cbs_root is None:
        cbs_root = default_cbs_root()
    override = os.environ.get("CBS_CLOUD_PROJECT_DIR", "").strip()
    if override:
        return Path(override)
    return cbs_root
