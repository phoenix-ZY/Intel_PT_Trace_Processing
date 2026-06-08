#!/usr/bin/env python3
"""Legacy host-native SPEC PT collector (not aligned with CBS container workloads).

For colocation-aligned SPEC offline PT, use run_offline_perf_trace_analysis.py
with --mode spec (CBS container + offline_workload_lib).
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
for _path in (REPO_ROOT, SRC_DIR):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from intel_pt_trace_processing.collect.spec_perf_cli import main


if __name__ == "__main__":
    raise SystemExit(main())
