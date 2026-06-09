from __future__ import annotations

from pathlib import Path


def repo_root() -> Path:
    here = Path(__file__).resolve()
    for parent in [here, *here.parents]:
        if (parent / "trace_feature_api.py").is_file():
            return parent
    raise RuntimeError("could not locate Intel_PT_Trace_Processing repo root")
