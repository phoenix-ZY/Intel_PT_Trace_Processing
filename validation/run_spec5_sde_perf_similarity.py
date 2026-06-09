#!/usr/bin/env python3
"""Host-native SPEC + SDE validation (not CBS container-aligned)."""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
VAL_DIR = REPO_ROOT / "validation"
for path in (REPO_ROOT, SRC_DIR, VAL_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from ipt_validation.collect.spec_batch import main


if __name__ == "__main__":
    raise SystemExit(main())
