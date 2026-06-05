from __future__ import annotations

import json
from pathlib import Path
from typing import Any

TRACE_PROFILE_SCHEMA = "trace-profile-v1"


def load_json_object(path: str | Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    p = Path(path)
    if not p.is_file():
        return {}
    raw = p.read_text(encoding="utf-8")
    if not raw.strip():
        return {}
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return obj if isinstance(obj, dict) else {}


def analysis_access_feature(analysis_obj: dict[str, Any], access: str = "all") -> dict[str, Any]:
    per_access = analysis_obj.get("per_access", {})
    if not isinstance(per_access, dict):
        return {}
    access_obj = per_access.get(access)
    if not isinstance(access_obj, dict):
        return {}
    feature = access_obj.get("feature")
    return feature if isinstance(feature, dict) else {}


def compact_artifacts(paths: dict[str, str | Path | None] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in (paths or {}).items():
        if value is None:
            continue
        out[key] = str(value)
    return out


def build_trace_profile(
    *,
    source_kind: str,
    source_path: str | Path,
    prefix: str,
    data_locality: dict[str, Any],
    inst_locality: dict[str, Any] | None = None,
    insn_portrait: dict[str, Any] | None = None,
    recover_report: dict[str, Any] | None = None,
    health: dict[str, Any] | None = None,
    artifacts: dict[str, str | Path | None] | None = None,
    theory: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
    include_legacy_keys: bool = True,
) -> dict[str, Any]:
    """
    Build the canonical trace-profile dictionary.

    The nested ``features`` block is the new normalized surface. Legacy top-level
    keys are kept by default so existing scripts and downstream users do not
    break while the repository migrates to the new layout.
    """
    profile: dict[str, Any] = {
        "schema": TRACE_PROFILE_SCHEMA,
        "prefix": prefix,
        "source": {
            "kind": source_kind,
            "path": str(source_path),
        },
        "features": {
            "data_memory": data_locality,
            "instruction_memory": inst_locality,
            "instruction_portrait": insn_portrait,
            "recovery": recover_report or {},
        },
        "health": health or {},
        "artifacts": compact_artifacts(artifacts),
        "metadata": metadata or {},
    }
    if theory is not None:
        profile["theory"] = theory

    if include_legacy_keys:
        profile["source_perf_data"] = str(source_path) if source_kind == "perf" else None
        profile["data_locality"] = data_locality
        profile["inst_locality"] = inst_locality
        profile["recover_report"] = recover_report or {}
        profile["insn_portrait"] = insn_portrait

    return profile
