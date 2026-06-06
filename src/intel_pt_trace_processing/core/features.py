from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from intel_pt_trace_processing.core.feature_groups import build_feature_groups, feature_group

TRACE_PROFILE_SCHEMA = "trace-profile-v2"


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


def analysis_view(profile_or_analysis: dict[str, Any], *, memory: str) -> dict[str, Any]:
    """
    Return the final memory feature group from a canonical trace profile.

    ``memory`` accepts ``data``/``data_memory`` or
    ``instruction``/``inst``/``instruction_memory``.
    """
    if not isinstance(profile_or_analysis, dict):
        return {}

    features = profile_or_analysis.get("features")
    if not isinstance(features, dict):
        features = {}
    key = memory.strip().lower().replace("-", "_")
    if key in {"data", "data_memory", "memory"}:
        obj = features.get("data_memory")
    elif key in {"instruction", "inst", "instruction_memory", "inst_memory"}:
        obj = features.get("instruction_memory")
    else:
        raise ValueError(f"unknown memory view: {memory}")
    return obj if isinstance(obj, dict) else {}


def portrait_view(profile: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(profile, dict):
        return {}
    features = profile.get("features")
    return features if isinstance(features, dict) else {}


def recovery_view(profile: dict[str, Any]) -> dict[str, Any]:
    metadata = profile.get("metadata") if isinstance(profile, dict) else None
    if not isinstance(metadata, dict):
        return {}
    recover = metadata.get("recover")
    return recover if isinstance(recover, dict) else {}


def health_view(profile: dict[str, Any]) -> dict[str, Any]:
    metadata = profile.get("metadata") if isinstance(profile, dict) else None
    if not isinstance(metadata, dict):
        return {}
    health = metadata.get("health")
    return health if isinstance(health, dict) else {}


def artifacts_view(profile: dict[str, Any]) -> dict[str, Any]:
    metadata = profile.get("metadata") if isinstance(profile, dict) else None
    if not isinstance(metadata, dict):
        return {}
    artifacts = metadata.get("artifacts")
    return artifacts if isinstance(artifacts, dict) else {}


def write_trace_profile(path: str | Path, profile: dict[str, Any]) -> Path:
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(profile, indent=2, ensure_ascii=False), encoding="utf-8")
    return out_path


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
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    source = {
        "kind": source_kind,
        "path": str(source_path),
    }
    meta = dict(metadata or {})
    meta.update(
        {
            "prefix": prefix,
            "source": source,
            "health": health or {},
            "artifacts": compact_artifacts(artifacts),
        }
    )
    if recover_report:
        meta["recover"] = recover_report
    return {
        "schema": TRACE_PROFILE_SCHEMA,
        "features": build_feature_groups(
            data_locality=data_locality,
            inst_locality=inst_locality,
            insn_portrait=insn_portrait,
            recover_report=recover_report,
        ),
        "metadata": meta,
    }


def memory_feature_view(profile: dict[str, Any], *, memory: str) -> dict[str, float]:
    key = memory.strip().lower().replace("-", "_")
    if key in {"data", "data_memory", "memory"}:
        return feature_group(profile, "data_memory")
    if key in {"instruction", "inst", "instruction_memory", "inst_memory"}:
        return feature_group(profile, "instruction_memory")
    raise ValueError(f"unknown memory view: {memory}")
