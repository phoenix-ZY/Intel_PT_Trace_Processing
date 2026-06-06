from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable


def _csv_escape(value: Any) -> str:
    text = "" if value is None else str(value)
    if any(ch in text for ch in [",", '"', "\n", "\r"]):
        text = text.replace('"', '""')
        return f'"{text}"'
    return text


def flatten_trace_profile(profile: dict[str, Any]) -> dict[str, Any]:
    metadata = profile.get("metadata") if isinstance(profile, dict) else None
    if not isinstance(metadata, dict):
        metadata = {}
    source = metadata.get("source")
    if not isinstance(source, dict):
        source = {}
    row: dict[str, Any] = {
        "schema": profile.get("schema", ""),
        "prefix": metadata.get("prefix", ""),
        "source_kind": source.get("kind", ""),
        "source_path": source.get("path", ""),
    }
    features = profile.get("features")
    if not isinstance(features, dict):
        return row
    for group, values in features.items():
        if not isinstance(values, dict):
            continue
        for key, value in values.items():
            if isinstance(value, bool):
                continue
            if isinstance(value, (int, float, str)):
                row[f"{group}_{key}"] = value
    return row


def write_profiles_csv(path: str | Path, profiles: Iterable[dict[str, Any]]) -> Path:
    rows = [flatten_trace_profile(profile) for profile in profiles]
    headers: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row:
            if key in seen:
                continue
            seen.add(key)
            headers.append(key)

    out_path = Path(path).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [",".join(_csv_escape(h) for h in headers)]
    for row in rows:
        lines.append(",".join(_csv_escape(row.get(h, "")) for h in headers))
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path
