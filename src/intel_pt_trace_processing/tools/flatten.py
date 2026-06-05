from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable


def _csv_escape(value: Any) -> str:
    text = "" if value is None else str(value)
    if any(ch in text for ch in [",", '"', "\n", "\r"]):
        text = text.replace('"', '""')
        return f'"{text}"'
    return text


def _merge(dst: dict[str, Any], prefix: str, values: dict[str, Any]) -> None:
    for key, value in values.items():
        dst[f"{prefix}_{key}" if prefix else key] = value


def flatten_feature_object(feature: dict[str, Any]) -> dict[str, float | int | str]:
    """
    Flatten one feature object into scalar CSV columns.

    Histogram-style pairs such as ``rd_bins``/``rd_prob`` and
    ``stride_bins``/``stride_prob`` become stable columns like
    ``rd_prob::1-2``. Other numeric scalar keys pass through unchanged.
    """
    out: dict[str, float | int | str] = {}

    for bins_key, prob_key, out_prefix in (
        ("rd_bins", "rd_prob", "rd_prob"),
        ("stride_bins", "stride_prob", "stride_prob"),
    ):
        bins = feature.get(bins_key)
        probs = feature.get(prob_key)
        if isinstance(bins, list) and isinstance(probs, list):
            for label, prob in zip(bins, probs):
                if isinstance(prob, (int, float)):
                    out[f"{out_prefix}::{label}"] = float(prob)

    for key, value in feature.items():
        if key in {"rd_bins", "rd_prob", "stride_bins", "stride_prob"}:
            continue
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            out[key] = float(value)
        elif isinstance(value, str):
            out[key] = value
    return out


def flatten_analysis_features(analysis: dict[str, Any], *, namespace: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    per_access = analysis.get("per_access")
    if not isinstance(per_access, dict):
        return out
    for access, access_obj in per_access.items():
        if not isinstance(access_obj, dict):
            continue
        feature = access_obj.get("feature")
        if not isinstance(feature, dict):
            continue
        _merge(out, f"{namespace}_{access}", flatten_feature_object(feature))
    return out


def flatten_recovery_report(report: dict[str, Any], *, namespace: str = "recover") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in report.items():
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float, str)):
            out[f"{namespace}_{key}"] = value
    syscalls = report.get("syscalls")
    if isinstance(syscalls, list):
        out[f"{namespace}_syscall_distinct"] = len(syscalls)
        for item in syscalls[:8]:
            if not isinstance(item, dict):
                continue
            nr = item.get("nr")
            count = item.get("count")
            if isinstance(nr, (int, float)) and isinstance(count, (int, float)):
                out[f"{namespace}_syscall_nr_{int(nr)}_count"] = float(count)
    return out


def flatten_portrait(portrait: dict[str, Any]) -> dict[str, Any]:
    if not portrait:
        return {}
    try:
        from intel_pt_trace_processing.core import portrait as insn_portrait
    except Exception:
        return {}
    flat = insn_portrait.flatten_portrait_metrics(portrait)
    return {k: v for k, v in flat.items() if isinstance(v, (int, float, str))}


def flatten_trace_profile(profile: dict[str, Any]) -> dict[str, Any]:
    row: dict[str, Any] = {
        "schema": profile.get("schema", ""),
        "prefix": profile.get("prefix", ""),
    }
    source = profile.get("source")
    if isinstance(source, dict):
        row["source_kind"] = source.get("kind", "")
        row["source_path"] = source.get("path", "")

    health = profile.get("health")
    if isinstance(health, dict):
        for key, value in health.items():
            if isinstance(value, (int, float, str)):
                row[f"health_{key}"] = value

    features = profile.get("features")
    if not isinstance(features, dict):
        return row

    data_memory = features.get("data_memory")
    if isinstance(data_memory, dict):
        row.update(flatten_analysis_features(data_memory, namespace="data"))

    instruction_memory = features.get("instruction_memory")
    if isinstance(instruction_memory, dict):
        row.update(flatten_analysis_features(instruction_memory, namespace="inst"))

    recovery = features.get("recovery")
    if isinstance(recovery, dict):
        row.update(flatten_recovery_report(recovery))

    portrait = features.get("instruction_portrait")
    if isinstance(portrait, dict):
        row.update(flatten_portrait(portrait))

    theory = profile.get("theory")
    if isinstance(theory, dict):
        prediction = theory.get("prediction")
        if isinstance(prediction, dict):
            for key in ("cycles", "ipc", "cpi"):
                value = prediction.get(key)
                if isinstance(value, (int, float)):
                    row[f"theory_{key}"] = float(value)
            stack = prediction.get("stack")
            if isinstance(stack, dict):
                for key, value in stack.items():
                    if isinstance(value, (int, float)):
                        row[f"theory_stack_{key}"] = float(value)
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
