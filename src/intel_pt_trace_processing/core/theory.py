from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .features import analysis_access_feature


@dataclass
class TheoryConfig:
    enabled: bool = False
    model: str = "miic-interval-v1"
    access: str = "all"


class InstructionTheoryHook(Protocol):
    """
    Future per-instruction theory-model hook.

    The current production pipeline still performs theory calculation as a
    post-pass over the normalized profile. Stream processors can use this hook
    shape to update model state while each instruction is visited.
    """

    def on_instruction(self, event: dict[str, Any]) -> None:
        ...

    def finish(self) -> dict[str, Any]:
        ...


class DisabledTheoryHook:
    def on_instruction(self, event: dict[str, Any]) -> None:
        return None

    def finish(self) -> dict[str, Any]:
        return {"enabled": False}


def predict_from_trace_profile(profile: dict[str, Any], config: TheoryConfig) -> dict[str, Any] | None:
    if not config.enabled:
        return None
    if config.model != "miic-interval-v1":
        return {
            "schema": "trace-theory-v1",
            "enabled": True,
            "model": config.model,
            "status": "unsupported_model",
        }

    try:
        from intel_pt_trace_processing.core.portrait_metrics import flatten_portrait_metrics
        from intel_pt_trace_processing.model.miic_interval import CpuSprLikeConfig, MiicInputs, predict_interval_cycles
    except Exception as exc:
        return {
            "schema": "trace-theory-v1",
            "enabled": True,
            "model": config.model,
            "status": "unavailable",
            "reason": repr(exc),
        }

    features = profile.get("features", {})
    if not isinstance(features, dict):
        features = {}
    data_analysis = features.get("data_memory")
    inst_analysis = features.get("instruction_memory")
    portrait_obj = features.get("instruction_portrait")
    data_analysis = data_analysis if isinstance(data_analysis, dict) else {}
    inst_analysis = inst_analysis if isinstance(inst_analysis, dict) else {}
    portrait_obj = portrait_obj if isinstance(portrait_obj, dict) else {}

    data_feature = analysis_access_feature(data_analysis, access=config.access)
    inst_feature = analysis_access_feature(inst_analysis, access=config.access)
    flat_portrait = flatten_portrait_metrics(portrait_obj) if portrait_obj else {}

    def pick_float(*keys: str, default: float = 0.0) -> float:
        for key in keys:
            value = flat_portrait.get(key)
            if isinstance(value, (int, float)):
                return float(value)
        return default

    n_instructions = pick_float("portrait_parsed_instructions")
    if n_instructions <= 0.0:
        return {
            "schema": "trace-theory-v1",
            "enabled": True,
            "model": config.model,
            "status": "missing_instruction_count",
        }

    miic_inputs = MiicInputs(
        n_instructions=n_instructions,
        load_frac=max(0.0, min(1.0, pick_float("portrait_opmix_mem_to_reg"))),
        store_frac=max(
            0.0,
            min(1.0, pick_float("portrait_opmix_reg_to_mem", "portrait_opmix_imm_to_mem")),
        ),
        cond_branch_per_1k=pick_float("portrait_branch_conditional_per_1k"),
        branch_taken_entropy=pick_float("portrait_branch_taken_entropy"),
        data_feature=data_feature,
        inst_feature=inst_feature,
    )
    pred = predict_interval_cycles(miic_inputs, cfg=CpuSprLikeConfig())
    return {
        "schema": "trace-theory-v1",
        "enabled": True,
        "model": config.model,
        "status": "ok",
        "prediction": {
            "cycles": pred.cycles,
            "ipc": pred.ipc,
            "cpi": pred.cpi,
            "stack": pred.stack,
            "derived": pred.derived,
        },
    }
