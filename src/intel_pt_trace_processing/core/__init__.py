"""Shared feature schema and model interfaces."""

from .features import TRACE_PROFILE_SCHEMA, build_trace_profile, load_json_object
from .theory import TheoryConfig, predict_from_trace_profile

__all__ = [
    "TRACE_PROFILE_SCHEMA",
    "TheoryConfig",
    "build_trace_profile",
    "load_json_object",
    "predict_from_trace_profile",
]
