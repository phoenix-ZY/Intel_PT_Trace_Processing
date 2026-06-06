from __future__ import annotations

import math
from typing import Any

from intel_pt_trace_processing.core.portrait_metrics import flatten_portrait_metrics

FEATURE_GROUP_ORDER = (
    "instruction_mix",
    "data_memory",
    "instruction_memory",
    "branch",
    "syscall",
    "register_dependency",
    "ipc",
)


def syscall_category_map() -> dict[int, str]:
    cat_map: dict[int, str] = {}
    # Linux x86_64 syscall groupings. The categories are deliberately coarse:
    # they are workload features, not ABI documentation.
    for nr in (
        0,
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        16,
        17,
        19,
        20,
        21,
        22,
        23,
        24,
        25,
        26,
        27,
        28,
        29,
        32,
        33,
        34,
        35,
        39,
        40,
        72,
        73,
        74,
        75,
        76,
        77,
        78,
        79,
        80,
        81,
        82,
        83,
        84,
        85,
        86,
        87,
        88,
        89,
        90,
        91,
        92,
        93,
        94,
        132,
        133,
        137,
        138,
        155,
        161,
        162,
        165,
        166,
        167,
        168,
        169,
        170,
        179,
        187,
        188,
        189,
        190,
        191,
        192,
        193,
        194,
        195,
        196,
        197,
        198,
        199,
        200,
        217,
        221,
        257,
        258,
        259,
        260,
        261,
        262,
        263,
        264,
        265,
        266,
        267,
        268,
        269,
        280,
        281,
        285,
        286,
        287,
        303,
        304,
        316,
        322,
        332,
        334,
        353,
        437,
    ):
        cat_map[nr] = "file"
    for nr in (41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55):
        cat_map[nr] = "net"
    for nr in (
        56,
        57,
        58,
        59,
        60,
        61,
        62,
        63,
        64,
        65,
        101,
        157,
        203,
        231,
        234,
        272,
        273,
        317,
        424,
        434,
        435,
        436,
    ):
        cat_map[nr] = "process"
    for nr in (96, 97, 98, 99, 100, 201, 202, 204, 228, 229, 230, 232, 233):
        cat_map[nr] = "time"
    for nr in (9, 10, 11, 12, 25, 26, 27, 28, 29, 158, 159, 160, 216, 237, 238, 239, 324, 325, 329):
        cat_map[nr] = "memory"
    return cat_map


def predefined_feature_groups() -> dict[str, list[str]]:
    rd_bins = [
        "1",
        "2",
        "3-4",
        "5-8",
        "9-16",
        "17-32",
        "33-64",
        "65-128",
        "129-256",
        "257-512",
        "513-1024",
        "1025-2048",
        "2049-4096",
        "4097-8192",
        "8193-16384",
        "16385-32768",
        "32769-65536",
        "65537-131072",
        "131073-262144",
        ">=262144",
    ]
    stride_bins = [
        "0",
        "1",
        "2-4",
        "5-16",
        "17-64",
        "65-256",
        "257-1024",
        "1025-4096",
        "4097-16384",
        "16385-65536",
        "65537-262144",
        ">=262144",
    ]
    locality_common = (
        [f"rd_prob::{b}" for b in rd_bins]
        + [f"stride_prob::{b}" for b in stride_bins]
        + [
            "rd_entropy",
            "stride_entropy",
            "rd_local_mass_le_64",
            "stride_near_mass_abs_le_1",
            "stride_far_mass_abs_gt_64",
            "stride_forward_ratio",
            "stride_backward_ratio",
        ]
    )
    return {
        "instruction_mix": [
            "alu",
            "branch_conditional",
            "branch_unconditional",
            "call_direct",
            "return",
            "lea",
            "compare",
            "load_store_mov",
            "mov",
            "opmix_reg_to_reg",
            "opmix_mem_to_reg",
            "opmix_imm_to_reg",
            "opmix_reg_to_mem",
            "opmix_imm_to_mem",
            "opmix_imm",
            "opmix_reg",
            "opmix_none",
            "submix_alu_addsub",
            "submix_alu_logic",
            "submix_alu_shift",
            "submix_alu_muldiv",
            "submix_compare",
            "submix_lea",
            "submix_branch",
            "submix_call",
            "submix_ret",
            "submix_setcc",
            "submix_cmov",
            "submix_prefix_rep",
            "submix_prefix_lock",
            "submix_barrier_fence",
            "submix_barrier_pause",
            "submix_syscall",
            "submix_simd_sse",
            "submix_simd_avx",
            "submix_simd_avx512",
        ],
        "data_memory": locality_common
        + [
            "cold_ratio",
            "accesses_per_1k_insns",
            "read_ratio",
            "write_ratio",
            "prefetch_nl_accuracy_proxy",
            "prefetch_nl_coverage_proxy",
            "prefetch_nl_pollution_proxy",
            "prefetch_pc_nl_coverage_proxy_mean",
            "prefetch_pc_nl_coverage_proxy_p90",
            "prefetch_pc_nl_coverage_proxy_weighted",
            "prefetch_pc_sign_flip_rate_mean",
            "prefetch_pc_stability_proxy_mean",
            "prefetch_pc_stream_forward_le4_proxy_mean",
            "prefetch_stream_far_jump_proxy",
            "prefetch_stream_forward_le4_proxy",
            "prefetch_zero_delta_proxy",
        ],
        "instruction_memory": locality_common
        + [
            "cold_ratio",
        ],
        "branch": [
            "total_per_1k",
            "conditional_per_1k",
            "unconditional_per_1k",
            "indirect_per_1k",
            "call_direct_per_1k",
            "call_indirect_per_1k",
            "return_per_1k",
            "conditional_taken_rate",
            "known_outcome_ratio",
            "taken_rate",
            "taken_entropy",
            "unknown_next_ip_rate",
            "hot_site_top_mass",
            "site_entropy_mean",
            "site_transition_rate_mean",
            "pat4_distinct_ratio",
            "pat4_top_mass",
            "pat4_entropy_norm",
            "pat8_distinct_ratio",
            "pat8_top_mass",
            "pat8_entropy_norm",
            "pat16_distinct_ratio",
            "pat16_top_mass",
            "pat16_entropy_norm",
            "pat32_distinct_ratio",
            "pat32_top_mass",
            "pat32_entropy_norm",
        ],
        "syscall": [
            "per_1k",
            "distinct_ratio",
            "cat_file_ratio",
            "cat_net_ratio",
            "cat_memory_ratio",
            "cat_process_ratio",
            "cat_time_ratio",
            "cat_other_ratio",
        ],
        "register_dependency": [
            "raw_per_1k",
            "raw_dist_mean",
            "raw_dist_bucket_1-4_ratio",
            "raw_dist_bucket_5-16_ratio",
            "raw_dist_bucket_17-64_ratio",
            "raw_dist_bucket_65+_ratio",
            "war_per_1k",
            "war_dist_mean",
            "war_dist_bucket_1-4_ratio",
            "war_dist_bucket_5-16_ratio",
            "war_dist_bucket_17-64_ratio",
            "war_dist_bucket_65+_ratio",
            "waw_per_1k",
            "waw_dist_mean",
            "waw_dist_bucket_1-4_ratio",
            "waw_dist_bucket_5-16_ratio",
            "waw_dist_bucket_17-64_ratio",
            "waw_dist_bucket_65+_ratio",
            "vec_raw_per_1k",
            "vec_raw_dist_mean",
            "vec_raw_dist_bucket_1-4_ratio",
            "vec_raw_dist_bucket_5-16_ratio",
            "vec_raw_dist_bucket_17-64_ratio",
            "vec_raw_dist_bucket_65+_ratio",
            "vec_war_per_1k",
            "vec_war_dist_mean",
            "vec_war_dist_bucket_1-4_ratio",
            "vec_war_dist_bucket_5-16_ratio",
            "vec_war_dist_bucket_17-64_ratio",
            "vec_war_dist_bucket_65+_ratio",
            "vec_waw_per_1k",
            "vec_waw_dist_mean",
            "vec_waw_dist_bucket_1-4_ratio",
            "vec_waw_dist_bucket_5-16_ratio",
            "vec_waw_dist_bucket_17-64_ratio",
            "vec_waw_dist_bucket_65+_ratio",
        ],
        "ipc": ["total"],
    }


def _finite_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    out = float(value)
    return out if math.isfinite(out) else None


def _complete_group(group: str, values: dict[str, float]) -> dict[str, float]:
    keys = predefined_feature_groups().get(group, [])
    return {key: float(values.get(key, 0.0)) for key in keys}


def _strip_known_prefix(value: str, prefix: str) -> str:
    return value[len(prefix) :] if value.startswith(prefix) else value


def _dedup_subprefix(prefix: str, value: str) -> str:
    head = f"{prefix}_"
    while value.startswith(head):
        value = value[len(head) :]
    return value


def _portrait_decoded(portrait: dict[str, Any] | None) -> float:
    if not isinstance(portrait, dict):
        return 0.0
    return _finite_number(portrait.get("decoded")) or 0.0


def _flatten_locality_feature(analysis_obj: dict[str, Any] | None, *, access: str = "all") -> dict[str, float]:
    if not isinstance(analysis_obj, dict):
        return {}
    per_access = analysis_obj.get("per_access")
    if not isinstance(per_access, dict):
        return {}
    access_obj = per_access.get(access)
    if not isinstance(access_obj, dict):
        return {}
    feature = access_obj.get("feature")
    if not isinstance(feature, dict):
        return {}

    out: dict[str, float] = {}
    cold_ratio = _finite_number(access_obj.get("cold_ratio"))
    if cold_ratio is not None:
        out["cold_ratio"] = cold_ratio

    for bins_key, prob_key, out_prefix in (
        ("rd_bins", "rd_prob", "rd_prob"),
        ("stride_bins", "stride_prob", "stride_prob"),
    ):
        bins = feature.get(bins_key)
        probs = feature.get(prob_key)
        if isinstance(bins, list) and isinstance(probs, list):
            for label, prob in zip(bins, probs):
                number = _finite_number(prob)
                if number is not None:
                    out[f"{out_prefix}::{label}"] = number

    for key, value in feature.items():
        if key in {"rd_bins", "rd_prob", "stride_bins", "stride_prob"}:
            continue
        number = _finite_number(value)
        if number is not None:
            out[key] = number
    return out


def _analysis_events(analysis_obj: dict[str, Any] | None, *, access: str = "all") -> float:
    if not isinstance(analysis_obj, dict):
        return 0.0
    per_access = analysis_obj.get("per_access")
    if not isinstance(per_access, dict):
        return 0.0
    access_obj = per_access.get(access)
    if not isinstance(access_obj, dict):
        return 0.0
    return _finite_number(access_obj.get("events")) or 0.0


def _analysis_read_write_ratios(analysis_obj: dict[str, Any] | None) -> dict[str, float]:
    if not isinstance(analysis_obj, dict):
        return {}
    per_access = analysis_obj.get("per_access")
    if not isinstance(per_access, dict):
        return {}
    read = per_access.get("read")
    write = per_access.get("write")
    if not isinstance(read, dict) or not isinstance(write, dict):
        return {}
    read_events = _finite_number(read.get("events")) or 0.0
    write_events = _finite_number(write.get("events")) or 0.0
    total = read_events + write_events
    if total <= 0.0:
        return {}
    return {
        "read_ratio": read_events / total,
        "write_ratio": write_events / total,
    }


def _portrait_group_metrics(portrait: dict[str, Any] | None) -> dict[str, dict[str, float]]:
    groups = {name: {} for name in FEATURE_GROUP_ORDER}
    if not isinstance(portrait, dict) or not portrait:
        return groups
    groups["instruction_mix"].update(_instruction_mix_from_portrait(portrait))
    flat = flatten_portrait_metrics(portrait, prefix="")
    for key, value in flat.items():
        number = _finite_number(value)
        if number is None:
            continue
        core = str(key)
        if core in {"lines_with_ipc_annotation", "skipped_lines", "parsed_instructions"}:
            continue
        if core.startswith(("mix_", "submix_", "opmix_", "barrier_")):
            out_name = _dedup_subprefix("mix", core)
            groups["instruction_mix"][out_name] = number
        elif core.startswith("branch_"):
            groups["branch"][_dedup_subprefix("branch", core)] = number
        elif core.startswith("syscall_"):
            groups["syscall"][_dedup_subprefix("syscall", core)] = number
        elif core == "ipc_total":
            groups["ipc"]["total"] = number
    groups["branch"].update(_branch_metrics_from_portrait(portrait, flat))
    groups["register_dependency"].update(_dependency_metrics_from_flat(flat, decoded=_portrait_decoded(portrait)))
    return groups


def _counter_list_by_name(value: Any) -> dict[str, float]:
    out: dict[str, float] = {}
    if not isinstance(value, list):
        return out
    for entry in value:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        count = _finite_number(entry.get("count"))
        if isinstance(name, str) and count is not None:
            out[name.upper()] = count
    return out


def _sum_counts(counts: dict[str, float], names: set[str]) -> float:
    return sum(count for name, count in counts.items() if name in names)


def _sum_prefixes(counts: dict[str, float], prefixes: tuple[str, ...]) -> float:
    return sum(count for name, count in counts.items() if name.startswith(prefixes))


def _instruction_mix_from_portrait(portrait: dict[str, Any]) -> dict[str, float]:
    decoded = _finite_number(portrait.get("decoded")) or 0.0
    denom = decoded if decoded > 0.0 else 1.0
    categories = _counter_list_by_name(portrait.get("categories"))
    iclasses = _counter_list_by_name(portrait.get("iclasses"))

    cond = categories.get("COND_BR", 0.0)
    uncond = categories.get("UNCOND_BR", 0.0)
    call = categories.get("CALL", 0.0)
    ret = categories.get("RET", 0.0)
    dataxfer = categories.get("DATAXFER", 0.0)
    alu_binary = categories.get("BINARY", 0.0)
    alu_logic = categories.get("LOGICAL", 0.0)
    alu_shift = categories.get("SHIFT", 0.0)
    compare = _sum_prefixes(iclasses, ("CMP", "TEST"))
    lea = iclasses.get("LEA", 0.0)
    setcc = categories.get("SETCC", 0.0)
    cmov = categories.get("CMOV", 0.0)
    syscall = categories.get("SYSCALL", 0.0)
    sse = categories.get("SSE", 0.0)
    avx = categories.get("AVX", 0.0) + categories.get("AVX2", 0.0)
    avx512 = categories.get("AVX512", 0.0)
    mov = _sum_prefixes(iclasses, ("MOV",))
    addsub = _sum_counts(iclasses, {"ADD", "ADC", "SUB", "SBB", "INC", "DEC", "NEG"})
    logic = _sum_counts(iclasses, {"AND", "OR", "XOR", "NOT"})
    shift = _sum_prefixes(iclasses, ("SHL", "SHR", "SAL", "SAR", "ROL", "ROR"))
    muldiv = _sum_counts(iclasses, {"MUL", "IMUL", "DIV", "IDIV"})
    prefix_rep = _sum_prefixes(iclasses, ("REP",))
    prefix_lock = sum(count for name, count in iclasses.items() if "LOCK" in name)

    direct_calls = _finite_number(portrait.get("direct_calls"))
    return {
        "alu": (alu_binary + alu_logic + alu_shift) / denom,
        "branch_conditional": cond / denom,
        "branch_unconditional": uncond / denom,
        "call_direct": (direct_calls if direct_calls is not None else call) / denom,
        "return": ret / denom,
        "lea": lea / denom,
        "compare": compare / denom,
        "load_store_mov": dataxfer / denom,
        "mov": mov / denom,
        "submix_alu_addsub": addsub / denom,
        "submix_alu_logic": logic / denom,
        "submix_alu_shift": shift / denom,
        "submix_alu_muldiv": muldiv / denom,
        "submix_compare": compare / denom,
        "submix_lea": lea / denom,
        "submix_branch": (cond + uncond) / denom,
        "submix_call": call / denom,
        "submix_ret": ret / denom,
        "submix_setcc": setcc / denom,
        "submix_cmov": cmov / denom,
        "submix_prefix_rep": prefix_rep / denom,
        "submix_prefix_lock": prefix_lock / denom,
        "submix_barrier_fence": categories.get("SEMAPHORE", 0.0) / denom,
        "submix_barrier_pause": iclasses.get("PAUSE", 0.0) / denom,
        "submix_syscall": syscall / denom,
        "submix_simd_sse": sse / denom,
        "submix_simd_avx": avx / denom,
        "submix_simd_avx512": avx512 / denom,
    }


def _branch_metrics_from_portrait(portrait: dict[str, Any], flat: dict[str, float | int | str]) -> dict[str, float]:
    decoded = _portrait_decoded(portrait)
    denom = decoded if decoded > 0.0 else 1.0
    conditional = _finite_number(flat.get("branch_conditional_per_1k")) or 0.0
    unconditional = _finite_number(flat.get("branch_unconditional_per_1k")) or 0.0
    indirect = _finite_number(flat.get("branch_indirect_per_1k")) or 0.0
    call_direct = _finite_number(flat.get("branch_call_direct_per_1k")) or 0.0
    call_indirect = _finite_number(flat.get("branch_call_indirect_per_1k")) or 0.0
    returns = _finite_number(flat.get("branch_return_per_1k")) or 0.0
    unknown = _finite_number(flat.get("branch_unknown_next_ip_total")) or 0.0
    return {
        "total_per_1k": conditional + unconditional + indirect + call_direct + call_indirect + returns,
        "unknown_next_ip_rate": unknown / denom,
    }


def _dependency_metrics_from_flat(flat: dict[str, float | int | str], *, decoded: float) -> dict[str, float]:
    out: dict[str, float] = {}
    insn_denom = decoded if decoded > 0.0 else 1.0
    for prefix in ("raw", "war", "waw", "vec_raw", "vec_war", "vec_waw"):
        base = f"{prefix}_dist"
        count = _finite_number(flat.get(f"{base}_count")) or 0.0
        mean = _finite_number(flat.get(f"{base}_mean")) or 0.0
        out[f"{prefix}_per_1k"] = 1000.0 * count / insn_denom
        out[f"{base}_mean"] = mean
        bucket_denom = count if count > 0.0 else 1.0
        for bucket in ("1-4", "5-16", "17-64", "65+"):
            value = _finite_number(flat.get(f"{base}_bucket_{bucket}")) or 0.0
            out[f"{base}_bucket_{bucket}_ratio"] = value / bucket_denom
    return out


def _recover_syscall_metrics(recover_report: dict[str, Any] | None) -> dict[str, float]:
    out: dict[str, float] = {}
    if not isinstance(recover_report, dict):
        return out

    syscalls = recover_report.get("syscalls")
    if not isinstance(syscalls, list):
        return out

    cat_map = syscall_category_map()
    total = 0.0
    by_cat: dict[str, float] = {}
    distinct = 0
    for entry in syscalls:
        if not isinstance(entry, dict):
            continue
        nr = _finite_number(entry.get("nr"))
        count = _finite_number(entry.get("count"))
        if nr is None or count is None or count <= 0.0:
            continue
        distinct += 1
        total += count
        cat = cat_map.get(int(nr), "other")
        by_cat[cat] = by_cat.get(cat, 0.0) + count

    out["distinct_ratio"] = (float(distinct) / total) if total > 0.0 else 0.0
    for cat in ("file", "net", "memory", "process", "time", "other"):
        out[f"cat_{cat}_ratio"] = (by_cat.get(cat, 0.0) / total) if total > 0.0 else 0.0
    return out


def build_feature_groups(
    *,
    data_locality: dict[str, Any] | None,
    inst_locality: dict[str, Any] | None = None,
    insn_portrait: dict[str, Any] | None = None,
    recover_report: dict[str, Any] | None = None,
) -> dict[str, dict[str, float]]:
    portrait_groups = _portrait_group_metrics(insn_portrait)
    decoded = _portrait_decoded(insn_portrait)
    syscall = dict(portrait_groups["syscall"])
    syscall.update(_recover_syscall_metrics(recover_report))
    data_memory = _flatten_locality_feature(data_locality)
    data_memory.update(_analysis_read_write_ratios(data_locality))
    inst_memory = _flatten_locality_feature(inst_locality)
    if decoded > 0.0:
        data_memory["accesses_per_1k_insns"] = 1000.0 * _analysis_events(data_locality) / decoded
    if isinstance(recover_report, dict):
        reads = _finite_number(recover_report.get("mem_read_events")) or 0.0
        writes = _finite_number(recover_report.get("mem_write_events")) or 0.0
        total = reads + writes
        if total > 0.0:
            data_memory["read_ratio"] = reads / total
            data_memory["write_ratio"] = writes / total
    groups = {
        "instruction_mix": _complete_group("instruction_mix", portrait_groups["instruction_mix"]),
        "data_memory": _complete_group("data_memory", data_memory),
        "instruction_memory": _complete_group("instruction_memory", inst_memory),
        "branch": _complete_group("branch", portrait_groups["branch"]),
        "syscall": _complete_group("syscall", syscall),
        "register_dependency": _complete_group("register_dependency", portrait_groups["register_dependency"]),
        "ipc": _complete_group("ipc", portrait_groups["ipc"]),
    }
    return {name: groups[name] for name in FEATURE_GROUP_ORDER}


def feature_group(profile: dict[str, Any], group: str) -> dict[str, float]:
    features = profile.get("features") if isinstance(profile, dict) else None
    if not isinstance(features, dict):
        return {}
    obj = features.get(group)
    if not isinstance(obj, dict):
        return {}
    out: dict[str, float] = {}
    for key, value in obj.items():
        number = _finite_number(value)
        if number is not None:
            out[str(key)] = number
    return out
