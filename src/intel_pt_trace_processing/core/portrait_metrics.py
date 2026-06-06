from __future__ import annotations


def flatten_portrait_metrics(report: dict, *, prefix: str = "portrait_") -> dict[str, float | int | str]:
    out: dict[str, float | int | str] = {}
    st = report.get("stats", {})
    for k, v in st.items():
        if isinstance(v, (int, float)):
            out[f"{prefix}{k}"] = v
    mix = report.get("instruction_mix", {}).get("fractions", {})
    for k, v in mix.items():
        out[f"{prefix}mix_{k}"] = float(v)
    sub = report.get("instruction_submix", {}).get("fractions", {})
    for k, v in sub.items():
        out[f"{prefix}submix_{k}"] = float(v)
    opm = report.get("operand_mix", {}).get("fractions", {})
    for k, v in opm.items():
        out[f"{prefix}opmix_{k}"] = float(v)
    bar = report.get("barrier", {}).get("per_1000_insns", {})
    for k, v in bar.items():
        out[f"{prefix}barrier_{k}_per_1k"] = float(v)
    br = report.get("branch", {}).get("per_1000_insns", {})
    for k, v in br.items():
        out[f"{prefix}branch_{k}_per_1k"] = float(v)
    bb = report.get("branch_behavior", {})
    g = bb.get("global", {}) if isinstance(bb, dict) else {}
    if isinstance(g, dict):
        if isinstance(g.get("taken_rate"), (int, float)):
            out[f"{prefix}branch_taken_rate"] = float(g["taken_rate"])
        if isinstance(g.get("entropy"), (int, float)):
            out[f"{prefix}branch_taken_entropy"] = float(g["entropy"])
        if isinstance(g.get("unknown_next_ip_total"), (int, float)):
            out[f"{prefix}branch_unknown_next_ip_total"] = int(g["unknown_next_ip_total"])
        if isinstance(g.get("known_outcome_ratio"), (int, float)):
            out[f"{prefix}branch_known_outcome_ratio"] = float(g["known_outcome_ratio"])
        if isinstance(g.get("conditional_taken_rate"), (int, float)):
            out[f"{prefix}branch_conditional_taken_rate"] = float(g["conditional_taken_rate"])
    sw = bb.get("site_weighted", {}) if isinstance(bb, dict) else {}
    if isinstance(sw, dict):
        if isinstance(sw.get("sites_with_known"), (int, float)):
            out[f"{prefix}branch_sites_with_known"] = int(sw["sites_with_known"])
        if isinstance(sw.get("hot_site_top_mass"), (int, float)):
            out[f"{prefix}branch_hot_site_top_mass"] = float(sw["hot_site_top_mass"])
        if isinstance(sw.get("entropy_mean"), (int, float)):
            out[f"{prefix}branch_site_entropy_mean"] = float(sw["entropy_mean"])
        if isinstance(sw.get("transition_rate_mean"), (int, float)):
            out[f"{prefix}branch_site_transition_rate_mean"] = float(sw["transition_rate_mean"])
    pats = bb.get("patterns", {}) if isinstance(bb, dict) else {}
    if isinstance(pats, dict):
        for length, pobj in pats.items():
            if not isinstance(pobj, dict):
                continue
            if isinstance(pobj.get("distinct_ratio"), (int, float)):
                out[f"{prefix}branch_pat{length}_distinct_ratio"] = float(pobj["distinct_ratio"])
            if isinstance(pobj.get("top_mass"), (int, float)):
                out[f"{prefix}branch_pat{length}_top_mass"] = float(pobj["top_mass"])
            if isinstance(pobj.get("entropy_norm"), (int, float)):
                out[f"{prefix}branch_pat{length}_entropy_norm"] = float(pobj["entropy_norm"])
    sc = report.get("syscall", {})
    if "per_1000_insns" in sc:
        out[f"{prefix}syscall_per_1k"] = float(sc["per_1000_insns"])
    ipc = report.get("ipc", {})
    iv = ipc.get("values", {})
    for k, v in iv.items():
        if isinstance(v, (int, float)):
            out[f"{prefix}ipc_{k}"] = float(v)
    rr = ipc.get("retire_ratio", {})
    for k, v in rr.items():
        if isinstance(v, (int, float)):
            out[f"{prefix}ipc_retire_{k}"] = float(v)
    tot = ipc.get("total", {})
    if isinstance(tot, dict):
        if isinstance(tot.get("insns"), (int, float)):
            out[f"{prefix}ipc_total_insns"] = int(tot["insns"])
        if isinstance(tot.get("cycles"), (int, float)):
            out[f"{prefix}ipc_total_cycles"] = int(tot["cycles"])
        if isinstance(tot.get("ipc"), (int, float)):
            out[f"{prefix}ipc_total"] = float(tot["ipc"])
    for kind in ("raw", "waw", "war"):
        block = report.get("gpr_dependency_distance", {}).get(kind, {})
        for k, v in block.items():
            if k == "buckets":
                for bk, bv in (v or {}).items():
                    out[f"{prefix}{kind}_dist_bucket_{bk}"] = int(bv)
            elif k == "count" and isinstance(v, (int, float)):
                out[f"{prefix}{kind}_dist_count"] = int(v)
            elif isinstance(v, (int, float)):
                out[f"{prefix}{kind}_dist_{k}"] = float(v)
    for kind in ("raw", "waw", "war"):
        block = report.get("vec_dependency_distance", {}).get(kind, {})
        for k, v in block.items():
            if k == "buckets":
                for bk, bv in (v or {}).items():
                    out[f"{prefix}vec_{kind}_dist_bucket_{bk}"] = int(bv)
            elif k == "count" and isinstance(v, (int, float)):
                out[f"{prefix}vec_{kind}_dist_count"] = int(v)
            elif isinstance(v, (int, float)):
                out[f"{prefix}vec_{kind}_dist_{k}"] = float(v)
    return out
