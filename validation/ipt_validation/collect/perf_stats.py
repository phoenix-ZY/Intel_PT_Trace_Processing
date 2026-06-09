from __future__ import annotations


def parse_perf_stat_csv(text: str) -> dict[str, float]:
    out: dict[str, float] = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 3:
            continue
        value_s, _unit, event = parts[0], parts[1], parts[2]
        if not event:
            continue
        try:
            out[event] = float(value_s.replace(",", ""))
        except ValueError:
            continue
    if out.get("cycles", 0.0) > 0 and out.get("instructions", 0.0) >= 0:
        out["ipc"] = out["instructions"] / out["cycles"]
    return out


def parse_perf_stat_unsupported(text: str) -> list[str]:
    bad: list[str] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lower = line.lower()
        if "<not supported>" in lower or "<not counted>" in lower:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 3 and parts[2]:
                bad.append(parts[2])
                continue
            toks = line.replace("<not supported>", "").replace("<not counted>", "").strip().split()
            if toks:
                bad.append(toks[0])
    seen: set[str] = set()
    out: list[str] = []
    for e in bad:
        if e not in seen:
            seen.add(e)
            out.append(e)
    return out
