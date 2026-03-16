import hashlib
import json
from datetime import datetime
from urllib.parse import urlparse

CANONICAL_FINDING_DEFAULTS = {
    "id": "",
    "id_stable": "",
    "scan_id": None,
    "title": "Unknown Finding",
    "description": "",
    "severity": "info",
    "confidence": "medium",
    "tool_source": "unknown",
    "tool": "",
    "module": "",
    "category": "general",
    "target": "",
    "endpoint": "",
    "parameter": "",
    "payload": "",
    "evidence": "",
    "reproduction": "",
    "request": "",
    "response": "",
    "repro_command": "",
    "raw_output": "",
    "metadata": {},
    "signal_ids": [],
    "created_at": "",
    "exploit_score": None,
    "risk_level": None,
    "attack_priority": None,
    "chain_length": 0,
    "signal_count": 0,
    "provider": None,
    "component": None,
    "version": None,
    "source": "",
    "remediation": "",
    "risk_scorecard": {},
    "impact_area": "Web Application",
    "chain_metadata": {
        "is_chain_root": False,
        "related_findings": [],
        "attack_path_summary": "",
        "pivot_point": None
    },
}


SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "warn": "medium",
    "warning": "medium",
}

CONFIDENCE_MAP = {"high": "high", "medium": "medium", "low": "low"}


def _to_evidence_string(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str)
    except Exception:
        return str(value)


def merge_signal_ids(*groups):
    out = []
    for group in groups:
        if group is None:
            continue
        if isinstance(group, list):
            items = group
        else:
            items = [group]
        for sid in items:
            if sid is None:
                continue
            if sid not in out:
                out.append(sid)
    return out


def deep_merge_metadata(base, overlay):
    base = base if isinstance(base, dict) else {}
    overlay = overlay if isinstance(overlay, dict) else {}
    merged = dict(base)
    for key, value in overlay.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = deep_merge_metadata(merged[key], value)
        elif value not in (None, ""):
            merged[key] = value
    return merged


def merge_field_sources(base, overlay):
    """Merge metadata.field_sources deterministically without clobbering existing attribution."""
    out = dict(base) if isinstance(base, dict) else {}
    incoming = overlay if isinstance(overlay, dict) else {}
    for field_name, source_name in incoming.items():
        if not field_name:
            continue
        if not source_name:
            continue
        if field_name not in out:
            out[field_name] = str(source_name)
    return out


def merge_score_factors(base, overlay):
    """Merge score factors with deterministic numeric overwrite from newer calculation."""
    out = dict(base) if isinstance(base, dict) else {}
    incoming = overlay if isinstance(overlay, dict) else {}
    for key, value in incoming.items():
        if value is None:
            continue
        out[key] = value
    return out


def merge_chain_explanation(base, overlay):
    """Merge chain explanation while preserving list uniqueness and deterministic order."""
    current = dict(base) if isinstance(base, dict) else {}
    incoming = overlay if isinstance(overlay, dict) else {}

    for key, value in incoming.items():
        if key in {"source_categories", "related_signal_ids", "related_finding_ids"}:
            merged_list = []
            existing_items = current.get(key) if isinstance(current.get(key), list) else []
            new_items = value if isinstance(value, list) else []
            for item in [*existing_items, *new_items]:
                if item is None:
                    continue
                if item not in merged_list:
                    merged_list.append(item)
            current[key] = merged_list
            continue
        if value not in (None, ""):
            current[key] = value
    return current


def generate_stable_id(finding):
    """
    Generate a deterministic, tool-agnostic stable ID for deduplication.
    V12: Normalizes endpoints (hostname/path) and includes tactical parameters.
    """
    import hashlib
    from urllib.parse import urlparse

    title = str(finding.get("title") or "unknown")
    endpoint_seed = finding.get("endpoint") or finding.get("target") or finding.get("url") or ""
    parameter = str(finding.get("parameter") or "")
    payload = str(finding.get("payload") or "")
    severity = str(finding.get("severity") or "info").lower()
    tool = str(finding.get("tool_source") or finding.get("tool") or "unknown")

    try:
        parsed = urlparse(str(endpoint_seed))
        # Normalize: ignore scheme and standard ports
        host = parsed.hostname or parsed.netloc.split(':')[0]
        # Ignore port if it's 80/443
        if parsed.port in [80, 443]:
            host = host.split(':')[0]
        
        endpoint_fingerprint = f"{host}{parsed.path}?{parsed.query}"
    except Exception:
        endpoint_fingerprint = str(endpoint_seed)

    fp_seed = (
        f"{title}|{endpoint_fingerprint}|{parameter}|{payload}|{severity}|{tool}"
    )

    return hashlib.sha256(fp_seed.encode()).hexdigest()



def normalize_finding_shape(payload, *, source=None):
    raw = payload if isinstance(payload, dict) else {}
    normalized = dict(CANONICAL_FINDING_DEFAULTS)
    normalized.update(raw)

    normalized["metadata"] = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
    normalized["signal_ids"] = merge_signal_ids(raw.get("signal_ids"))
    normalized["severity"] = SEVERITY_MAP.get(
        str(normalized.get("severity", "info")).lower(),
        "info",
    )
    normalized["confidence"] = CONFIDENCE_MAP.get(
        str(normalized.get("confidence", "medium")).lower(),
        "medium",
    )

    normalized["tool_source"] = (
        raw.get("tool_source")
        or raw.get("tool")
        or normalized.get("tool_source")
        or normalized.get("tool")
        or "unknown"
    )
    normalized["tool"] = normalized.get("tool") or normalized["tool_source"]
    normalized["module"] = normalized.get("module") or normalized["tool_source"]
    normalized["source"] = normalized.get("source") or source or normalized["tool_source"]

    normalized["target"] = normalized.get("target") or raw.get("url", "")
    normalized["endpoint"] = normalized.get("endpoint") or normalized.get("target")
    normalized["parameter"] = normalized.get("parameter") or raw.get("param", "")
    normalized["payload"] = normalized.get("payload") or raw.get("poison", "")

    evidence = normalized.get("evidence") or raw.get("evidence") or {}
    normalized["evidence"] = _to_evidence_string(evidence)

    normalized["raw_output"] = (
        normalized.get("raw_output")
        or normalized.get("response")
        or normalized.get("description")
        or normalized["evidence"]
    )
    normalized["reproduction"] = normalized.get("reproduction") or normalized.get("repro_command")
    normalized["created_at"] = normalized.get("created_at") or datetime.utcnow().isoformat() + "Z"

    metadata = deep_merge_metadata(
        normalized["metadata"],
        {
            "source": normalized["source"],
            "confidence": normalized["confidence"],
        },
    )
    metadata["field_sources"] = merge_field_sources(
        metadata.get("field_sources"),
        {
            "endpoint": metadata.get("source") if normalized.get("endpoint") else None,
            "parameter": metadata.get("source") if normalized.get("parameter") else None,
            "payload": metadata.get("source") if normalized.get("payload") else None,
            "evidence": metadata.get("source") if normalized.get("evidence") else None,
            "raw_output": metadata.get("source") if normalized.get("raw_output") else None,
            "provider": metadata.get("source") if (normalized.get("provider") or metadata.get("provider")) else None,
            "component": metadata.get("source") if (normalized.get("component") or metadata.get("component")) else None,
            "version": metadata.get("source") if (normalized.get("version") or metadata.get("version")) else None,
        },
    )

    normalized["signal_count"] = len(normalized["signal_ids"])
    normalized["chain_length"] = (
        len(metadata.get("chain", []))
        if isinstance(metadata.get("chain"), list)
        else int(normalized.get("chain_length") or 0)
    )

    for key in [
        "exploit_score",
        "risk_level",
        "attack_priority",
        "provider",
        "component",
        "version",
        "remediation",
        "risk_scorecard",
    ]:
        if normalized.get(key) is None and key in metadata:
            normalized[key] = metadata.get(key)

    metadata.setdefault("signal_count", normalized["signal_count"])
    metadata.setdefault("chain_length", normalized["chain_length"])
    normalized["metadata"] = metadata

    if not normalized.get("id_stable"):
        normalized["id_stable"] = generate_stable_id(normalized)
    normalized["id"] = normalized.get("id") or normalized["id_stable"]

    return normalized