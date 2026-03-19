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
        "pivot_point": None,
    },
    "result_state": "observation",
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

RESULT_STATE_MAP = {
    "observation": "observation",
    "observed": "observation",
    "heuristic": "heuristic",
    "signal": "heuristic",
    "correlation": "correlation",
    "correlated": "correlation",
    "validation": "validation",
    "validated": "validation",
    "confirmed": "confirmed",
    "operator_confirmed": "confirmed",
    "rejected": "rejected",
    "invalidated": "rejected",
    "operator_rejected": "rejected",
}

VALIDATION_STATUS_MAP = {
    "success": "success",
    "succeeded": "success",
    "failed": "failed",
    "failure": "failed",
    "error": "failed",
    "uncertain": "uncertain",
    "unknown": "uncertain",
    "not_run": "not_run",
    "not-executed": "not_run",
}

INVALID_TEXT_MARKERS = {"", "none", "n/a", "na", "null", "todo", "tbd", "manual", "ui"}


def _clean_text(value):
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    return value.strip()


def _normalize_command_value(*candidates):
    for candidate in candidates:
        normalized = _clean_text(candidate)
        if not normalized:
            continue
        if normalized.lower() in INVALID_TEXT_MARKERS:
            continue
        return normalized
    return ""


def _normalize_locator_value(*candidates):
    for candidate in candidates:
        normalized = _clean_text(candidate)
        if not normalized:
            continue
        if normalized.lower() in INVALID_TEXT_MARKERS:
            continue
        # Reject synthetic internal port references — not real network locators
        if normalized.lower().startswith("port:"):
            continue
        return normalized
    return ""


def _has_meaningful_artifact(value):
    text_value = _clean_text(value)
    if not text_value:
        return False
    if text_value.lower() in INVALID_TEXT_MARKERS:
        return False
    if text_value in {"{}", "[]", '""'}:
        return False
    return True


def _normalize_arguments(value):
    if isinstance(value, dict):
        return {k: v for k, v in value.items() if k not in (None, "")}
    if isinstance(value, list):
        filtered = [item for item in value if item not in (None, "")]
        return {"argv": filtered} if filtered else {}
    if isinstance(value, str) and value.strip():
        return {"raw": value.strip()}
    return {}


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
    title = str(finding.get("title") or "unknown")
    endpoint_seed = finding.get("endpoint") or finding.get("target") or finding.get("url") or ""
    parameter = str(finding.get("parameter") or "")
    payload = str(finding.get("payload") or "")
    severity = str(finding.get("severity") or "info").lower()
    tool = str(finding.get("tool_source") or finding.get("tool") or "unknown")

    try:
        parsed = urlparse(str(endpoint_seed))
        host = parsed.hostname or parsed.netloc.split(":")[0]
        if parsed.port in [80, 443]:
            host = host.split(":")[0]
        endpoint_fingerprint = f"{host}{parsed.path}?{parsed.query}"
    except Exception:
        endpoint_fingerprint = str(endpoint_seed)

    fp_seed = f"{title}|{endpoint_fingerprint}|{parameter}|{payload}|{severity}|{tool}"
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

    raw_result_state = (
        raw.get("result_state")
        or normalized.get("result_state")
        or raw.get("status")
        or raw.get("state")
    )
    normalized["result_state"] = RESULT_STATE_MAP.get(
        str(raw_result_state or "observation").lower(),
        "observation",
    )

    metadata = deep_merge_metadata(
        normalized["metadata"],
        {
            "source": normalized["source"],
            "confidence": normalized["confidence"],
            "result_state": normalized["result_state"],
        },
    )

    raw_validation = raw.get("validation") if isinstance(raw.get("validation"), dict) else {}
    metadata_validation = metadata.get("validation") if isinstance(metadata.get("validation"), dict) else {}
    validation_status_seed = (
        raw_validation.get("status")
        or metadata_validation.get("status")
        or raw.get("validation_status")
    )
    normalized_validation_status = VALIDATION_STATUS_MAP.get(
        str(validation_status_seed or "not_run").lower(),
        "not_run",
    )

    metadata_validation_command = _normalize_command_value(
        raw_validation.get("command"),
        metadata_validation.get("command"),
        _normalize_command_value(normalized.get("repro_command"), normalized.get("reproduction")),
        normalized.get("reproduction"),
    )
    metadata["validation"] = {
        "status": normalized_validation_status,
        "target": _clean_text(
            _normalize_locator_value(
                raw_validation.get("target"),
                metadata_validation.get("target"),
                normalized.get("endpoint"),
                normalized.get("target"),
            )
        ),
        "command": metadata_validation_command,
        "expected": _clean_text(raw_validation.get("expected") or metadata_validation.get("expected")),
        "success_criteria": _clean_text(
            raw_validation.get("success_criteria") or metadata_validation.get("success_criteria")
        ),
        "failure_criteria": _clean_text(
            raw_validation.get("failure_criteria") or metadata_validation.get("failure_criteria")
        ),
        "uncertainty_criteria": _clean_text(
            raw_validation.get("uncertainty_criteria") or metadata_validation.get("uncertainty_criteria")
        ),
        "artifact": _clean_text(raw_validation.get("artifact") or metadata_validation.get("artifact")),
    }

    reproducibility = metadata.get("reproducibility") if isinstance(metadata.get("reproducibility"), dict) else {}
    metadata["reproducibility"] = {
        "command": _normalize_command_value(
            reproducibility.get("command"),
            _normalize_command_value(normalized.get("repro_command"), normalized.get("reproduction")),
            normalized.get("reproduction"),
            metadata_validation_command,
        ),
        "url": _normalize_locator_value(
            reproducibility.get("url"),
            normalized.get("endpoint"),
            normalized.get("target"),
        ),
        "arguments": _normalize_arguments(reproducibility.get("arguments") or raw.get("arguments")),
        "request_excerpt": _clean_text(reproducibility.get("request_excerpt") or normalized.get("request")),
        "response_excerpt": _clean_text(reproducibility.get("response_excerpt") or normalized.get("response")),
    }

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
            "result_state": metadata.get("source") if normalized.get("result_state") else None,
            "repro_command": metadata.get("source") if metadata.get("reproducibility", {}).get("command") else None,
            "request": metadata.get("source") if metadata.get("reproducibility", {}).get("request_excerpt") else None,
            "response": metadata.get("source") if metadata.get("reproducibility", {}).get("response_excerpt") else None,
        },
    )

    evidence_value = str(normalized.get("evidence") or "").strip()
    validation_artifact = str(metadata["validation"].get("artifact") or "").strip()
    has_proof_artifact = any(
        [
            _has_meaningful_artifact(evidence_value),
            _has_meaningful_artifact(normalized.get("response")),
            _normalize_command_value(normalized.get("repro_command"), normalized.get("reproduction")),
            _has_meaningful_artifact(validation_artifact),
        ]
    )
    if normalized["result_state"] == "confirmed" and not has_proof_artifact:
        normalized["result_state"] = "validation"
        metadata["result_state"] = "validation"
        metadata["validation"]["status"] = "uncertain"
        metadata["validation"]["downgrade_reason"] = "confirmed_without_artifact"

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
