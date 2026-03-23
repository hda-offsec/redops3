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
    "command": "",
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
    "impact": "",
    "remediation": "",
    "references": [],
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

CONFIDENCE_MAP = {"certain": "high", "high": "high", "medium": "medium", "low": "low"}

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
GENERIC_TITLES = {"", "finding", "untitled finding", "unknown finding", "candidate finding"}
RECOMMENDATION_CATEGORIES = {"attack_plan", "next_step", "mission_prep", "objective_path"}
SUSPICION_RESULT_STATES = {"heuristic", "correlation", "validation"}
CONFIRMED_RESULT_STATES = {"confirmed"}
VISIBLE_TRUTH_VALUES = (
    "observation",
    "suspicion",
    "recommendation",
    "confirmed_vulnerability",
)


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


def _safe_lower(value):
    return _clean_text(value).lower()


def _looks_like_real_command(value):
    command = _clean_text(value)
    if not command:
        return False
    lowered = command.lower()
    if lowered in INVALID_TEXT_MARKERS:
        return False
    first_line = next((line.strip() for line in command.splitlines() if line.strip()), "")
    if not first_line:
        return False
    for prompt in ("$ ", "# ", "> "):
        if first_line.startswith(prompt):
            first_line = first_line[len(prompt):].lstrip()
            break
    if not first_line:
        return False
    token = first_line.split()[0].lower()
    if token in {
        "aws", "bash", "burp", "curl", "dalfox", "dirsearch", "docker", "ffuf",
        "gobuster", "httpx", "jq", "katana", "kubectl", "nc", "nmap", "node",
        "nuclei", "openssl", "php", "powershell", "python", "python3", "ruby",
        "sh", "sqlmap", "ssh", "wget", "wpscan", "zsh",
    }:
        return True
    return token.startswith(("./", "/", "~/"))


def _is_meaningful_proof_artifact(value):
    if isinstance(value, (dict, list)):
        if not value:
            return False
        try:
            serialized = json.dumps(value, default=str, sort_keys=True)
        except Exception:
            serialized = str(value)
        return _is_meaningful_proof_artifact(serialized)

    text_value = _clean_text(value)
    if not _has_meaningful_artifact(text_value):
        return False

    lowered = text_value.lower()
    if len(text_value) < 12 and not any(char in text_value for char in "{}[]:=/\\"):
        return False

    weak_markers = (
        "possible issue",
        "potential issue",
        "appears vulnerable",
        "likely vulnerable",
        "manual verification",
        "needs validation",
        "interesting finding",
        "heuristic",
        "correlation",
        "suspected",
    )
    if any(marker in lowered for marker in weak_markers) and not any(
        token in text_value for token in ("HTTP/", "{", "}", "[", "]", ":", "/", "=", "<", ">")
    ):
        return False

    proof_tokens = (
        "http/", "get ", "post ", "put ", "delete ", "trace ", "host:", "cookie:",
        "set-cookie", "location:", "content-type", "{", "}", "[", "]", ":", "/",
        "error", "stack trace", "exception", "<html", "select ", "union ", "token",
        "jwt", "eyj", "aws", "xml", "json", "status", "response",
    )
    return any(token in lowered for token in proof_tokens) or len(text_value) >= 48


def collect_finding_quality_signals(payload):
    finding = payload if isinstance(payload, dict) else {}
    metadata = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    validation = metadata.get("validation") if isinstance(metadata.get("validation"), dict) else {}
    reproducibility = metadata.get("reproducibility") if isinstance(metadata.get("reproducibility"), dict) else {}

    validation_status = VALIDATION_STATUS_MAP.get(
        _safe_lower(validation.get("status") or metadata.get("validation_status") or finding.get("validation_status") or "not_run"),
        "not_run",
    )
    result_state = RESULT_STATE_MAP.get(
        _safe_lower(
            validation.get("result_state")
            or finding.get("result_state")
            or metadata.get("result_state")
            or finding.get("state")
            or "observation"
        ),
        "observation",
    )
    endpoint = _normalize_locator_value(
        validation.get("target"),
        reproducibility.get("url"),
        finding.get("endpoint"),
        finding.get("target"),
        finding.get("url"),
    )
    command = _normalize_command_value(
        validation.get("command"),
        reproducibility.get("command"),
        finding.get("repro_command"),
        finding.get("command"),
        finding.get("reproduction"),
    )
    title = _clean_text(finding.get("title"))
    description = _clean_text(finding.get("description"))

    artifact_candidates = [
        finding.get("evidence"),
        finding.get("request"),
        finding.get("response"),
        finding.get("raw_output"),
        validation.get("artifact"),
        reproducibility.get("request_excerpt"),
        reproducibility.get("response_excerpt"),
    ]
    proof_artifacts = [candidate for candidate in artifact_candidates if _is_meaningful_proof_artifact(candidate)]

    corroborating_signals = merge_signal_ids(
        finding.get("signal_ids"),
        metadata.get("signal_ids"),
        metadata.get("supporting_signal_ids"),
    )
    score = 0
    if endpoint:
        score += 1
    if _looks_like_real_command(command):
        score += 1
    if proof_artifacts:
        score += 1
    if len(proof_artifacts) >= 2:
        score += 1
    if validation_status == "success":
        score += 2
    elif validation_status == "uncertain":
        score += 1
    if title.lower() not in GENERIC_TITLES:
        score += 1
    if len(description) >= 24:
        score += 1
    if corroborating_signals:
        score += 1
    if result_state == "confirmed":
        score += 1

    return {
        "validation_status": validation_status,
        "result_state": result_state,
        "endpoint": endpoint,
        "command": command,
        "title": title,
        "description": description,
        "proof_artifact_count": len(proof_artifacts),
        "proof_artifacts_present": bool(proof_artifacts),
        "has_request_response": any(
            _is_meaningful_proof_artifact(candidate)
            for candidate in (
                finding.get("request"),
                finding.get("response"),
                reproducibility.get("request_excerpt"),
                reproducibility.get("response_excerpt"),
            )
        ),
        "has_corroborating_signals": bool(corroborating_signals),
        "signal_count": len(corroborating_signals),
        "has_endpoint": bool(endpoint),
        "has_command": _looks_like_real_command(command),
        "has_substantive_description": len(description) >= 24,
        "has_non_generic_title": title.lower() not in GENERIC_TITLES,
        "quality_score": score,
    }


def classify_visible_truth(payload):
    finding = payload if isinstance(payload, dict) else {}
    metadata = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    category = _safe_lower(finding.get("category"))
    title = _safe_lower(finding.get("title"))
    family = _safe_lower(finding.get("family"))

    if (
        category in RECOMMENDATION_CATEGORIES
        or title.startswith("recommendation:")
        or family
        or "internal_priority" in finding
    ) and finding.get("reason") is not None:
        return "recommendation"

    quality = collect_finding_quality_signals(finding)
    if (
        quality["result_state"] in CONFIRMED_RESULT_STATES
        and quality["validation_status"] == "success"
        and quality["has_endpoint"]
        and quality["has_command"]
        and quality["proof_artifact_count"] >= 1
        and quality["has_request_response"]
        and quality["has_non_generic_title"]
        and quality["quality_score"] >= 6
    ):
        return "confirmed_vulnerability"

    if (
        quality["result_state"] in SUSPICION_RESULT_STATES
        or quality["validation_status"] in {"failed", "uncertain"}
        or category in {"attack_chain", "attack_path"}
        or _safe_lower(metadata.get("validation_state")) in {"heuristic", "correlation", "validation"}
    ):
        return "suspicion"

    return "observation"


def apply_finding_quality_gates(payload):
    finding = dict(payload) if isinstance(payload, dict) else {}
    metadata = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
    validation = metadata.get("validation") if isinstance(metadata.get("validation"), dict) else {}
    quality = collect_finding_quality_signals({"metadata": metadata, **finding})

    severity = _safe_lower(finding.get("severity") or "info") or "info"
    result_state = quality["result_state"]
    downgrade_reasons = []

    strong_high_gate = (
        quality["has_endpoint"]
        and quality["has_command"]
        and quality["proof_artifact_count"] >= 1
        and quality["has_non_generic_title"]
        and quality["has_substantive_description"]
        and quality["quality_score"] >= 5
    )
    strong_critical_gate = strong_high_gate and quality["validation_status"] == "success" and quality["proof_artifact_count"] >= 2
    strong_confirmed_gate = (
        quality["validation_status"] == "success"
        and quality["has_endpoint"]
        and quality["has_command"]
        and quality["proof_artifact_count"] >= 1
        and quality["has_request_response"]
        and quality["quality_score"] >= 6
    )

    if severity == "critical" and not strong_critical_gate:
        severity = "high" if strong_high_gate else "medium"
        downgrade_reasons.append("critical_requires_validated_multi_artifact_proof")
    elif severity == "high" and not strong_high_gate:
        severity = "medium"
        downgrade_reasons.append("high_requires_endpoint_command_and_proof")

    if result_state == "confirmed" and not strong_confirmed_gate:
        result_state = "validation" if quality["proof_artifacts_present"] or quality["has_command"] else "correlation"
        validation["status"] = "uncertain" if quality["validation_status"] != "success" else quality["validation_status"]
        downgrade_reasons.append("confirmed_requires_validated_reproducible_proof")

    metadata["validation"] = validation
    metadata["result_state"] = result_state
    metadata["validation_state"] = result_state
    metadata["proof_summary"] = {
        "quality_score": quality["quality_score"],
        "proof_artifact_count": quality["proof_artifact_count"],
        "has_endpoint": quality["has_endpoint"],
        "has_command": quality["has_command"],
        "has_request_response": quality["has_request_response"],
        "has_corroborating_signals": quality["has_corroborating_signals"],
    }
    if downgrade_reasons:
        validation["downgrade_reason"] = downgrade_reasons[-1]
        metadata["quality_gate"] = {
            "downgraded": True,
            "reasons": downgrade_reasons,
        }
    elif isinstance(metadata.get("quality_gate"), dict):
        metadata["quality_gate"]["downgraded"] = bool(metadata["quality_gate"].get("downgraded"))

    finding["severity"] = severity
    finding["result_state"] = result_state
    finding["metadata"] = metadata
    metadata["visible_truth"] = classify_visible_truth(finding)
    return finding


def _normalize_arguments(value):
    if isinstance(value, dict):
        return {k: v for k, v in value.items() if k not in (None, "")}
    if isinstance(value, list):
        filtered = [item for item in value if item not in (None, "")]
        return {"argv": filtered} if filtered else {}
    if isinstance(value, str) and value.strip():
        return {"raw": value.strip()}
    return {}


def _normalize_references(value):
    if isinstance(value, list):
        out = []
        for item in value:
            text = _clean_text(item)
            if not text:
                continue
            if text not in out:
                out.append(text)
        return out
    if isinstance(value, str):
        text = _clean_text(value)
        return [text] if text else []
    return []


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
    normalized["command"] = _normalize_command_value(
        normalized.get("command"),
        normalized.get("repro_command"),
        normalized.get("reproduction"),
    )
    normalized["impact"] = _clean_text(
        normalized.get("impact")
        or normalized.get("impact_area")
        or raw.get("impact")
        or raw.get("impact_area")
    )
    normalized["references"] = _normalize_references(
        normalized.get("references")
        or raw.get("references")
        or (normalized.get("metadata") or {}).get("references")
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
    if normalized["command"] and not metadata["reproducibility"]["command"]:
        metadata["reproducibility"]["command"] = normalized["command"]

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

    normalized["signal_count"] = len(normalized["signal_ids"])
    if isinstance(metadata.get("chain"), list):
        normalized["chain_length"] = len(metadata.get("chain", []))
    else:
        try:
            normalized["chain_length"] = int(
                metadata.get("chain_length")
                or normalized.get("chain_length")
                or 0
            )
        except (TypeError, ValueError):
            normalized["chain_length"] = int(normalized.get("chain_length") or 0)

    for key in [
        "exploit_score",
        "risk_level",
        "attack_priority",
        "provider",
        "component",
        "version",
        "impact",
        "remediation",
        "risk_scorecard",
        "references",
    ]:
        if normalized.get(key) is None and key in metadata:
            normalized[key] = metadata.get(key)

    if not normalized["command"]:
        normalized["command"] = _normalize_command_value(
            metadata.get("validation", {}).get("command") if isinstance(metadata.get("validation"), dict) else "",
            metadata.get("reproducibility", {}).get("command") if isinstance(metadata.get("reproducibility"), dict) else "",
            normalized.get("repro_command"),
            normalized.get("reproduction"),
        )
    if not normalized["references"]:
        normalized["references"] = _normalize_references(metadata.get("references"))

    metadata.setdefault("signal_count", normalized["signal_count"])
    metadata.setdefault("chain_length", normalized["chain_length"])
    normalized["metadata"] = metadata
    normalized = apply_finding_quality_gates(normalized)

    if not normalized.get("id_stable"):
        normalized["id_stable"] = generate_stable_id(normalized)
    normalized["id"] = normalized.get("id") or normalized["id_stable"]

    return normalized
