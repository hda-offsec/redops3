"""Mirrored Findings UI contract for server-rendered payloads.

This module intentionally mirrors `ui/web/static/js/findings_contract.js`.
Both sides must keep the same:
- canonical `_ui` fields,
- command and URL priority rules,
- validation/result-state mapping,
- `searchText` token order and deduplication rules.

The backend enriches payloads with `_ui` for Jinja and API responses.
The frontend mirrors the same logic for live websocket findings.
"""

import json
import re

from scan_engine.helpers.finding_schema import (
    INVALID_TEXT_MARKERS,
    RESULT_STATE_MAP,
    VALIDATION_STATUS_MAP,
)


EXPLICIT_COMMAND_PREFIXES = (
    "aws",
    "bash",
    "cmd",
    "curl",
    "dalfox",
    "dig",
    "dirsearch",
    "docker",
    "feroxbuster",
    "ffuf",
    "ghauri",
    "gobuster",
    "httpx",
    "java",
    "jq",
    "katana",
    "kubectl",
    "nc",
    "nikto",
    "nmap",
    "node",
    "nslookup",
    "nuclei",
    "openssl",
    "perl",
    "php",
    "powershell",
    "pwsh",
    "python",
    "python3",
    "ruby",
    "sh",
    "sqlmap",
    "ssh",
    "ssh-audit",
    "telnet",
    "wget",
    "whois",
    "wpscan",
    "zsh",
)
COMMAND_SCRIPT_RE = re.compile(r"^[A-Za-z0-9_.-]+\.(?:pl|ps1|py|rb|sh)$")
RESULT_STATE_ALIASES = {
    **RESULT_STATE_MAP,
    "confirmed_active": "confirmed",
}
VALIDATED_RESULT_STATES = {"validation", "confirmed"}
CANONICAL_UI_FIELDS = (
    "validationStatus",
    "resultState",
    "primaryCommand",
    "primaryUrl",
    "provider",
    "component",
    "version",
    "portState",
    "hasEvidence",
    "isValidated",
    "searchText",
)
SEARCH_TEXT_FIELD_SOURCES = (
    "title",
    "tool_source",
    "tool",
    "source",
    "category",
    "primary_url",
    "target",
    "provider",
    "component",
    "version",
    "validation_status",
    "result_state",
    "validated_token",
    "parameter",
    "port_state",
)
OBSERVED_VERSION_FIELD_SOURCES = (
    "version",
    "metadata.version",
    "metadata.service_version",
    "metadata.detected_version",
    "metadata.component_version",
)
DETAIL_COMMAND_BLOCK_SOURCES = (
    "validation.command",
    "reproducibility.command",
    "repro_command",
)
DETAIL_EVIDENCE_BLOCK_SOURCES = (
    "validation.artifact",
    "request",
    "response",
    "raw_output",
    "evidence",
)


def _as_dict(value):
    return value if isinstance(value, dict) else {}


def _clean_text(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _serialize_detail_value(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, default=str, indent=2, sort_keys=True)
        except Exception:
            return str(value)
    text = _clean_text(value)
    if text[:1] in "[{" and text[-1:] in "]}":
        try:
            parsed = json.loads(text)
        except Exception:
            return text
        if isinstance(parsed, (dict, list)):
            try:
                return json.dumps(parsed, default=str, indent=2, sort_keys=True)
            except Exception:
                return text
    return text


def _is_meaningful_text(value):
    if value is None:
        return False
    if isinstance(value, dict):
        return bool(value)
    if isinstance(value, list):
        return any(item not in (None, "") for item in value)
    normalized = _clean_text(value)
    if not normalized:
        return False
    lowered = normalized.lower()
    if lowered in INVALID_TEXT_MARKERS:
        return False
    if normalized in {"{}", "[]", '""'}:
        return False
    return True


def _is_meaningful_locator(value):
    if not _is_meaningful_text(value):
        return False
    return not _clean_text(value).lower().startswith("port:")


def _first_meaningful(*values, locator=False):
    check = _is_meaningful_locator if locator else _is_meaningful_text
    for value in values:
        if check(value):
            return _clean_text(value)
    return ""


def _normalize_validation_status(finding):
    metadata = _as_dict(finding.get("metadata"))
    validation = _as_dict(metadata.get("validation"))
    for candidate in (
        validation.get("status"),
        metadata.get("validation_status"),
        finding.get("validation_status"),
    ):
        lowered = _clean_text(candidate).lower()
        if not lowered:
            continue
        mapped = VALIDATION_STATUS_MAP.get(lowered)
        if mapped:
            return mapped
    return "not_run"


def _normalize_result_state(finding):
    metadata = _as_dict(finding.get("metadata"))
    validation = _as_dict(metadata.get("validation"))
    for candidate in (
        validation.get("result_state"),
        finding.get("result_state"),
        metadata.get("result_state"),
        validation.get("status"),
        metadata.get("validation_status"),
        finding.get("validation_status"),
    ):
        lowered = _clean_text(candidate).lower()
        if not lowered:
            continue
        mapped = RESULT_STATE_ALIASES.get(lowered)
        if mapped:
            return mapped
    return "observation"


def _extract_command_candidate(value):
    command = _clean_text(value)
    if not _is_meaningful_text(command):
        return ""
    return command


def _is_safe_legacy_command(value):
    candidate = _clean_text(value)
    if not _is_meaningful_text(candidate):
        return False
    first_line = ""
    for line in candidate.splitlines():
        stripped = line.strip()
        if stripped:
            first_line = stripped
            break
    if not first_line:
        return False
    for prompt in ("$ ", "# ", "> "):
        if first_line.startswith(prompt):
            first_line = first_line[len(prompt):].lstrip()
            break
    if not first_line:
        return False
    token = first_line.split()[0].lower()
    if token in EXPLICIT_COMMAND_PREFIXES:
        return True
    if token.startswith(("./", "/", "~/")):
        return True
    return bool(COMMAND_SCRIPT_RE.match(token))


def get_finding_primary_command(finding):
    metadata = _as_dict(finding.get("metadata"))
    validation = _as_dict(metadata.get("validation"))
    reproducibility = _as_dict(metadata.get("reproducibility"))
    for candidate in (
        validation.get("command"),
        reproducibility.get("command"),
        finding.get("repro_command"),
    ):
        command = _extract_command_candidate(candidate)
        if command:
            return command
    fallback = _clean_text(finding.get("reproduction"))
    return fallback if _is_safe_legacy_command(fallback) else ""


def get_finding_primary_url(finding):
    metadata = _as_dict(finding.get("metadata"))
    validation = _as_dict(metadata.get("validation"))
    reproducibility = _as_dict(metadata.get("reproducibility"))
    return _first_meaningful(
        validation.get("target"),
        reproducibility.get("url"),
        finding.get("endpoint"),
        finding.get("target"),
        locator=True,
    )


def get_finding_version(finding):
    metadata = _as_dict(finding.get("metadata"))
    return _first_meaningful(
        finding.get("version"),
        metadata.get("version"),
        metadata.get("service_version"),
        metadata.get("detected_version"),
        metadata.get("component_version"),
    )


def get_finding_observed_versions(finding):
    metadata = _as_dict(finding.get("metadata"))
    versions = []
    seen = set()
    for candidate in (
        finding.get("version"),
        metadata.get("version"),
        metadata.get("service_version"),
        metadata.get("detected_version"),
        metadata.get("component_version"),
    ):
        value = _serialize_detail_value(candidate)
        if not _is_meaningful_text(value):
            continue
        if value in seen:
            continue
        seen.add(value)
        versions.append(value)
    extra_versions = metadata.get("versions")
    if isinstance(extra_versions, list):
        for candidate in extra_versions:
            value = _serialize_detail_value(candidate)
            if not _is_meaningful_text(value):
                continue
            if value in seen:
                continue
            seen.add(value)
            versions.append(value)
    return versions


def get_finding_references(finding):
    metadata = _as_dict(finding.get("metadata"))
    references = []
    seen = set()
    for source in (finding.get("references"), metadata.get("references")):
        items = source if isinstance(source, list) else [source]
        for item in items:
            text = _clean_text(item)
            if not _is_meaningful_text(text):
                continue
            if text in seen:
                continue
            seen.add(text)
            references.append(text)
    return references


def get_finding_command_blocks(finding):
    metadata = _as_dict(finding.get("metadata"))
    validation = _as_dict(metadata.get("validation"))
    reproducibility = _as_dict(metadata.get("reproducibility"))
    blocks = []
    seen = set()

    def append_block(key, label, value):
        serialized = _serialize_detail_value(value)
        if not _is_meaningful_text(serialized):
            return
        if serialized in seen:
            return
        seen.add(serialized)
        blocks.append(
            {
                "key": key,
                "label": label,
                "kind": "command",
                "value": serialized,
            }
        )

    append_block("validation_command", "Validation command", validation.get("command"))
    append_block("reproducibility_command", "Reproducibility command", reproducibility.get("command"))
    append_block("stored_repro_command", "Stored repro command", finding.get("repro_command"))
    return blocks


def get_finding_validation_guidance(finding):
    guidance = _clean_text(finding.get("reproduction"))
    if not _is_meaningful_text(guidance):
        return ""
    primary_command = get_finding_primary_command(finding)
    if guidance == primary_command:
        return ""
    return "" if _is_safe_legacy_command(guidance) else guidance


def get_finding_artifacts(finding):
    metadata = _as_dict(finding.get("metadata"))
    artifacts = []
    screenshot_path = _clean_text(finding.get("screenshot_path"))
    if _is_meaningful_text(screenshot_path):
        artifacts.append(
            {
                "label": "Screenshot",
                "kind": "image",
                "value": screenshot_path,
            }
        )

    raw_artifacts = metadata.get("artifacts")
    if isinstance(raw_artifacts, list):
        for index, item in enumerate(raw_artifacts, start=1):
            serialized = _serialize_detail_value(item)
            if not _is_meaningful_text(serialized):
                continue
            artifacts.append(
                {
                    "label": f"Artifact {index}",
                    "kind": "text",
                    "value": serialized,
                }
            )
    elif _is_meaningful_text(raw_artifacts):
        artifacts.append(
            {
                "label": "Artifact",
                "kind": "text",
                "value": _serialize_detail_value(raw_artifacts),
            }
        )
    return artifacts


def build_finding_technical_context(finding):
    normalized = attach_finding_ui_contract(finding)
    metadata = _as_dict(normalized.get("metadata"))
    reproducibility = _as_dict(metadata.get("reproducibility"))
    ui = _as_dict(normalized.get("_ui"))
    rows = []

    def append_row(label, value):
        serialized = _serialize_detail_value(value)
        if not _is_meaningful_text(serialized):
            return
        rows.append({"label": label, "value": serialized})

    tool_value = _first_meaningful(normalized.get("tool_source"), normalized.get("tool"))
    source_value = _clean_text(normalized.get("source"))
    module_value = _clean_text(normalized.get("module"))

    append_row("Tool", tool_value)
    if source_value and source_value != tool_value:
        append_row("Source", source_value)
    if module_value and module_value not in {tool_value, source_value}:
        append_row("Module", module_value)
    append_row("Category", normalized.get("category"))
    append_row("Parameter", normalized.get("parameter"))
    append_row("Provider", ui.get("provider"))
    append_row("Component", ui.get("component"))
    append_row("Port state", ui.get("portState"))
    append_row("Validation status", ui.get("validationStatus"))
    append_row("Result state", ui.get("resultState"))
    append_row(
        "Impact area",
        normalized.get("impact_area") or metadata.get("impact_area"),
    )
    append_row("Arguments", reproducibility.get("arguments"))
    return rows


def build_finding_evidence_blocks(finding):
    normalized = attach_finding_ui_contract(finding)
    metadata = _as_dict(normalized.get("metadata"))
    validation = _as_dict(metadata.get("validation"))
    reproducibility = _as_dict(metadata.get("reproducibility"))
    blocks = []
    seen = set()

    def append_block(key, label, kind, value):
        serialized = _serialize_detail_value(value)
        if not _is_meaningful_text(serialized):
            return
        if serialized in seen:
            return
        seen.add(serialized)
        blocks.append(
            {
                "key": key,
                "label": label,
                "kind": kind,
                "value": serialized,
            }
        )

    append_block("validation_artifact", "Validation artifact", "proof", validation.get("artifact"))
    append_block(
        "request",
        "Request excerpt",
        "request",
        reproducibility.get("request_excerpt") or normalized.get("request"),
    )
    append_block(
        "response",
        "Response excerpt",
        "response",
        reproducibility.get("response_excerpt") or normalized.get("response"),
    )
    append_block("raw_output", "Raw output", "raw_output", normalized.get("raw_output"))
    append_block("evidence", "Evidence", "evidence", normalized.get("evidence"))
    return blocks


def build_finding_detail_contract(finding):
    normalized = attach_finding_ui_contract(finding)
    metadata = _as_dict(normalized.get("metadata"))
    ui = _as_dict(normalized.get("_ui"))
    risk_scorecard = _as_dict(normalized.get("risk_scorecard"))
    return {
        "summary": _clean_text(normalized.get("description")),
        "technicalContext": build_finding_technical_context(normalized),
        "commandExecuted": ui.get("primaryCommand") or "",
        "commandBlocks": get_finding_command_blocks(normalized),
        "validationGuidance": get_finding_validation_guidance(normalized),
        "target": ui.get("primaryUrl") or "",
        "observedVersions": get_finding_observed_versions(normalized),
        "evidenceBlocks": build_finding_evidence_blocks(normalized),
        "rawOutput": _serialize_detail_value(normalized.get("raw_output")),
        "interpretation": _first_meaningful(
            normalized.get("impact"),
            metadata.get("impact"),
            risk_scorecard.get("impact"),
            risk_scorecard.get("summary"),
        ),
        "severity": _clean_text(normalized.get("severity") or "info").lower() or "info",
        "confidence": _clean_text(normalized.get("confidence") or "medium").lower() or "medium",
        "remediation": _first_meaningful(normalized.get("remediation"), metadata.get("remediation")),
        "references": get_finding_references(normalized),
        "artifacts": get_finding_artifacts(normalized),
    }


def has_finding_evidence(finding):
    metadata = _as_dict(finding.get("metadata"))
    validation = _as_dict(metadata.get("validation"))
    reproducibility = _as_dict(metadata.get("reproducibility"))
    evidence_candidates = (
        finding.get("request"),
        finding.get("response"),
        finding.get("evidence"),
        finding.get("raw_output"),
        finding.get("artifact"),
        validation.get("artifact"),
        reproducibility.get("request_excerpt"),
        reproducibility.get("response_excerpt"),
    )
    return any(_is_meaningful_text(candidate) for candidate in evidence_candidates)


def _build_search_text_fields(finding):
    metadata = _as_dict(finding.get("metadata"))
    validation_status = _normalize_validation_status(finding)
    result_state = _normalize_result_state(finding)
    primary_url = get_finding_primary_url(finding)
    provider = _first_meaningful(finding.get("provider"), metadata.get("provider"))
    component = _first_meaningful(finding.get("component"), metadata.get("component"))
    version = get_finding_version(finding)
    port_state = _clean_text(metadata.get("port_state")).lower() if _is_meaningful_text(metadata.get("port_state")) else ""
    is_validated = validation_status == "success" or result_state in VALIDATED_RESULT_STATES

    return [
        finding.get("title"),
        finding.get("tool_source"),
        finding.get("tool"),
        finding.get("source"),
        finding.get("category"),
        primary_url,
        finding.get("target"),
        provider,
        component,
        version,
        validation_status,
        result_state,
        "validated" if is_validated else "",
        finding.get("parameter"),
        port_state,
    ]


def build_finding_search_text(finding):
    """Build the stable lowercase token list used for Findings search/filter."""
    tokens = []
    seen = set()
    for field in _build_search_text_fields(finding):
        cleaned = _clean_text(field).lower()
        if not _is_meaningful_text(cleaned):
            continue
        if cleaned in seen:
            continue
        seen.add(cleaned)
        tokens.append(cleaned)
    return " ".join(tokens)


def build_finding_ui_contract(finding):
    finding = finding if isinstance(finding, dict) else {}
    metadata = _as_dict(finding.get("metadata"))
    validation_status = _normalize_validation_status(finding)
    result_state = _normalize_result_state(finding)
    port_state = _clean_text(metadata.get("port_state")).lower() if _is_meaningful_text(metadata.get("port_state")) else ""
    provider = _first_meaningful(finding.get("provider"), metadata.get("provider"))
    component = _first_meaningful(finding.get("component"), metadata.get("component"))
    version = get_finding_version(finding)
    primary_command = get_finding_primary_command(finding)
    primary_url = get_finding_primary_url(finding)
    has_evidence = has_finding_evidence(finding)
    is_validated = validation_status == "success" or result_state in VALIDATED_RESULT_STATES

    ui_contract = {
        "validationStatus": validation_status,
        "resultState": result_state,
        "primaryCommand": primary_command,
        "primaryUrl": primary_url,
        "provider": provider,
        "component": component,
        "version": version,
        "portState": port_state,
        "hasEvidence": has_evidence,
        "isValidated": is_validated,
        "searchText": build_finding_search_text(finding),
    }
    return {field_name: ui_contract[field_name] for field_name in CANONICAL_UI_FIELDS}


def attach_finding_ui_contract(finding):
    output = dict(finding) if isinstance(finding, dict) else {}
    output["metadata"] = _as_dict(output.get("metadata"))
    output["_ui"] = build_finding_ui_contract(output)
    return output


def attach_finding_ui_contracts(findings):
    if not isinstance(findings, list):
        return []
    return [attach_finding_ui_contract(finding) for finding in findings]
