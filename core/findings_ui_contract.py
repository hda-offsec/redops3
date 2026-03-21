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


def _as_dict(value):
    return value if isinstance(value, dict) else {}


def _clean_text(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


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


def build_finding_search_text(finding):
    metadata = _as_dict(finding.get("metadata"))
    validation_status = _normalize_validation_status(finding)
    result_state = _normalize_result_state(finding)
    primary_url = get_finding_primary_url(finding)
    provider = _first_meaningful(finding.get("provider"), metadata.get("provider"))
    component = _first_meaningful(finding.get("component"), metadata.get("component"))
    version = get_finding_version(finding)
    port_state = _clean_text(metadata.get("port_state")).lower() if _is_meaningful_text(metadata.get("port_state")) else ""
    is_validated = validation_status == "success" or result_state in VALIDATED_RESULT_STATES

    ordered_fields = [
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

    tokens = []
    seen = set()
    for field in ordered_fields:
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

    return {
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


def attach_finding_ui_contract(finding):
    output = dict(finding) if isinstance(finding, dict) else {}
    output["metadata"] = _as_dict(output.get("metadata"))
    output["_ui"] = build_finding_ui_contract(output)
    return output


def attach_finding_ui_contracts(findings):
    if not isinstance(findings, list):
        return []
    return [attach_finding_ui_contract(finding) for finding in findings]
