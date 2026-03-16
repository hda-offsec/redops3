import hashlib
import time
import json
from scan_engine.helpers.finding_schema import normalize_finding_shape, generate_stable_id
from scan_engine.helpers.remediation_vault import get_remediation_blueprint


def _confidence_from_signal(finding):
    severity = str(finding.get("severity", "info")).lower()
    evidence = finding.get("evidence") or "{}"
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except Exception:
            evidence = {}
            
    payload = finding.get("payload") or (evidence.get("poison") if isinstance(evidence, dict) else "")
    repro = finding.get("reproduction") or finding.get("repro_command")
    
    # R1: Direct Proof (Response contains payload/poison)
    if finding.get("response") and payload and str(payload) in str(finding.get("response")):
        return "high"
    
    # R2: Expert Validation (Expert explicitly marked as high)
    if finding.get("confidence") == "high":
        return "high"
        
    # R3: Reproduction Command (POC exists)
    if repro and "curl" in repro.lower():
        return "high"

    # R4: Fallback for High/Critical without proof
    if severity in {"critical", "high"}:
        return "low"
        
    return "low"

def _derive_impact_area(finding):
    """Semantic mapping of finding to business impact area."""
    title = finding.get("title", "").lower()
    cat = finding.get("category", "").lower()
    
    if any(k in title or k in cat for k in ["auth", "jwt", "oauth", "session", "cookie", "login", "password"]):
        return "Identity & Access"
    if any(k in title or k in cat for k in ["sqli", "nosql", "database", "rce", "cmd", "shell", "lfi", "rfi"]):
        return "System / Data Integrity"
    if any(k in title or k in cat for k in ["s3", "bucket", "cloud", "aws", "azure", "metadata"]):
        return "Cloud Infrastructure"
    if any(k in title or k in cat for k in ["api", "graphql", "rest", "swagger", "endpoint"]):
        return "API Surface"
    if any(k in title or k in cat for k in ["pii", "secret", "token", "key", "leak"]):
        return "Sensitive Information"
    
    return "Web Application"

def _generate_risk_scorecard(finding):
    """Generates a 3-axis risk scorecard."""
    severity = finding.get("severity", "info").lower()
    confidence = finding.get("confidence", "medium").lower()
    
    # Impact (1-10)
    impact_map = {"critical": 10, "high": 8, "medium": 5, "low": 2, "info": 1}
    impact = impact_map.get(severity, 1)
    
    # Complexity (Low, Medium, High)
    complexity = "Medium"
    if "rce" in finding.get("title", "").lower(): complexity = "High"
    if "xss" in finding.get("category", "").lower(): complexity = "Low"
    
    # Likelihood
    likelihood = "Low"
    if confidence == "high": likelihood = "High"
    elif confidence == "certain": likelihood = "Certain"
    elif severity in ["high", "critical"]: likelihood = "Medium"
    
    return {
        "impact": impact,
        "complexity": complexity,
        "likelihood": likelihood
    }

class FindingNormalizer:
    """
    Unifies findings from various tools into a canonical RedOps3 schema.
    Ensures consistency for UI rendering and reporting.
    """
    @staticmethod
    def normalize(tool_data, tool_name=None):
        """
        Maps tool-specific output to a canonical finding.
        Ensures stable IDs and evidence completeness.
        """
        if not tool_name and isinstance(tool_data, dict):
            tool_name = tool_data.get("tool_source") or "unknown"

        finding = {
            "id": "",
            "title": tool_data.get("title", "Unknown Finding") if isinstance(tool_data, dict) else "General Finding",
            "severity": tool_data.get("severity", "info") if isinstance(tool_data, dict) else "info",
            "category": tool_data.get("category", "general") if isinstance(tool_data, dict) else "general",
            "description": tool_data.get("description", "") if isinstance(tool_data, dict) else str(tool_data),
            "target": tool_data.get("url", tool_data.get("target", "")) if isinstance(tool_data, dict) else "",
            "endpoint": tool_data.get("endpoint", tool_data.get("url", tool_data.get("target", ""))) if isinstance(tool_data, dict) else "",
            "parameter": tool_data.get("parameter", tool_data.get("param", "")) if isinstance(tool_data, dict) else "",
            "payload": tool_data.get("payload", tool_data.get("poison", "")) if isinstance(tool_data, dict) else "",
            "evidence": {},
            "request": tool_data.get("request", "") if isinstance(tool_data, dict) else "",
            "response": tool_data.get("response", "") if isinstance(tool_data, dict) else "",
            "repro_command": tool_data.get("repro_command", tool_data.get("curl-command", "")) if isinstance(tool_data, dict) else "",
            "reproduction": tool_data.get("reproduction", tool_data.get("repro_command", tool_data.get("curl-command", ""))) if isinstance(tool_data, dict) else "",
            "screenshot_path": tool_data.get("screenshot_path", "") if isinstance(tool_data, dict) else "",
            "tool_source": tool_name or (tool_data.get("tool_source", "generic") if isinstance(tool_data, dict) else "generic"),
            "module": tool_data.get("module", tool_name or "generic") if isinstance(tool_data, dict) else (tool_name or "generic"),
            "raw_output": tool_data.get("raw_output", tool_data.get("response", tool_data.get("description", ""))) if isinstance(tool_data, dict) else str(tool_data),
            "metadata": tool_data.get("metadata", {}) if isinstance(tool_data, dict) and isinstance(tool_data.get("metadata", {}), dict) else {},
            "timestamp": int(time.time()),
            "id_stable": "" # V6 Stable ID
        }
        
        raw_validation = tool_data.get("validation") if isinstance(tool_data, dict) and isinstance(tool_data.get("validation"), dict) else {}
        raw_arguments = tool_data.get("arguments") if isinstance(tool_data, dict) else {}

        if not isinstance(finding.get("metadata"), dict):
            finding["metadata"] = {}

        existing_repro = finding["metadata"].get("reproducibility") if isinstance(finding["metadata"].get("reproducibility"), dict) else {}
        existing_validation = finding["metadata"].get("validation") if isinstance(finding["metadata"].get("validation"), dict) else {}

        finding["metadata"]["reproducibility"] = {
            "command": existing_repro.get("command") or finding.get("repro_command") or finding.get("reproduction") or "",
            "url": existing_repro.get("url") or finding.get("endpoint") or finding.get("target") or "",
            "arguments": existing_repro.get("arguments") if isinstance(existing_repro.get("arguments"), dict) else raw_arguments if isinstance(raw_arguments, dict) else {},
            "request_excerpt": existing_repro.get("request_excerpt") or finding.get("request") or "",
            "response_excerpt": existing_repro.get("response_excerpt") or finding.get("response") or "",
        }

        finding["metadata"]["validation"] = {
            "status": raw_validation.get("status") or existing_validation.get("status") or "not_run",
            "target": raw_validation.get("target") or existing_validation.get("target") or finding.get("endpoint") or finding.get("target") or "",
            "command": raw_validation.get("command") or existing_validation.get("command") or finding.get("repro_command") or finding.get("reproduction") or "",
            "expected": raw_validation.get("expected") or existing_validation.get("expected") or "",
            "success_criteria": raw_validation.get("success_criteria") or existing_validation.get("success_criteria") or "",
            "failure_criteria": raw_validation.get("failure_criteria") or existing_validation.get("failure_criteria") or "",
            "uncertainty_criteria": raw_validation.get("uncertainty_criteria") or existing_validation.get("uncertainty_criteria") or "",
            "artifact": raw_validation.get("artifact") or existing_validation.get("artifact") or finding.get("response") or "",
        }

        # Preserve specialized tool logic
        if tool_name == "nuclei":
            finding.update({
                "title": tool_data.get("info", {}).get("name", finding["title"]),
                "severity": tool_data.get("info", {}).get("severity", finding["severity"]).lower(),
                "description": tool_data.get("info", {}).get("description", finding["description"]),
                "target": tool_data.get("matched-at", finding["target"]),
                "category": tool_data.get("info", {}).get("tags", ["nuclei"])[0] if tool_data.get("info", {}).get("tags") else "vuln",
                "evidence": {
                    "template": tool_data.get("template-id"),
                    "matcher": tool_data.get("matcher-name"),
                    "extracted": tool_data.get("extracted-results")
                }
            })
            
        elif tool_name == "dalfox":
            finding.update({
                "title": f"Reflected XSS: {tool_data.get('param', 'unknown')}",
                "severity": "high",
                "category": "xss",
                "description": f"XSS found via {tool_data.get('type', 'reflected')} in parameter '{tool_data.get('param')}'",
                "target": tool_data.get("url", ""),
                "evidence": {
                    "param": tool_data.get("param"),
                    "poison": tool_data.get("poison"),
                    "proof": tool_data.get("evidence")
                },
                "parameter": tool_data.get("param", ""),
                "payload": tool_data.get("poison", ""),
                "endpoint": tool_data.get("url", ""),
                "reproduction": tool_data.get("repro_command", tool_data.get("curl-command", "")) or f"dalfox url '{tool_data.get('url', '')}'"
            })

        vuln_class = str(finding.get("category", "")).lower()
        if vuln_class in {"xss", "sqli", "sqli", "lfi", "rfi", "ssrf", "idor", "command-injection", "cmdi"}:
            if not finding.get("parameter"):
                finding["parameter"] = tool_data.get("param", "") if isinstance(tool_data, dict) else ""
            if not finding.get("payload") and isinstance(finding.get("evidence"), dict):
                finding["payload"] = finding["evidence"].get("poison", "")
            if not finding.get("reproduction"):
                finding["reproduction"] = finding.get("repro_command", "")

        # --- SEVERITY NORMALIZATION ---
        sev_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info", "warn": "medium"}
        finding["severity"] = sev_map.get(str(finding["severity"]).lower(), "info")

        # --- EVIDENCE VALIDATION ---
        if not any(finding["evidence"].values()) and isinstance(tool_data, dict):
             finding["evidence"] = tool_data
        if not isinstance(finding.get("evidence"), str):
            finding["evidence"] = json.dumps(finding.get("evidence", {}), default=str)

        conf = _confidence_from_signal(finding)
        finding["confidence"] = conf
        
        # V12 Argumentative labeling: if high severity but low confidence, label it
        if finding["severity"] in {"critical", "high"} and conf == "low":
            if not finding["title"].startswith("["):
                finding["title"] = f"[Unverified] {finding['title']}"
            finding["description"] = f"**⚠ ATTENTION: This finding lacks definitive proof.**\n" \
                                     f"It is based on theoretical heuristics. Manual audit recommended.\n\n" + \
                                     finding["description"]

        # --- RE-REMEDIATION ENRICHMENT (Wave 5.4) ---
        if not finding.get("remediation"):
            finding["remediation"] = get_remediation_blueprint(finding)

        # --- ENRICHMENT (Wave 5.4) ---
        finding["impact_area"] = _derive_impact_area(finding)
        finding["risk_scorecard"] = _generate_risk_scorecard(finding)
        
        # --- STABLE ID GENERATION (V6) ---
        finding["id_stable"] = generate_stable_id(finding)
        finding["id"] = finding["id_stable"]

        
        return normalize_finding_shape(finding, source=tool_name)
