import hashlib
import time
import json


def _confidence_from_signal(finding):
    severity = str(finding.get("severity", "info")).lower()
    evidence = finding.get("evidence") or {}
    payload = finding.get("payload") or (evidence.get("poison") if isinstance(evidence, dict) else "")
    if finding.get("response") and payload and str(payload) in str(finding.get("response")):
        return "high"
    if severity in {"critical", "high"}:
        return "medium"
    return "low"

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
        
        # ... logic for specific tools ... (keeping existing ones)
        if tool_name == "nuclei":
            # [Existing nuclei logic]
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

        if not finding.get("confidence"):
            finding["confidence"] = _confidence_from_signal(finding)
        else:
            finding["confidence"] = str(finding.get("confidence")).lower()

        # --- STABLE ID GENERATION (V6) ---
        try:
            from urllib.parse import urlparse
            parsed = urlparse(str(finding["target"]))
            path_stable = parsed.path or "/"
            evidence_obj = finding.get("evidence")
            if isinstance(evidence_obj, str):
                try:
                    evidence_obj = json.loads(evidence_obj)
                except Exception:
                    evidence_obj = {}
            
            # Use evidence if available, else title/category
            trigger_stable = str((evidence_obj or {}).get("param", "")) or \
                             str((evidence_obj or {}).get("parameter", "")) or \
                             str(finding["title"])
                             
            payload_class = str(finding["category"])
            
            id_seed = f"{path_stable}|{trigger_stable}|{payload_class}"
            finding["id_stable"] = hashlib.sha256(id_seed.encode()).hexdigest()
            finding["id"] = finding["id_stable"]
        except Exception:
            id_str = f"{finding['title']}|{finding['target']}|{finding['category']}"
            finding["id_stable"] = hashlib.sha256(id_str.encode()).hexdigest()
            finding["id"] = finding["id_stable"]
        
        return finding
