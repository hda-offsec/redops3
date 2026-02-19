import hashlib
import time

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
            "evidence": {},
            "tool_source": tool_name or tool_data.get("tool_source", "generic"),
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
                }
            })

        # --- SEVERITY NORMALIZATION ---
        sev_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info", "warn": "medium"}
        finding["severity"] = sev_map.get(str(finding["severity"]).lower(), "info")

        # --- EVIDENCE VALIDATION ---
        if not any(finding["evidence"].values()) and isinstance(tool_data, dict):
             finding["evidence"] = tool_data

        # --- STABLE ID GENERATION (V6) ---
        try:
            from urllib.parse import urlparse
            parsed = urlparse(str(finding["target"]))
            path_stable = parsed.path or "/"
            param_stable = str(finding["evidence"].get("param", "")) or str(finding["title"])
            payload_class = str(finding["category"])
            
            id_seed = f"{path_stable}{param_stable}{payload_class}"
            finding["id_stable"] = hashlib.sha512(id_seed.encode(), usedforsecurity=False).hexdigest()
            finding["id"] = finding["id_stable"]
        except Exception:
            id_str = f"{finding['title']}{finding['target']}{finding['category']}"
            finding["id"] = hashlib.sha512(id_str.encode(), usedforsecurity=False).hexdigest()
            finding["id_stable"] = finding["id"]
        
        return finding

