import hashlib
import time

class FindingNormalizer:
    """
    Unifies findings from various tools into a canonical RedOps3 schema.
    Ensures consistency for UI rendering and reporting.
    """
    @staticmethod
    def normalize(tool_data, tool_name):
        """
        Maps tool-specific output to a canonical finding.
        Ensures stable IDs and evidence completeness.
        """
        finding = {
            "id": "",
            "title": "Unknown Finding",
            "severity": "info",
            "category": "general",
            "description": "",
            "target": "",
            "evidence": {},
            "tool_source": tool_name,
            "timestamp": int(time.time()),
            "id_stable": "" # V6 Stable ID
        }
        
        if tool_name == "nuclei":
            finding.update({
                "title": tool_data.get("info", {}).get("name", "Nuclei finding"),
                "severity": tool_data.get("info", {}).get("severity", "info").lower(),
                "description": tool_data.get("info", {}).get("description", ""),
                "target": tool_data.get("matched-at", ""),
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
            
        elif tool_name == "sqlmap":
            finding.update({
                "title": "SQL Injection Detected",
                "severity": "critical",
                "category": "sqli",
                "description": tool_data.get("data", "SQLMap identified a vulnerability."),
                "target": tool_data.get("url", ""),
                "evidence": {
                    "payload": tool_data.get("payload")
                }
            })

        # --- SEVERITY NORMALIZATION ---
        sev_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}
        finding["severity"] = sev_map.get(finding["severity"].lower(), "info")

        # --- EVIDENCE VALIDATION ---
        if not any(finding["evidence"].values()):
             finding["evidence"]["raw"] = str(tool_data)

        # --- STABLE ID GENERATION (V6) ---
        # id_stable = hash(path + param + payload_class)
        # We extract path and param if possible
        try:
            from urllib.parse import urlparse
            parsed = urlparse(finding["target"])
            path_stable = parsed.path
            param_stable = finding["evidence"].get("param", "") or finding["title"]
            payload_class = finding["category"]
            
            id_seed = f"{path_stable}{param_stable}{payload_class}"
            finding["id_stable"] = hashlib.md5(id_seed.encode()).hexdigest()
            finding["id"] = finding["id_stable"] # Maintain backward compatibility
        except:
            id_str = f"{finding['title']}{finding['target']}{finding['category']}"
            finding["id"] = hashlib.md5(id_str.encode()).hexdigest()
            finding["id_stable"] = finding["id"]
        
        return finding

