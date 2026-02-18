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
            "timestamp": int(time.time())
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

        # Generate unique ID based on title, target and category to avoid UI duplicates
        id_str = f"{finding['title']}{finding['target']}{finding['category']}"
        finding["id"] = hashlib.md5(id_str.encode()).hexdigest()
        
        return finding
