import re
import requests
from typing import Dict, List, Any

class SPAAnalyzer:
    """
    Advanced JS & SPA Intelligence module.
    V12: Ported from RedOps2 javascript_analyzer.py.
    """
    def __init__(self, options=None):
        self.options = options or {}
        self.secrets_patterns = {
            "API Key": r"(?:api_key|apikey|key|auth|token)[\"']?\s?[:=]\s?[\"']([a-zA-Z0-9\-_]{20,})[\"']",
            "Firebase URL": r"https://[a-z0-9\-_]+\.firebaseio\.com",
            "S3 Bucket": r"[a-z0-9\-\.]+\.s3\.amazonaws\.com",
            "Client ID": r"client_id[\"']?\s?[:=]\s?[\"']([a-zA-Z0-9\-_]+)[\"']",
            "Secret Key": r"(?:secret|password|passwd|pwd)[\"']?\s?[:=]\s?[\"']([a-zA-Z0-9!@#$%^&*()_\-+={}\[\]\-_]{8,})[\"']"
        }
        
        self.vulnerability_patterns = {
            "DOM XSS (innerHTML)": r"\.innerHTML\s?=",
            "DOM XSS (document.write)": r"document\.write\(",
            "Eval Usage": r"\beval\(",
            "Dangerous Regex": r"new\s+RegExp\(.*[+*]{2,}"
        }

    def analyze(self, url: str, content: str = None) -> Dict[str, Any]:
        """Analyzes a JS file from URL or provided content."""
        if not content:
            try:
                # Use RedOps3 session if available, otherwise requests
                response = requests.get(url, timeout=10, verify=False)
                content = response.text
            except Exception as e:
                return {"error": f"Failed to fetch JS: {str(e)}"}

        analysis = {
            "url": url,
            "secrets_found": [],
            "vulnerabilities": [],
            "endpoints": [],
            "security_score": 100
        }

        # 1. Pattern Matching for Secrets
        for name, pattern in self.secrets_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple): match = match[0]
                analysis["secrets_found"].append({"type": name, "value": match})
                analysis["security_score"] -= 20

        # 2. Pattern Matching for Vulnerabilities
        for name, pattern in self.vulnerability_patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                analysis["vulnerabilities"].append({"type": name, "count": len(matches)})
                analysis["security_score"] -= 10

        # 3. Endpoint Extraction (Enhanced)
        endpoint_pattern = r"(?:https?://[a-zA-Z0-9/.\-_]+|/[a-zA-Z0-9/.\-_]+)"
        endpoints = re.findall(endpoint_pattern, content)
        # Filter out common false positives and noise
        valid_endpoints = [e for e in endpoints if len(e) > 3 and not e.endswith(('.jpg', '.png', '.css', '.svg'))]
        analysis["endpoints"] = list(set(valid_endpoints))[:100] # Limit to 100

        analysis["security_score"] = max(0, analysis["security_score"])
        analysis["recommendations"] = self._generate_recommendations(analysis)

        return analysis

    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        recommendations = []
        if analysis["secrets_found"]:
            recommendations.append("Remove hardcoded API keys and secrets. Use environment variables.")
        if any(v["type"] == "DOM XSS (innerHTML)" for v in analysis["vulnerabilities"]):
            recommendations.append("Avoid using .innerHTML; use .textContent or safer templating methods to prevent XSS.")
        if analysis["security_score"] < 70:
            recommendations.append("Review JS security posture and sanitize inputs.")
        return recommendations
