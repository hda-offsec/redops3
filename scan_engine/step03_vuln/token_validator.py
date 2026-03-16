import re
import requests
import json
from datetime import datetime

class TokenValidator:
    """
    Precision intelligence module to validate discovered secrets and tokens.
    Performs safe, non-destructive validation checks.
    """
    
    SIGNATURES = {
        "github_token": r"(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}",
        "aws_access_key": r"AKIA[0-9A-Z]{16}",
        "slack_token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
        "google_api_key": r"AIza[0-9A-Za-z-_]{35}",
        "generic_bearer": r"Bearer\s+([a-zA-Z0-9\.\-_]{20,})",
    }

    def __init__(self, scan_id):
        self.scan_id = scan_id

    def validate_discovered_secrets(self, findings, logger=None):
        """
        Analyzes findings for potential secrets and attempts validation.
        """
        validated_findings = []
        for finding in findings:
            content = f"{finding.get('description', '')} {finding.get('payload', '')} {finding.get('evidence', '')}"
            
            for token_type, pattern in self.SIGNATURES.items():
                matches = re.findall(pattern, content)
                for secret in matches:
                    if logger: logger(f"💎 TokenValidator: Detected potential {token_type}. Attempting safe validation...", "INFO")
                    
                    result = self._check_secret(token_type, secret)
                    if result["valid"]:
                        if logger: logger(f"✅ TokenValidator: Confirmed VALID {token_type}!", "SUCCESS")
                        
                        # Create a high-fidelity finding or update existing
                        validated_findings.append({
                            "title": f"Validated {token_type.replace('_', ' ').title()}",
                            "description": f"A verified {token_type} was discovered and confirmed active.\n\n**Impact**: {result['impact']}\n**Metadata**: {json.dumps(result['metadata'])}",
                            "severity": "high" if result["impact"] == "sensitive" else "critical",
                            "confidence": "high",
                            "category": "secret_leak",
                            "tool_source": "token_validator",
                            "metadata": {
                                "token_type": token_type,
                                "validation_status": "confirmed_active",
                                "validation_timestamp": datetime.utcnow().isoformat(),
                                "impact_scope": result["impact"]
                            },
                            "remediation": self._get_remediation(token_type)
                        })
        return validated_findings

    def _check_secret(self, token_type, secret):
        """
        Performs the actual network check. 
        NOTE: In a real red teaming tool, we must be careful with rate limits and attribution.
        """
        # Default result
        res = {"valid": False, "impact": "unknown", "metadata": {}}
        
        try:
            if token_type == "github_token":
                # Check GitHub User
                headers = {"Authorization": f"token {secret}"}
                r = requests.get("https://api.github.com/user", headers=headers, timeout=5)
                if r.status_code == 200:
                    user_data = r.json()
                    res = {
                        "valid": True, 
                        "impact": "critical" if user_data.get("site_admin") else "high",
                        "metadata": {"user": user_data.get("login"), "scopes": r.headers.get("X-OAuth-Scopes")}
                    }
            
            elif token_type == "google_api_key":
                # Check if it works for a harmless call
                r = requests.get(f"https://www.googleapis.com/oauth2/v1/tokeninfo?key={secret}", timeout=5)
                if r.status_code != 400: # Usually 400 if invalid key
                     res = {"valid": True, "impact": "medium", "metadata": {"status": "authenticated"}}

            # Add more validators as needed
                
        except Exception:
            pass
            
        return res

    def _get_remediation(self, token_type):
        remediations = {
            "github_token": "Revoke the token immediately in GitHub Settings > Developer Settings > Personal Access Tokens. Audit repository logs for unauthorized access.",
            "aws_access_key": "Rotate keys via IAM console. Deactivate the compromised key and update applications to use IAM roles (IRSA) instead of static keys.",
            "google_api_key": "Restrict the API key to specific referrers, IP addresses, or APIs in the Google Cloud Console. Regenerate the key if exposed.",
            "default": "Revoke the credential immediately. Rotate all associated passwords and secrets. Audit logs for any unauthorized activity originating from this credential."
        }
        return remediations.get(token_type, remediations["default"])
