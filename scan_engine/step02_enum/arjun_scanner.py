import shutil
import json
import uuid
import re
import os
import tempfile
import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session
from scan_engine.helpers.process_manager import ProcessManager

class ArjunScanner:
    """
    Expert Parameter Discovery Module (Hardened).
    Implements Arjun execution, robust parsing, active validation,
    CMS-aware filtering, and surface scoring.
    """
    def __init__(self, target, options=None):
        self.options = options or {}
        self.target = target
        self.session = get_session(self.options)
        
        # Noise patterns (CMS related)
        self.noise_patterns = [
            r"^_wp_", r"^nonce_", r"^uncode_", r"^woocommerce_", r"^wc_",
            r"^ajax_url$", r"^action$", r"^register_metadata$", r"^logs_enabled$"
        ]

    def check_tools(self):
        return shutil.which('arjun') is not None

    def get_command(self, port, protocol, output_file):
        url = f"{protocol}://{self.target}:{port}"
        return [
            "arjun", 
            "-u", url, 
            "-t", "10",
            "--rate", "5",
            "-m", "GET,POST,JSON",
            "-oJ", output_file
        ]

    def _get_baseline(self, url, logger=None):
        """Captures a baseline for comparison."""
        try:
            resp = self.session.get(url, timeout=5)
            return {
                "status": resp.status_code,
                "length": len(resp.text),
                "body": resp.text
            }
        except Exception as e:
            if logger: logger(f"Baseline capture failed for {url}: {e}", "DEBUG")
            return None

    def _is_cms_related(self, param_name):
        """Checks if a parameter name matches CMS/Frontend noise patterns."""
        for pattern in self.noise_patterns:
            if re.search(pattern, param_name, re.IGNORECASE):
                return True
        return False

    def _validate_param(self, url, param_name, baseline, logger=None):
        """
        Active Validation Engine:
        Injects a unique token and measures influence on response.
        """
        token = f"REDOPS_TEST_{uuid.uuid4().hex[:8]}"
        
        # We test both GET and POST if possible, but keep it simple for now (GET focus)
        test_url = f"{url}?{param_name}={token}" if "?" not in url else f"{url}&{param_name}={token}"
        
        try:
            resp = self.session.get(test_url, timeout=5)
            
            # 1. Reflection Check
            reflected = token in resp.text
            
            # 2. Influence Check (Length or Status change)
            # Significant length change defined as > 5% or > 20 chars diff from baseline length + token length
            len_diff = abs(len(resp.text) - baseline["length"])
            influences = (resp.status_code != baseline["status"]) or (len_diff > (len(token) + 20))
            
            # 3. Logic Alteration Check
            alters_logic = resp.status_code != baseline["status"]
            
            # 4. Error Check
            triggers_error = resp.status_code >= 400
            
            # Scoring
            score = 0
            if influences: score += 0.3
            if reflected: score += 0.2
            if alters_logic: score += 0.3
            if triggers_error: score += 0.2
            
            if self._is_cms_related(param_name):
                score -= 0.5
                classification = "CMS_FRONTEND_CONFIG"
            elif influences or reflected:
                classification = "ACTIVE_PARAMETER" if influences else "REFLECTED_PARAMETER"
            else:
                classification = "UNKNOWN/PASSIVE"

            severity = "INFO"
            if score >= 0.75: severity = "HIGH"
            elif score >= 0.4: severity = "MEDIUM"
            elif score > 0.1: severity = "LOW"

            return {
                "name": param_name,
                "validated": True,
                "influences_response": influences,
                "reflected": reflected,
                "triggers_error": triggers_error,
                "alters_logic": alters_logic,
                "cms_related": self._is_cms_related(param_name),
                "classification": classification,
                "exploitable_score": round(max(0, score), 2),
                "severity": severity
            }
        except Exception as e:
            if logger: logger(f"Validation failed for {param_name}: {e}", "DEBUG")
            return None

    def scan_and_validate(self, port, protocol='http', logger=None):
        """
        Orchestrates Arjun discovery followed by manual active validation.
        """
        findings = {
            "total_found": 0,
            "active_validated": 0,
            "passive_filtered": 0,
            "suspicious": 0,
            "parameters": []
        }
        
        url = f"{protocol}://{self.target}:{port}"
        
        # 1. Capture Baseline
        baseline = self._get_baseline(url, logger)
        if not baseline:
            return findings

        # 2. Run Arjun with JSON output
        temp_file = tempfile.mktemp(suffix=".json")
        command = self.get_command(port, protocol, temp_file)
        
        if logger: logger(f"Running Arjun on {url} with discovery validation...", "INFO")
        
        # Run process to completion
        ProcessManager.run_command_sync(command)
        
        # 3. Parse and Validate
        try:
            if os.path.exists(temp_file):
                with open(temp_file, 'r') as f:
                    data = json.load(f)
                
                # Arjun JSON format is usually { url: { "params": [p1, p2...] } }
                potential_params = []
                for u in data:
                    potential_params.extend(data[u].get("params", []))
                
                # Cleanup duplicates
                potential_params = list(set(potential_params))
                findings["total_found"] = len(potential_params)
                
                if logger: logger(f"Arjun discovered {len(potential_params)} candidate parameters. Starting validation...", "DEBUG")
                
                for p_name in potential_params:
                    # Guardrail: CMS noise reduction
                    is_cms = self._is_cms_related(p_name)
                    
                    # Validate
                    validated = self._validate_param(url, p_name, baseline, logger)
                    if validated:
                        findings["parameters"].append(validated)
                        
                        # Counters
                        if validated["classification"] == "ACTIVE_PARAMETER":
                            findings["active_validated"] += 1
                        elif validated["classification"] == "CMS_FRONTEND_CONFIG":
                            findings["passive_filtered"] += 1
                        
                        if validated["severity"] in ["HIGH", "MEDIUM"]:
                            findings["suspicious"] += 1
                
                # Clean up temp file
                os.remove(temp_file)
        except Exception as e:
            if logger: logger(f"Failed to parse or validate Arjun output: {e}", "ERROR")

        return findings

    # Legacy method to keep compatibility if needed, but we now prefer scan_and_validate
    def stream_arjun(self, port, protocol='http'):
        """
        Runs arjun for parameter discovery (legacy stdout stream).
        """
        command = [
            "arjun", 
            "-u", f"{protocol}://{self.target}:{port}", 
            "-t", "10",
            "--rate", "5",
            "-m", "GET,POST,JSON"
        ]
        return ProcessManager.stream_command(command)
