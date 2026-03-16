import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scan_engine.helpers.http_client import get_session

class ParameterMiner:
    """
    Expert Miner for hidden parameters (inspired by Arjun).
    Uses differential analysis to detect when a parameter affects the response.
    """
    def __init__(self, options=None):
        self.options = options
        self.session = get_session(self.options)
        self.session.headers.update({"User-Agent": "RedOps3-ParamMiner/1.0"})
        
        # High-value parameter wordlist
        self.wordlist = [
            "debug", "admin", "dev", "test", "config", "env", "cmd", "exec", 
            "url", "redirect", "dest", "destination", "callback", "id", "user_id",
            "role", "priv", "internal", "source", "file", "path", "src", "ref",
            "proxy", "api_key", "token", "secret", "verify", "allow", "grant"
        ]

    def mine(self, url, logger=None):
        findings = []
        parsed = urlparse(url)
        base_url = urlunparse(parsed._replace(query=""))
        
        if logger: logger(f"💎 Parameter Miner: Mining hidden inputs on {base_url}...", "INFO")

        # 1. Collect Baseline
        try:
            baseline_resp = self.session.get(url, timeout=5, verify=False)
            baseline_text = baseline_resp.text
            baseline_len = len(baseline_resp.content)
            baseline_status = baseline_resp.status_code
        except Exception as e:
            if logger: logger(f"Parameter Miner Error: Baseline failed: {e}", "DEBUG")
            return []

        discovered = []
        
        # 2. Batch Probing (to be efficient)
        # We test parameters in small batches
        batch_size = 5
        for i in range(0, len(self.wordlist), batch_size):
            batch = self.wordlist[i:i+batch_size]
            test_params = {p: "redops_miner_test_v1" for p in batch}
            
            try:
                # Merge with existing params if any
                orig_qs = parse_qs(parsed.query)
                for k, v in test_params.items():
                    orig_qs[k] = v
                
                test_url = urlunparse(parsed._replace(query=urlencode(orig_qs, doseq=True)))
                resp = self.session.get(test_url, timeout=5, verify=False)
                
                # Check for differential
                if resp.status_code != 200 and baseline_status == 200:
                    # Anomaly detected! One of the params caused a change.
                    # We narrow it down.
                    for p in batch:
                        if self._is_parameter_active(url, p, baseline_text, baseline_len):
                            discovered.append(p)
                elif abs(len(resp.content) - baseline_len) > 5:
                    # Length change! 
                    for p in batch:
                        if self._is_parameter_active(url, p, baseline_text, baseline_len):
                            discovered.append(p)
            except Exception:
                continue

        for p in set(discovered):
            findings.append({
                "title": f"Discovery: Hidden Parameter Found (`{p}`)",
                "description": f"The hidden parameter `{p}` was discovered on `{base_url}` via differential analysis. This parameter affects the application response and should be audited for vulnerabilities.",
                "severity": "info",
                "confidence": "high",
                "tool_source": "parameter_miner",
                "url": url,
                "parameter": p,
                "metadata": {"technique": "differential_analysis", "location": "query_string"}
            })
            if logger: logger(f"🔥 Hidden Parameter Discovered: {p} on {base_url}", "SUCCESS")

        return findings

    def _is_parameter_active(self, url, param, baseline_text, baseline_len):
        """Verifies if a specific parameter is active via reflection or length delta."""
        try:
            test_val = f"redops_verify_{param}"
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            qs[param] = test_val
            test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            
            r = self.session.get(test_url, timeout=5, verify=False)
            
            # Success Criteria:
            # 1. Reflection
            if test_val in r.text:
                return True
            # 2. Length Delta (significant)
            if abs(len(r.content) - baseline_len) > 2:
                # Double check with a different value
                qs[param] = test_val + "_alt"
                test_url_alt = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
                r_alt = self.session.get(test_url_alt, timeout=5, verify=False)
                if len(r_alt.content) != len(r.content):
                    return True
            # 3. Status Code Change
            # (handled by caller mostly, but can be added here)
        except:
            pass
        return False
