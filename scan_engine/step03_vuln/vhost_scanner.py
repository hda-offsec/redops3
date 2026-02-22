import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session
import time
import traceback

class VhostScanner:
    """
    V7 EXPERT: Virtual Host (Vhost) Brute-forcer (Hardened).
    Discovers hidden subdomains or sites co-located on the same IP by fuzzing the 'Host' header.
    Implements explicit scan modes, strict timeout, and fail-safe execution.
    """
    def __init__(self, target, options=None):
        self.options = options or {}
        self.target = target
        self.session = get_session(self.options)
        
        # Wordlists
        self.quick_vhosts = ["dev", "test", "staging", "api", "admin", "git", "vpn"]
        self.full_vhosts = [
            "dev", "test", "stage", "staging", "api", "v1", "v2", "beta",
            "admin", "internal", "corp", "m", "mobile", "static", "assets",
            "vpn", "mail", "blog", "shop", "git", "jenkins", "docker", "registry",
            "db", "database", "sql", "monitor", "zabbix", "grafana", "prometheus"
        ]

    def run(self, port, protocol='http', scan_mode="full", logger=None):
        """
        Main entry point for Vhost Discovery.
        Returns a structured dictionary with status and findings.
        """
        start_time = time.time()
        is_quick = scan_mode == "quick"
        
        results = {
            "status": "INIT",
            "execution_time": 0,
            "findings": [],
            "error": None,
            "confidence": 0
        }

        try:
            if logger: logger(f"Vhost Expert: Starting scan on port {port} (Mode: {scan_mode})", "INFO")
            
            base_url = f"{protocol}://{self.target}:{port}"
            
            # 1. Capture Baseline
            try:
                # Use a specific timeout for baseline
                r_base = self.session.get(base_url, timeout=5, allow_redirects=False)
                base_len = len(r_base.content)
                base_status = r_base.status_code
            except Exception as e:
                results["status"] = "FAILED"
                results["error"] = f"Baseline capture failed: {str(e)}"
                return results

            # 2. Prepare Candidates
            common_list = self.quick_vhosts if is_quick else self.full_vhosts
            t_parts = self.target.split('.')
            domain = ".".join(t_parts[-2:]) if len(t_parts) >= 2 else self.target
            
            candidates = set()
            for v in common_list:
                candidates.add(f"{v}.{domain}")
                candidates.add(f"{v}-{domain}")
            
            # 3. Fuzzing Loop with Watchdog
            findings = []
            timeout_limit = 30 if is_quick else 120
            
            for vhost in candidates:
                # Check execution time
                if (time.time() - start_time) > timeout_limit:
                    if logger: logger("Vhost Expert: Timeout reached, aborting loop.", "WARN")
                    results["status"] = "TIMEOUT"
                    break
                
                if vhost == self.target: continue
                
                try:
                    headers = {"Host": vhost}
                    # Small timeout per request to keep it moving
                    r = self.session.get(base_url, headers=headers, timeout=3, allow_redirects=False)
                    
                    # Detection Logic
                    is_different = False
                    if r.status_code != base_status:
                        is_different = True
                    elif abs(len(r.content) - base_len) > (base_len * 0.15): # 15% tolerance
                        is_different = True
                    
                    if is_different:
                        finding = {
                            "title": f"Virtual Host Discovered: {vhost}",
                            "description": (
                                f"A unique response was detected when using the Host header `{vhost}`.\n\n"
                                f"**Status**: {r.status_code} (Base: {base_status})\n"
                                f"**Content Length**: {len(r.content)} (Base: {base_len})"
                            ),
                            "severity": "medium",
                            "tool_source": "vhost_expert",
                            "vhost": vhost,
                            "url": f"{protocol}://{vhost}:{port}",
                            "confidence": "high" if r.status_code != base_status else "medium"
                        }
                        findings.append(finding)
                        if logger: logger(f"🌐 VHOST DISCOVERED: {vhost} (Port {port})", "SUCCESS")
                except Exception:
                    continue

            results["findings"] = findings
            if results["status"] != "TIMEOUT":
                results["status"] = "COMPLETED"
            results["confidence"] = 0.8 if findings else 0.5

        except Exception as e:
            results["status"] = "FAILED"
            results["error"] = str(e)
            if logger: logger(f"Vhost Expert Critical Failure: {traceback.format_exc()}", "DEBUG")

        results["execution_time"] = round(time.time() - start_time, 2)
        return results

    # Legacy compatibility
    def scan(self, port, protocol='http', logger=None):
        res = self.run(port, protocol, scan_mode="full", logger=logger)
        return res.get("findings", [])
