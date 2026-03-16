import re
import scan_engine.helpers.http_client as http_client

class DeceptiveRecon:
    """
    Offensive Deception & Internal Routing Discovery.
    Uses specialized headers and path manipulation to uncover internal proxy hops and CDN leaks.
    """
    
    DECEPTIVE_HEADERS = [
        {"Max-Forwards": "0"}, # Forces some proxies to respond directly
        {"Max-Forwards": "1"}, 
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Rewrite-URL": "/"},
        {"X-Original-URL": "/"}
    ]

    def __init__(self, target, options=None):
        self.target = target
        self.options = options

    def audit(self, port, protocol='http', logger=None):
        findings = []
        base_url = f"{protocol}://{self.target}:{port}"
        if logger: logger(f"Deceptive Recon: Probing {base_url} for internal hop leaks & CDN deception...", "INFO")

        # 1. Internal Hop Discovery (Max-Forwards)
        findings.extend(self.probe_internal_hops(base_url, logger))

        # 2. CDN Cache Deception (RCD/RPO)
        findings.extend(self.probe_cache_deception(base_url, logger))

        return findings

    def probe_internal_hops(self, base_url, logger):
        findings = []
        for headers in self.DECEPTIVE_HEADERS:
            try:
                r = http_client.get(base_url, headers=headers, timeout=3, allow_redirects=False)
                # If we see 413, 502, or specific headers in response that differ from baseline
                if r.status_code == 483 or (headers.get("Max-Forwards") == "0" and r.status_code == 200):
                    via = r.headers.get("Via", "")
                    server = r.headers.get("Server", "")
                    if via or "Proxy" in server or "Gateway" in server:
                        findings.append({
                            "title": "Deceptive Recon: Internal Proxy Hop Discovered",
                            "description": f"Internal routing node revealed via {list(headers.keys())[0]} header.\nNode: {via or server}",
                            "severity": "info",
                            "tool_source": "deceptive_recon",
                            "metadata": {"hop_info": via or server, "trigger_header": headers}
                        })
            except Exception: pass
        return findings

    def probe_cache_deception(self, base_url, logger):
        findings = []
        # RCD: Web Cache Deception via relative path
        # Testing /profile/nonexistent.css to see if /profile is cached as CSS
        test_path = f"{base_url}/favicon.ico/nonexistent.css" # Testing on icon first to avoid noise
        try:
            r = http_client.get(test_path, timeout=5)
            if r.status_code == 200 and "image" in r.headers.get("Content-Type", "").lower():
                # Favicon returned for CSS path -> potentially vulnerable to Cache Deception
                findings.append({
                    "title": "Deceptive Recon: Potential CDN Cache Deception (RCD)",
                    "description": f"The CDN/Proxy served an image for a CSS path request ({test_path}).\nThis indicates a 'Relative Path Overwrite' (RPO) vulnerability that can lead to account takeover via cache poisoning.",
                    "severity": "high",
                    "tool_source": "deceptive_recon",
                    "endpoint": test_path,
                    "repro_command": f"curl -ik {test_path}"
                })
        except Exception: pass
        return findings
