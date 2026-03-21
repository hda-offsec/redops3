import json
from urllib.parse import urlparse, urljoin
from scan_engine.helpers.http_client import get_session

class APIFuzzer:
    """
    Expert Auditor for API logic.
    Focuses on:
    - HTTP Method Fuzzing (PATCH, DELETE, etc.)
    - IDOR Pattern Detection
    - GraphQL Introspection
    """
    def __init__(self, options=None):
        self.options = options
        self.session = get_session(self.options)
        self.session.headers.update({"User-Agent": "RedOps3-APIFuzzer/1.0", "Content-Type": "application/json"})

    def fuzz_endpoint(self, url, logger=None):
        findings = []
        if logger: logger(f"📡 API Fuzzer: Auditing logic on {url}...", "INFO")

        # 1. HTTP Method Fuzzing (Verb Tampering) — Safe methods only
        methods = ["OPTIONS", "TRACE"]
        for m in methods:
            try:
                r = self.session.request(m, url, timeout=3, verify=False)
                # Successful method change might be a problem if it wasn't expected
                if r.status_code in [200, 201, 204]:
                    findings.append({
                        "title": f"API Intelligence: Allowed Method (`{m}`)",
                        "description": f"The endpoint `{url}` allows the `{m}` HTTP method (Status: {r.status_code}). This should be verified for proper access control.",
                        "severity": "info",
                        "tool_source": "api_fuzzer",
                        "url": url,
                        "metadata": {"method": m}
                    })
            except: pass

        # 2. IDOR Pattern Probing (Simple numeric ID inversion)
        import re
        id_match = re.search(r'/(\d+)(?:/|$|\?)', url)
        if id_match:
            original_id = id_match.group(1)
            # Try incrementing / decrementing or a "canary" ID
            test_ids = [str(int(original_id) + 1), str(int(original_id) - 1), "0", "1", "9999"]
            for tid in test_ids:
                if tid == original_id: continue
                test_url = url.replace(original_id, tid)
                try:
                    r = self.session.get(test_url, timeout=3, verify=False)
                    if r.status_code == 200:
                        # Baseline comparison needed here for "true" IDOR, but reporting as signal
                        findings.append({
                            "title": "Potential IDOR Surface Detected",
                            "description": f"Successfully accessed alternative ID `{tid}` at `{test_url}` (Original: `{original_id}`). This is a candidate for Insecure Direct Object Reference.",
                            "severity": "medium",
                            "confidence": "medium",
                            "tool_source": "api_fuzzer",
                            "url": test_url
                        })
                except: pass

        # 3. GraphQL Introspection
        if "graphql" in url.lower():
            introspection_query = {"query": "{__schema{queryType{name}}}"}
            try:
                r = self.session.post(url, json=introspection_query, timeout=5, verify=False)
                if r.status_code == 200 and "__schema" in r.text:
                    if logger: logger(f"🔥 GraphQL Introspection Enabled: {url}", "HIGH")
                    findings.append({
                        "title": "CRITICAL: GraphQL Introspection Enabled",
                        "description": f"The GraphQL endpoint at `{url}` allows introspection. This enables anyone to query the entire schema and underlying data models.",
                        "severity": "high",
                        "confidence": "high",
                        "tool_source": "api_fuzzer",
                        "url": url,
                        "metadata": {"technique": "introspection"}
                    })
            except: pass

        return findings
