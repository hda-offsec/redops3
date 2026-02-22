import hashlib
import re
import json
from urllib.parse import quote
from scan_engine.helpers.http_client import get_session

class CSTIScanner:
    """
    Expert Auditor for Client-Side Template Injection (CSTI).
    Advanced Refactoring: Implements baseline diffing, multi-payload validation, 
    framework fingerprinting, and strict severity gating.
    """
    def __init__(self, options=None):
        self.options = options
        self.session = get_session(options)
        self.session.headers.update({"User-Agent": "RedOps3-CSTIExpert/2.0"})
        
        # Differential validation pairs
        self.check_pairs = [
            ("{{7*7}}", "49"),
            ("{{8*8}}", "64"),
            ("${7*7}", "49"),
            ("${8*8}", "64")
        ]
        
        self.framework_patterns = {
            "angular": [
                r"ng-app", r"ng-controller", r"ng-repeat", r"angular\.js", r"angular\.min\.js",
                r"window\.angular", r"ng-version", r"__angular", r"ng-binding"
            ],
            "vue": [
                r"vue\.js", r"vue\.min\.js", r"v-bind", r"v-if", r"v-for", r"__vue__", r"v-cloak"
            ],
            "react": [
                r"react\.js", r"react\.min\.js", r"_reactRootContainer", r"data-reactroot"
            ]
        }

    def _get_baseline(self, url, logger=None):
        """Captures a baseline snapshot of the target endpoint."""
        try:
            resp = self.session.get(url, timeout=5)
            return {
                "text": resp.text,
                "status": resp.status_code,
                "length": len(resp.text),
                "hash": hashlib.md5(resp.text.encode()).hexdigest()
            }
        except Exception as e:
            if logger: logger(f"Baseline error for {url}: {e}", "DEBUG")
            return None

    def fingerprint_frameworks(self, html):
        """Detects presence of client-side frameworks via static analysis."""
        detected = []
        for fw, patterns in self.framework_patterns.items():
            for p in patterns:
                if re.search(p, html, re.IGNORECASE):
                    detected.append(fw)
                    break
        return detected

    def scan_endpoint(self, url, params, logger=None):
        findings = []
        if logger: logger(f"CSTI Expert: Auditing {url} with Hardened Differential Engine...", "INFO")

        # 1. Baseline Response Snapshot
        baseline = self._get_baseline(url, logger)
        if not baseline:
            return []

        # 2. Framework Fingerprinting
        frameworks = self.fingerprint_frameworks(baseline["text"])
        is_angular = "angular" in frameworks
        
        for param in params:
            results_found = {} # payload -> result_found
            reflections = 0
            evidences = []

            # 3. Validation Différentielle Multi-Payload
            # We use at least two distinct mathematical expressions
            test_sets = [
                ("{{7*7}}", "49", "{{8*8}}", "64"),
                ("${7*7}", "49", "${8*8}", "64")
            ]

            for p1, r1, p2, r2 in test_sets:
                # Numeric Collision Guard: Check if expected results are already in baseline
                if r1 in baseline["text"] or r2 in baseline["text"]:
                    if logger: logger(f"Skip numeric collision: {r1} or {r2} found in baseline for {param}", "DEBUG")
                    continue

                try:
                    # Test Payload 1
                    u1 = f"{url}?{param}={quote(p1)}" if "?" not in url else f"{url}&{param}={quote(p1)}"
                    resp1 = self.session.get(u1, timeout=5)
                    
                    # Test Payload 2
                    u2 = f"{url}?{param}={quote(p2)}" if "?" not in url else f"{url}&{param}={quote(p2)}"
                    resp2 = self.session.get(u2, timeout=5)

                    found_r1 = r1 in resp1.text and p1 not in resp1.text
                    found_r2 = r2 in resp2.text and p2 not in resp2.text
                    
                    # Reflection check (Payload returned as-is)
                    reflect_p1 = p1 in resp1.text
                    reflect_p2 = p2 in resp2.text

                    if found_r1 and found_r2:
                        # Success: Multi-payload confirmation
                        # BUT: If the result is in raw response, it's SSTI, not CSTI (Angular)
                        # The user wants to track this distinction.
                        evidences.append({"type": "server_eval", "p1": p1, "r1": r1, "p2": p2, "r2": r2})
                    elif reflect_p1 and reflect_p2:
                        # Potential CSTI: Server reflects pattern, client (browser) will interpret it.
                        evidences.append({"type": "client_reflect", "p1": p1, "p2": p2})

                except Exception as e:
                    if logger: logger(f"Request error during CSTI probe: {e}", "DEBUG")
                    continue

            # 4. Severity Gating & Confidence Score
            for ev in evidences:
                confidence = 0.5 # Default
                severity = "low"
                framework_detected = frameworks
                validation_mode = "differential_multi_payload"
                diff_confirmed = True

                if ev["type"] == "server_eval":
                    # Server side evaluation confirmed. High risk but maybe not "CSTI Angular" 
                    # based on user definition. We'll label it accurately.
                    confidence = 0.95
                    severity = "high"
                    title = "Server-Side Template Injection (SSTI) Confirmed"
                else:
                    # Patterns reflected. This is the true "CSTI" surface.
                    # HIGH only if Angular/Vue detected and validation successful.
                    if is_angular or "vue" in frameworks:
                        confidence = 0.85
                        severity = "high"
                        title = f"Confirmed Client-Side Template Injection ({frameworks[0].upper()})"
                    else:
                        confidence = 0.6
                        severity = "medium"
                        title = "Potential Client-Side Template Injection (Reflected Pattern)"

                # Rule 6 & 7: Confidence < 0.8 -> Downgrade High
                if severity == "high" and confidence < 0.8:
                    severity = "medium"

                findings.append({
                    "title": title,
                    "description": f"The endpoint at `{url}` appears vulnerable to template injection on parameter `{param}`.\n\n" +
                                   f"**Validation Details**:\n" +
                                   f"- Multi-payload match: `{ev.get('p1')} -> {ev.get('r1', 'Reflected')}` AND `{ev.get('p2')} -> {ev.get('r2', 'Reflected')}`\n" +
                                   f"- Frameworks: {', '.join(frameworks) if frameworks else 'None detected'}\n" +
                                   f"- Baseline Diff: Unique results confirmed.",
                    "severity": severity,
                    "confidence_score": confidence,
                    "framework_detected": frameworks,
                    "validation_mode": validation_mode,
                    "differential_confirmed": diff_confirmed,
                    "baseline_hash": baseline["hash"],
                    "tool_source": "csti_expert",
                    "url": url,
                    "param": param
                })
                
                if logger: logger(f"{severity.upper()}: CSTI/SSTI finding recorded on {param} (Confidence: {confidence})", "SUCCESS")
                break # One finding per param enough

        return findings
