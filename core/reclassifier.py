import json
import re
from typing import List, Dict, Any, Tuple, Optional
from core.models import Finding, db
from core.evidence import EvidenceModel, EvidenceLevel, EvidenceProof, StackContext, compute_body_hash

class PostDetectionReclassifier:
    """
    Evidence-driven validation layer that:
    1) Prevents CRITICAL classification without proof.
    2) Avoids premature stack attribution.
    3) Deduplicates findings deterministically.
    """
    
    def __init__(self, scan_id: int):
        self.scan_id = scan_id

    def process(self):
        """Main entry point to reclassify and deduplicate a scan's findings."""
        findings = Finding.query.filter_by(scan_id=self.scan_id).all()
        if not findings:
            return

        enriched = self._enrich_and_reclassify(findings)
        final_findings = self._deduplicate(enriched)
        self._persist_changes(final_findings, findings)

    def _enrich_and_reclassify(self, findings: List[Finding]) -> List[Tuple[Finding, EvidenceModel]]:
        enriched_list = []
        for f in findings:
            evidence = EvidenceModel()
            self._apply_rules(f, evidence)
            enriched_list.append((f, evidence))
        return enriched_list

    def _apply_rules(self, f: Finding, ev: EvidenceModel):
        title_lower = f.title.lower() if f.title else ""
        desc_lower = f.description.lower() if f.description else ""
        tool = f.tool_source.lower() if f.tool_source else ""
        req = f.request or ""
        res = f.response or ""
        repro = f.repro_command or ""
        
        # 1) SSTI Handling
        if "ssti" in title_lower or "template injection" in title_lower:
            self._handle_ssti(f, ev, req, res, repro)
            
        # 2) WAF/ACL Bypass via headers
        elif "bypass" in title_lower and ("waf" in title_lower or "acl" in title_lower or "403" in title_lower):
            self._handle_waf_bypass(f, ev, req, res)
            
        # 3) Sensitive File (wp-config.php)
        elif "wp-config" in title_lower or "sensitive file" in title_lower:
            self._handle_sensitive_file(f, ev, req, res)
            
        # 4) CFIDE/administrator
        elif "cfide" in title_lower or "coldfusion" in title_lower:
            self._handle_cfide(f, ev, req, res)
            
        # 5) IP Leak
        elif "ip leak" in title_lower or "internal ip" in title_lower:
            self._handle_ip_leak(f, ev, req, res)
            
        # 6) Correlation Engine Hygiene (V12)
        elif tool == "correlation_engine":
            self._handle_correlation_hygiene(f, ev)
            
        # 7) Deserialization
        elif "deserialization" in title_lower or "node-serialize" in title_lower:
            self._handle_deserialization(f, ev)

        # 8) Decision Cortex (Suggestions)
        elif tool == "decision_cortex" or "cortex" in tool:
            self._handle_cortex_suggestion(f, ev)

        # 9) Generic Secret Cleanup
        elif "secret" in title_lower and "generic" in title_lower:
            self._handle_generic_secret(f, ev, res)
            
        else:
            # Default fallback for unhandled types
            if f.severity.lower() == "critical":
                # Demote unknown criticals if no strong evidence parsing exists yet
                f.severity = "high"
                ev.verification_required = True
                ev.level = EvidenceLevel.PROBABLE

        # 10) Global Endpoint Sanity Check (V12)
        endpoint = str(f.endpoint or "").lower()
        target = str(f.target or "").lower()
        if not endpoint or endpoint.startswith("port:") or not target or target.startswith("port:"):
            # Only demote if BOTH carry no real address info
            has_no_addr = (not endpoint or endpoint.startswith("port:")) and (not target or target.startswith("port:"))
            if has_no_addr:
                if f.severity.lower() in ["critical", "high"]:
                    f.severity = "info"
                    f.description = (f.description or "") + "\n\n[Reclassifier] Demoted: No target URL or endpoint captured (contextless port reference); finding is tactical debris."
                    ev.level = EvidenceLevel.HEURISTIC

    def _handle_ssti(self, f: Finding, ev: EvidenceModel, req: str, res: str, repro: str):
        # Current logic: '7*7=49' alone shouldn't be CRITICAL
        # We look for distinct engine signatures in the response or multiple probes
        ev.verification_required = True
        ev.level = EvidenceLevel.PROBABLE
        
        # Check if response actually evaluated the math
        # It's hard to definitively know how many distinct probes succeeded from a single finding string
        # unless the tool outputs it. Nuclei often outputs a single matched template.
        # We will downgrade to HIGH/PROBABLE by default.
        has_engine_sig = re.search(r'(freemarker|velocity|jinja2|twig|smarty|mako)', res, re.IGNORECASE)
        multiple_evals = res.count("49") > 1 or res.count("111111111") > 0 # Heuristic for multiple distinct payloads
        
        if has_engine_sig or multiple_evals:
            ev.level = EvidenceLevel.CONFIRMED
            ev.verification_required = False
            # Can keep CRITICAL if confirmed
        else:
            # Cap severity
            if f.severity.lower() == "critical":
                f.severity = "high"
            # Strip specific engine claims if unconfirmed
            f.title = re.sub(r'\b(freemarker|velocity|jinja2|twig|smarty|mako)\b', 'UNKNOWN_ENGINE', f.title, flags=re.IGNORECASE)
            f.description = (f.description or "") + "\n\n[Reclassifier] Potential SSTI — requires manual confirmation."


    def _extract_status(self, http_text: str) -> Optional[int]:
        if not http_text: return None
        match = re.search(r'^HTTP/1\.[01]\s+(\d{3})', http_text.lstrip())
        return int(match.group(1)) if match else None

    def _extract_body(self, http_text: str) -> str:
        if not http_text: return ""
        parts = http_text.split('\r\n\r\n', 1)
        if len(parts) == 2:
            return parts[1]
        parts = http_text.split('\n\n', 1)
        return parts[1] if len(parts) == 2 else http_text

    def _handle_waf_bypass(self, f: Finding, ev: EvidenceModel, req: str, res: str):
        # We need status before and status after. Often Katana/Nuclei just give the "after" response.
        # If we only have the "after" response, and it's a 403, it's not a bypass.
        status_after = self._extract_status(res)
        body_after = self._extract_body(res)
        
        ev.proof.status_after = status_after
        ev.proof.body_hash_after = compute_body_hash(body_after)
        
        # If the bypass response is still a 401/403/block page, downgrade severely
        is_blocked = status_after in [401, 403, 406] or re.search(r'(cloudflare|imperva|sucuri|forbidden|access denied)', body_after, re.IGNORECASE)
        
        if is_blocked or (status_after is not None and status_after >= 400):
            f.severity = "info"
            ev.level = EvidenceLevel.HEURISTIC
            f.description = (f.description or "") + "\n\n[Reclassifier] Header accepted; no authorization change proven (still blocked)."
        else:
            # It's a 200/302. Were we blocked before? We don't always have the 'before' request.
            # Assume probable bypass, but cap at HIGH unless we have a definitive protected body marker.
            protected_marker = re.search(r'(admin|dashboard|user|welcome|logout|settings)', body_after, re.IGNORECASE)
            if protected_marker and status_after == 200:
                ev.level = EvidenceLevel.CONFIRMED
                ev.proof.markers.append(protected_marker.group(1) if protected_marker.groups() else protected_marker.group(0))
                # keep original severity (likely critical/high)
            else:
                ev.level = EvidenceLevel.PROBABLE
                ev.verification_required = True
                if f.severity.lower() == "critical":
                    f.severity = "high"

    def _handle_sensitive_file(self, f: Finding, ev: EvidenceModel, req: str, res: str):
        status = self._extract_status(res)
        body = self._extract_body(res)
        
        ev.proof.status_after = status
        
        if status in [403, 401, 404]:
            f.severity = "info"
            ev.level = EvidenceLevel.HEURISTIC
            f.description = (f.description or "") + "\n\n[Reclassifier] Direct access blocked or not found."
            return

        db_markers = re.findall(r'(DB_NAME|DB_USER|AUTH_KEY|DB_PASSWORD|spring\.datasource|password=)', body, re.IGNORECASE)
        if status == 200 and db_markers:
            ev.level = EvidenceLevel.CONFIRMED
            ev.proof.markers = db_markers
            f.severity = "critical" # Confirm extreme impact
        else:
            f.severity = "medium" if f.severity.lower() in ["high", "critical"] else f.severity
            ev.level = EvidenceLevel.PROBABLE
            ev.verification_required = True
            f.description = (f.description or "") + "\n\n[Reclassifier] File reachable, but no sensitive content signatures validated."

    def _handle_cfide(self, f: Finding, ev: EvidenceModel, req: str, res: str):
        status = self._extract_status(res)
        body = self._extract_body(res)
        
        has_admin_title = re.search(r'<title>.*ColdFusion.*Administrator.*</title>', body, re.IGNORECASE)
        has_cf_asset = re.search(r'(cfide/scripts/|cf_scripts)', body, re.IGNORECASE)
        
        conditions_met = sum([
            1 if status == 200 else 0,
            1 if has_admin_title else 0,
            1 if has_cf_asset else 0
        ])
        
        if conditions_met >= 2:
            ev.level = EvidenceLevel.CONFIRMED
            f.severity = "medium" # CFIDE alone isn't critical unless RCE is found, usually Medium
        else:
            f.severity = "info"
            ev.level = EvidenceLevel.HEURISTIC
            f.description = (f.description or "") + "\n\n[Reclassifier] Path probe; signature not confirmed."

    def _handle_ip_leak(self, f: Finding, ev: EvidenceModel, req: str, res: str):
        body = self._extract_body(res)
        
        # Find all IPs in the body
        ips = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', body)
        
        def is_private(ip):
            parts = [int(p) for p in ip.split('.')]
            return parts[0] == 10 or \
                   (parts[0] == 172 and 16 <= parts[1] <= 31) or \
                   (parts[0] == 192 and parts[1] == 168)
        
        leaks_private = any(is_private(ip) for ip in ips)
        context_secret = re.search(r'(password|secret|token|key|config)=', body, re.IGNORECASE)
        
        if leaks_private or context_secret:
            ev.level = EvidenceLevel.CONFIRMED
            # Keep original severity (usually medium/high)
        else:
            f.severity = "info"
            ev.level = EvidenceLevel.HEURISTIC
            f.description = (f.description or "") + "\n\n[Reclassifier] Public IP banner only."

    def _handle_cortex_suggestion(self, f: Finding, ev: EvidenceModel):
        f.severity = "info"
        f.confidence = "medium"
        ev.level = EvidenceLevel.HEURISTIC
        ev.verification_required = True
        
        if "[cortex" not in f.title.lower():
            f.title = f"[Cortex Hypothèse] {f.title}"
        
        f.description = (f.description or "") + "\n\n[Reclassifier] Categorized as automated attack surface reasoning. This is NOT a confirmed vulnerability."

    def _handle_generic_secret(self, f: Finding, ev: EvidenceModel, res: str):
        # Many generic secrets are just placeholders in HTML, e.g. placeholder="password"
        # We look for a real string in the response that doesn't look like a placeholder
        body = self._extract_body(res).lower()
        # Heuristic: if it's "password":"Password" or placeholder="password" - it's noise
        is_placeholder = re.search(r'(placeholder|label|title|value|id|name)["\']?\s*[=:]\s*["\']?password["\']?', body)
        
        if is_placeholder:
            f.severity = "info"
            ev.level = EvidenceLevel.HEURISTIC
            f.description = (f.description or "") + "\n\n[Reclassifier] Demoted: Secret match appears to be a UX placeholder or label, not a live credential."
        else:
            # Check for high-entropy matches
            ev.level = EvidenceLevel.PROBABLE
            # Keep original severity (often low/medium)

    def _handle_deserialization(self, f: Finding, ev: EvidenceModel):
        desc = (f.description or "").lower()
        title = (f.title or "").lower()
        
        # Check if it's just timing-based
        is_timing = "baseline" in desc and "attack" in desc and "sleep" in desc
        has_callback = any(x in desc for x in ["callback", "oast", "dns", "ping", "nslookup", "curl", "wget"])
        
        if is_timing and not has_callback:
            # Cap severity and confidence for unvalidated timing findings
            if f.severity.lower() in ["critical", "high"]:
                f.severity = "medium"
            
            f.confidence = "low"
            
            if "suspected" not in title and "hypothesis" not in title:
                f.title = f"Suspected Deserialization: {f.title} (Timing Only)"
            
            ev.level = EvidenceLevel.HEURISTIC
            ev.verification_required = True
            f.description = (f.description or "") + "\n\n[Reclassifier] Demoted: Purely timing-based detection without OAST/Callback proof."
            
            # Integrate state signals for UI
            meta = (f.metadata_json or {}) if isinstance(f.metadata_json, dict) else {}
            f.metadata_json = {**meta, "result_state": "hypothesis", "validation_status": "not_run"}
        
        elif not has_callback and f.severity.lower() == "critical":
            # Even if it's not timing, if it's a claim of critical without callback evidence
            f.severity = "high"
            ev.level = EvidenceLevel.PROBABLE
            ev.verification_required = True

    def _handle_correlation_hygiene(self, f: Finding, ev: EvidenceModel):
        title_lower = f.title.lower() if f.title else ""
        desc_lower = f.description.lower() if f.description else ""
        endpoint_lower = (f.endpoint or "").lower()
        
        # WP Exclusions matching
        is_wp_noise = any(x in endpoint_lower for x in ["robots.txt", "wp-login.php", "admin-ajax.php", "admin-post.php", "reauth="]) or \
                      any(x in desc_lower for x in ["robots.txt", "wp-login.php", "admin-ajax.php", "reauth="])
        
        has_critical_claim = "critical" in f.severity.lower() or "privileged surface" in title_lower or "api key exposure" in title_lower
        
        # If it's a critical attack chain but linked to standard WP assets with no proof
        if has_critical_claim and is_wp_noise:
            # Check if there's any 'CONFIRMED' marker in description or signals
            # Since correlation engine findings are consolidated, we look for explicit success markers
            is_proven = "SUCCESS" in desc_payload if (desc_payload := (f.description or "")) else False
            
            if not is_proven:
                f.severity = "low"
                if "Candidate" not in f.title:
                    f.title = f"Candidate Correlation: {f.title} (Unvalidated)"
                f.description = (f.description or "") + "\n\n[Reclassifier] Demoted: WordPress administrative surfaces discovered but no valid secret/access proven."
                ev.level = EvidenceLevel.HEURISTIC
                ev.verification_required = True
        
        # Label all unverified chains
        if f.severity.lower() in ["high", "critical"] and "verified" not in str(f.metadata_json or ""):
             ev.verification_required = True
             if "candidate" not in f.title.lower():
                 f.title = f"Hypothesis: {f.title}"

    def _deduplicate(self, enriched: List[Tuple[Finding, EvidenceModel]]) -> List[Finding]:
        # signature -> list of (Finding, Evidence)
        buckets: Dict[str, List[Tuple[Finding, EvidenceModel]]] = {}
        
        for f, ev in enriched:
            # Deterministic key: type (title heuristic), endpoint (target_identifier/request host), param/normalized body hash
            title_base = re.sub(r'[^a-zA-Z0-9]', '', f.title.lower())[:30]
            
            # Try to grab host/endpoint from request
            endpoint = ""
            if f.request:
                host_match = re.search(r'Host:\s*([^\r\n]+)', f.request, re.IGNORECASE)
                path_match = re.search(r'^[A-Z]+\s+([^\s\?]+)', f.request)
                if host_match: endpoint += host_match.group(1)
                if path_match: endpoint += path_match.group(1)
            
            if not endpoint:
                # fallback to title words
                endpoint = title_base
                
            # Evidence signature
            sig = ev.proof.body_hash_after or str(ev.proof.status_after or "")
            
            key = f"{title_base}_{endpoint}_{sig}"
            buckets.setdefault(key, []).append((f, ev))
            
        final_findings = []
        for key, group in buckets.items():
            # Sort by severity (critical > high > medium > low > info) and then by evidence level
            sev_rank = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}
            lvl_rank = {EvidenceLevel.CONFIRMED: 3, EvidenceLevel.PROBABLE: 2, EvidenceLevel.HEURISTIC: 1}
            
            group.sort(key=lambda item: (sev_rank.get(item[0].severity.lower(), 0), lvl_rank.get(item[1].level, 0)), reverse=True)
            
            best_f, best_ev = group[0]
            
            # Merge context if multiple
            if len(group) > 1:
                best_f.description = (best_f.description or "") + f"\n\n[Reclassifier] Deduplicated {len(group)-1} similar occurrences."
                # Append Evidence JSON
                
            # Serialize EvidenceModel to description as JSON so UI/reports can read it without schema changes
            ev_json = json.dumps({"_evidence_model": best_ev.to_dict()}, indent=2)
            best_f.description = (best_f.description or "") + f"\n\n```json\n{ev_json}\n```"
            
            final_findings.append(best_f)
            
        return final_findings

    def _persist_changes(self, final_findings: List[Finding], original_findings: List[Finding]):
        final_ids = {f.id for f in final_findings}
        
        try:
            for f in original_findings:
                if f.id not in final_ids:
                    db.session.delete(f)
                else:
                    # SQLAlchemy tracks changes automatically, just making sure it's in session
                    db.session.add(f)
            db.session.commit()
            print(f"[Reclassifier] Preserved {len(final_findings)} unique, reclassified findings.")
        except Exception as e:
            print(f"[Reclassifier] DB Persistence failed: {e}")
            db.session.rollback()
