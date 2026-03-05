import json
import hashlib
import re


class DetectionAdapter:
    """
    Unified DetectionAdapter layer (V7 — Full Surface).
    Responsibilities:
    1. Normalize DB Finding -> UI model
    2. Normalize JSON findings -> UI model (ALL vuln/enum phase lists)
    3. Synthesize findings from structural data (WhatWeb, Headers, WAF, DNS, JS Secrets)
    4. Deduplicate via id_stable
    5. Merge severity + confidence safely
    6. Preserve original engine metadata
    """

    @staticmethod
    def _make_id(*parts):
        """Deterministic stable ID from arbitrary components."""
        raw = "|".join(str(p) for p in parts)
        return hashlib.sha256(raw.encode()).hexdigest()

    @staticmethod
    def _add(normalized, fid, title, severity, description, tool_source, confidence="medium", **extra):
        """Helper to add a finding with V10 governance and robust deduplication."""
        if not title:
            return

        # 1. Clean and Normalize title for dedup
        title = title.strip()
        # Strip legacy "HIGH: " prefixes for cleaner matching
        clean_title = re.sub(r'^(critical|high|medium|low|info|warn|warning):\s*', '', title, flags=re.IGNORECASE).strip()
        clean_title_lower = clean_title.lower()
        severity = (severity or "info").lower()

        # 2. V10 Governance: Retroactive severity correction (Fixes legacy scan data)
        # Data leaks of public/non-sensitive data -> INFO
        if any(x in clean_title_lower for x in ['data leak', 'data exposure', 'exposure:']):
            if any(x in clean_title_lower for x in ['email', 'ip_address', 'ip address']):
                severity = 'info'
            elif any(x in clean_title_lower for x in ['api_key', 'token', 'secret', 'jwt', 'private_key']):
                severity = 'high'
        
        # Missing headers -> LOW
        if 'missing' in clean_title_lower and 'header' in clean_title_lower:
            severity = 'low'
            
        # Auth Bypass (Token only) -> MEDIUM
        if 'probable auth bypass' in clean_title_lower and 'token detected' in clean_title_lower:
            if severity == 'high':
                severity = 'medium'

        # 3. Deduplication check
        if fid in normalized:
            return

        # 4. Final storage
        normalized[fid] = {
            'id': str(extra.get('id', '')),
            'id_stable': fid,
            'title': title, # Keep original display title
            'severity': severity,
            'confidence': confidence,
            'description': description,
            'tool_source': tool_source or 'unknown',
            'request': extra.get('request', ''),
            'response': extra.get('response', ''),
            'repro_command': extra.get('repro_command', ''),
            'screenshot_path': extra.get('screenshot_path', ''),
            'target': extra.get('target', ''),
            'endpoint': extra.get('endpoint', ''),
            'parameter': extra.get('parameter', ''),
            'payload': extra.get('payload', ''),
            'raw_output': extra.get('raw_output', ''),
            'signal_ids': extra.get('signal_ids', []),
            'category': extra.get('category', ''),
        }

    # ------------------------------------------------------------------
    # MAIN ENTRY POINT
    # ------------------------------------------------------------------

    @staticmethod
    # ------------------------------------------------------------------
    # SYNTHESIZERS: Convert structural data into actionable findings
    # ------------------------------------------------------------------

    @staticmethod
    def _synth_whatweb(enum_data, normalized):
        """Convert WhatWeb technology fingerprints into detection findings."""
        ww = enum_data.get('whatweb', {})
        techs = ww.get('technologies', {})
        summary = ww.get('summary', {})

        for port, tech_list in techs.items():
            if not tech_list:
                continue
            # Build a consolidated tech finding per port
            tech_str = ", ".join(tech_list)
            fid = DetectionAdapter._make_id("whatweb", port, tech_str)
            desc = f"WhatWeb identified the following technologies on port {port}:\n"
            for t in tech_list:
                desc += f"  • {t}\n"
            
            raw_line = summary.get(str(port), "")
            if raw_line:
                desc += f"\nRaw fingerprint:\n{raw_line.strip()}"

            DetectionAdapter._add(
                normalized, fid,
                title=f"Technology Fingerprint (Port {port})",
                severity="info",
                description=desc,
                tool_source="whatweb",
                confidence="high"
            )

    @staticmethod
    def _synth_headers(enum_data, normalized):
        """V10: Convert missing security headers into LOW hardening findings."""
        headers = enum_data.get('headers', {})
        for port, header_data in headers.items():
            if not isinstance(header_data, dict):
                continue
            missing = []
            for header_name, info in header_data.items():
                if not isinstance(info, dict):
                    continue
                status = info.get('status', '')
                if status == 'missing':
                    missing.append(header_name)
            
            if missing:
                header_list = "\n".join(f"  • {h}" for h in missing)
                fid = DetectionAdapter._make_id("header_summary", port)
                DetectionAdapter._add(
                    normalized, fid,
                    title=f"Missing Security Headers ({port})",
                    severity="low",
                    description=(
                        f"The following security headers are not configured on port {port}:\n\n"
                        f"{header_list}\n\n"
                        f"These are hardening recommendations, not exploitable vulnerabilities."
                    ),
                    tool_source="header_audit",
                    confidence="high"
                )

    @staticmethod
    def _synth_waf(enum_data, normalized):
        """Convert WAF detection into a finding."""
        waf = enum_data.get('waf', {})
        for port, waf_str in waf.items():
            if not waf_str or not isinstance(waf_str, str):
                continue
            # Strip ANSI escape codes
            clean = re.sub(r'\x1b\[[0-9;]*m', '', waf_str).strip()
            if not clean:
                continue
            fid = DetectionAdapter._make_id("waf_detected", port, clean)
            DetectionAdapter._add(
                normalized, fid,
                title=f"WAF/CDN Detected (Port {port}): {clean.split('WAF')[0].strip() if 'WAF' in clean else clean}",
                severity="info",
                description=f"A Web Application Firewall or CDN was detected on port {port}:\n`{clean}`\n\nThis may impact scan accuracy and indicates perimeter protection.",
                tool_source="wafw00f",
                confidence="high"
            )

    @staticmethod
    def _synth_js_secrets(enum_data, normalized):
        """Convert JS secrets into findings."""
        js = enum_data.get('js_secrets', {})
        for port, secrets in js.items():
            if not isinstance(secrets, list):
                continue
            for s in secrets:
                if not isinstance(s, dict):
                    continue
                stype = s.get('type', 'Unknown')
                match = s.get('match', '')
                context = s.get('context', '')
                source = s.get('source', '')
                
                fid = DetectionAdapter._make_id("js_secret", port, stype, match[:100])
                DetectionAdapter._add(
                    normalized, fid,
                    title=f"Secret Found: {stype}",
                    severity="info" if stype in ["IPv4 Address", "Exposed URL"] else "medium",
                    description=(
                        f"Discovered '{stype}' in '{source or f'Port {port}'}'.\n"
                        f"Match Preview: `{match[:200]}`\n"
                        f"Confidence: {s.get('confidence', 'Medium')} ({s.get('validation', 'Pattern Match')})\n"
                        f"Context: {context[:300] if context else 'N/A'}"
                    ),
                    tool_source="secret_scanner",
                    confidence=s.get('confidence', 'medium').lower() if isinstance(s.get('confidence'), str) else 'medium'
                )

    @staticmethod
    def _synth_dns_security(dns_data, normalized):
        """Convert DNS security analysis into findings."""
        security = dns_data.get('security', {})
        
        # SPF
        spf = security.get('spf', {})
        if isinstance(spf, dict) and not spf.get('present', True):
            fid = DetectionAdapter._make_id("dns_spf_missing")
            DetectionAdapter._add(
                normalized, fid,
                title="Missing SPF Record",
                severity="medium",
                description="The domain has no SPF record. This is a configuration issue that may allow email spoofing.",
                tool_source="dns_security",
                confidence="high"
            )
        
        # DMARC
        dmarc = security.get('dmarc', {})
        if isinstance(dmarc, dict) and not dmarc.get('present', True):
            fid = DetectionAdapter._make_id("dns_dmarc_missing")
            DetectionAdapter._add(
                normalized, fid,
                title="Missing DMARC Record",
                severity="medium",
                description="The domain has no DMARC record. This prevents enforcement of SPF/DKIM policies.",
                tool_source="dns_security",
                confidence="high"
            )
        
        # Subdomain Takeovers
        takeovers = security.get('takeovers', [])
        for t in takeovers:
            if isinstance(t, dict):
                fid = DetectionAdapter._make_id("takeover", t.get('subdomain', ''))
                DetectionAdapter._add(
                    normalized, fid,
                    title=f"CRITICAL: Subdomain Takeover Possible — {t.get('subdomain', '')}",
                    severity="critical",
                    description=f"Subdomain `{t.get('subdomain')}` points to `{t.get('cname', '')}` which may be unclaimed.",
                    tool_source="takeover_scanner",
                    confidence="high"
                )

    @staticmethod
    def _synth_open_ports(recon_data, normalized):
        """Convert open ports into an informational finding."""
        ports = recon_data.get('open_ports', [])
        if not ports:
            return
        port_lines = []
        for p in ports:
            if isinstance(p, dict):
                port_lines.append(f"  • {p.get('port')}/{p.get('protocol', 'tcp')} — {p.get('service', '?')} ({p.get('version', 'N/A')})")
            elif isinstance(p, (int, str)):
                port_lines.append(f"  • {p}")
        
        fid = DetectionAdapter._make_id("open_ports", len(ports))
        DetectionAdapter._add(
            normalized, fid,
            title=f"Open Ports Detected ({len(ports)})",
            severity="info",
            description="Port scan identified the following open services:\n" + "\n".join(port_lines),
            tool_source="nmap",
            confidence="high"
        )

    @staticmethod
    def normalize_findings(db_findings, json_results):
        print("[V10_RESTORE] detection_adapter synthesizing findings...")
        normalized = {}

        # 1. Normalize DB Findings (highest priority)
        # Sort by severity to ensure highest priority ones are processed first? 
        # Actually DB order by ID desc is fine.
        for f in db_findings:
            fid = f.id_stable or str(f.id)
            DetectionAdapter._add(
                normalized, fid,
                title=f.title,
                severity=f.severity,
                description=f.description,
                tool_source=f.tool_source,
                confidence=f.confidence,
                id=f.id,
                request=f.request,
                response=f.response,
                repro_command=f.repro_command,
                screenshot_path=f.screenshot_path,
                target=f.target,
                endpoint=f.endpoint,
                parameter=f.parameter,
                payload=f.payload,
                raw_output=f.raw_output,
                signal_ids=f.signal_ids or [],
                category=f.category
            )

        # 2. Normalize JSON findings (from Vuln and Enum phases — list-based data)
        # Skip keys that are structural/config, not finding lists
        STRUCTURAL_KEYS = {
            'whatweb', 'headers', 'katana', 'derived', 'derived_endpoints',
            'mutation_strategy', 'targets', 'injection_points', 'normalized',
            'seed_meta', 'attack_profile', 'waf', 'api', 'arjun',
            'wordpress', 'tech', 'js_secrets', 'data_leaks', 'logic_assault',
            'waf_bypass', 'acl_bypass', 'container_exposure', 'websocket',
            'surface_mapping', 'enterprise', 'jwt', 'oauth', 'nosql',
            'cache', 'upload', 'business_logic', 'ssrf_deep', 'infra_exposure',
            'shadow_hunter', 'csti', 'metadata', 'java_rce', 'h2c_smuggler'
        }

        phases_to_check = []
        if json_results and 'phases' in json_results:
            if 'vuln' in json_results['phases']:
                phases_to_check.append(json_results['phases']['vuln'])
            if 'enum' in json_results['phases']:
                phases_to_check.append(json_results['phases']['enum'])

        for phase in phases_to_check:
            for tool, findings_data in phase.items():
                if tool in STRUCTURAL_KEYS:
                    continue

                findings_list = []
                if isinstance(findings_data, list):
                    findings_list = findings_data
                elif isinstance(findings_data, dict) and 'findings' in findings_data:
                    findings_list = findings_data['findings']

                for item in findings_list:
                    if not isinstance(item, dict):
                        continue

                    fid = item.get('id_stable') or str(item.get('id', ''))
                    if not fid and item.get('title'):
                        fid = f"h-{tool}-{hash(item.get('title'))}"

                    if not fid:
                        continue

                    title = item.get('name') or item.get('title') or "Untitled JSON Finding"
                    
                    DetectionAdapter._add(
                        normalized, fid,
                        title=title,
                        severity=item.get('severity', 'info'),
                        description=item.get('description', ''),
                        tool_source=item.get('tool_source', tool),
                        confidence=item.get('confidence', 'medium'),
                        id=item.get('id', ''),
                        request=item.get('request', ''),
                        response=item.get('response', ''),
                        repro_command=item.get('curl-command', '') or item.get('repro_command', ''),
                        screenshot_path=item.get('screenshot_path', ''),
                        target=item.get('target', item.get('url', '')),
                        endpoint=item.get('endpoint', item.get('url', '')),
                        parameter=item.get('parameter', ''),
                        payload=item.get('payload', ''),
                        raw_output=item.get('raw_output', ''),
                        signal_ids=item.get('signal_ids', []),
                        category=item.get('category', ''),
                    )

        # 3. SYNTHESIZE findings from structural data
        if json_results and 'phases' in json_results:
            phases = json_results['phases']

            # Recon phase
            if 'recon' in phases:
                DetectionAdapter._synth_open_ports(phases['recon'], normalized)

            # Enum phase
            if 'enum' in phases:
                DetectionAdapter._synth_whatweb(phases['enum'], normalized)
                DetectionAdapter._synth_headers(phases['enum'], normalized)
                DetectionAdapter._synth_waf(phases['enum'], normalized)
                DetectionAdapter._synth_js_secrets(phases['enum'], normalized)

            # DNS phase
            if 'dns' in phases:
                DetectionAdapter._synth_dns_security(phases['dns'], normalized)

            # Vuln phase — WordPress
            if 'vuln' in phases:
                DetectionAdapter._synth_wordpress(phases['vuln'], normalized)

        print(f"[INTEL_RESTORE] merged JSON + DB findings. Total detections: {len(normalized)}")
        return list(normalized.values())

    # ------------------------------------------------------------------
    # WORDPRESS SYNTHESIZER
    # ------------------------------------------------------------------

    @staticmethod
    def _synth_wordpress(vuln_data, normalized):
        """Convert WordPress intelligence (WPScan) into granular findings."""
        wp = vuln_data.get('wordpress', {})
        if not wp or not isinstance(wp, dict):
            return

        for port, data in wp.items():
            if not isinstance(data, dict):
                continue

            version = data.get('version', 'Unknown')
            theme = data.get('theme', 'Unknown')
            users = data.get('users', [])
            plugins = data.get('plugins', [])
            vulns = data.get('vulns', [])
            wordfence = data.get('wordfence_detected', False)

            # Skip empty port data
            if version == 'Unknown' and theme == 'Unknown' and not users and not plugins:
                continue

            # --- 1. WordPress Version ---
            if version and version != 'Unknown':
                fid = DetectionAdapter._make_id("wp_version", port, version)
                DetectionAdapter._add(
                    normalized, fid,
                    title=f"WordPress {version} Detected (Port {port})",
                    severity="info",
                    description=(
                        f"WordPress version **{version}** identified on port {port}.\n\n"
                        f"**Recommendation**: Verify this is the latest stable release. "
                        f"Outdated WordPress installations are frequently targeted by automated exploit kits."
                    ),
                    tool_source="wpscan",
                    confidence="high",
                    repro_command=f"wpscan --url http://TARGET:{port}/ --enumerate vp,vt,u"
                )

            # --- 2. Theme Detection ---
            if theme and theme != 'Unknown':
                fid = DetectionAdapter._make_id("wp_theme", port, theme)
                DetectionAdapter._add(
                    normalized, fid,
                    title=f"WordPress Theme: {theme} (Port {port})",
                    severity="info",
                    description=f"Active WordPress theme identified: **{theme}** on port {port}.",
                    tool_source="wpscan",
                    confidence="high"
                )

            # --- 3. Enumerated Users ---
            if users:
                user_lines = []
                for u in users:
                    if isinstance(u, dict):
                        user_lines.append(f"  • **{u.get('name', '?')}** (ID: {u.get('id', '?')})")
                    elif isinstance(u, str):
                        user_lines.append(f"  • **{u}**")

                fid = DetectionAdapter._make_id("wp_users", port, len(users))
                DetectionAdapter._add(
                    normalized, fid,
                    title=f"WordPress Users Enumerated ({len(users)}) — Port {port}",
                    severity="medium",
                    description=(
                        f"WPScan successfully enumerated **{len(users)}** WordPress user(s) on port {port}:\n\n"
                        + "\n".join(user_lines) + "\n\n"
                        f"**Impact**: Enumerated usernames enable targeted brute-force and phishing attacks.\n"
                        f"**Recommendation**: Disable user enumeration via REST API and author archives."
                    ),
                    tool_source="wpscan",
                    confidence="high",
                    repro_command=f"wpscan --url http://TARGET:{port}/ --enumerate u"
                )

            # --- 4. Plugins ---
            for p in plugins:
                if not isinstance(p, dict):
                    continue
                slug = p.get('slug', 'unknown')
                pver = p.get('version', 'Unknown')
                latest = p.get('latest_version', '')
                location = p.get('location', '')
                p_vulns = p.get('vulns', [])

                outdated = latest and pver != 'Unknown' and latest != pver
                has_vulns = bool(p_vulns)

                sev = "info"
                if has_vulns:
                    sev = "high"
                elif outdated:
                    sev = "medium"

                desc = f"Plugin **{slug}** v{pver} detected on port {port}."
                if location:
                    desc += f"\nLocation: `{location}`"
                if outdated:
                    desc += f"\n\n⚠️ **Outdated**: Current v{pver} → Latest v{latest}"
                if has_vulns:
                    desc += "\n\n**Known Vulnerabilities**:"
                    for v in p_vulns:
                        if isinstance(v, dict):
                            desc += f"\n  • {v.get('title', v.get('raw_title', 'Unknown'))}"
                            if v.get('fixed_in'):
                                desc += f" (Fix: {v['fixed_in']})"

                fid = DetectionAdapter._make_id("wp_plugin", port, slug, pver)
                DetectionAdapter._add(
                    normalized, fid,
                    title=f"WP Plugin: {slug} v{pver} (Port {port})",
                    severity=sev,
                    description=desc,
                    tool_source="wpscan",
                    confidence="high"
                )

            # --- 5. WordPress-Level Vulnerabilities ---
            for v in vulns:
                if not isinstance(v, dict):
                    continue
                vtitle = v.get('title', v.get('raw_title', 'Unknown Vulnerability'))
                component = v.get('component', 'WordPress Core')
                vtype = v.get('type', 'Vulnerability')

                fid = DetectionAdapter._make_id("wp_vuln", port, vtitle)
                DetectionAdapter._add(
                    normalized, fid,
                    title=f"WP Vulnerability: {vtitle}",
                    severity="high",
                    description=(
                        f"**{vtype}** detected in **{component}** on port {port}.\n\n"
                        f"Title: {vtitle}\n"
                        f"Fixed In: {v.get('fixed_in', 'N/A')}"
                    ),
                    tool_source="wpscan",
                    confidence="high"
                )

            # --- 6. Wordfence Detection ---
            if wordfence:
                fid = DetectionAdapter._make_id("wp_wordfence", port)
                DetectionAdapter._add(
                    normalized, fid,
                    title=f"Wordfence WAF Active (Port {port})",
                    severity="info",
                    description=(
                        f"Wordfence Security plugin detected on port {port}.\n"
                        f"This may limit scan accuracy and indicates active perimeter defense."
                    ),
                    tool_source="wpscan",
                    confidence="high"
                )
