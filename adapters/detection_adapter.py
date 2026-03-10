import json
import hashlib
import re

from scan_engine.helpers.finding_schema import (
    normalize_finding_shape,
    merge_signal_ids,
    deep_merge_metadata,
    merge_field_sources,
)


class DetectionAdapter:
    """
    Unified DetectionAdapter layer.

    Responsibilities
    ----------------
    1. Normalize DB findings -> UI model
    2. Normalize JSON findings -> UI model
    3. Generate synthetic findings from structural data
    4. Deduplicate findings via stable ID
    5. Apply severity governance
    """

    # ------------------------------------------------------------------
    # ID GENERATION
    # ------------------------------------------------------------------

    @staticmethod
    def _make_id(*parts):
        raw = "|".join(str(p) for p in parts)
        return hashlib.sha256(raw.encode()).hexdigest()

    # ------------------------------------------------------------------
    # ADD FINDING (CORE NORMALIZER)
    # ------------------------------------------------------------------

    @staticmethod
    def _add(
        normalized,
        fid,
        title,
        severity,
        description,
        tool_source,
        confidence="medium",
        **extra,
    ):
        if not title:
            return

        title = title.strip()
        clean_title = re.sub(
            r"^(critical|high|medium|low|info|warn|warning):\s*",
            "",
            title,
            flags=re.IGNORECASE,
        ).strip()
        clean_title_lower = clean_title.lower()
        severity = (severity or "info").lower()

        if any(x in clean_title_lower for x in ["data leak", "data exposure"]):
            if any(x in clean_title_lower for x in ["email", "ip address"]):
                severity = "info"
            elif any(x in clean_title_lower for x in ["api key", "token", "secret"]):
                severity = "high"

        if "missing" in clean_title_lower and "header" in clean_title_lower:
            severity = "low"

        if (
            "probable auth bypass" in clean_title_lower
            and "token detected" in clean_title_lower
            and severity == "high"
        ):
            severity = "medium"

        if fid in normalized:
            existing = normalized[fid]
            merged_metadata = dict(existing.get("metadata") or {})
            incoming_metadata = (
                extra.get("metadata", {})
                if isinstance(extra.get("metadata", {}), dict)
                else {}
            )

            merged_metadata = deep_merge_metadata(merged_metadata, incoming_metadata)
            merged_metadata["field_sources"] = merge_field_sources(
                merged_metadata.get("field_sources"),
                incoming_metadata.get("field_sources")
                if isinstance(incoming_metadata.get("field_sources"), dict)
                else {},
            )

            existing["signal_ids"] = merge_signal_ids(
                existing.get("signal_ids"),
                extra.get("signal_ids"),
            )
            existing["metadata"] = merged_metadata
            existing["signal_count"] = len(existing["signal_ids"])
            existing["chain_length"] = (
                len(merged_metadata.get("chain", []))
                if isinstance(merged_metadata.get("chain"), list)
                else existing.get("chain_length", 0)
            )

            incoming_raw_output = extra.get("raw_output", "")
            if incoming_raw_output and incoming_raw_output not in str(existing.get("raw_output") or ""):
                existing["raw_output"] = "\n".join(
                    x for x in [existing.get("raw_output"), incoming_raw_output] if x
                )[:3000]

            incoming_evidence = extra.get("evidence", "")
            if incoming_evidence and incoming_evidence not in str(existing.get("evidence") or ""):
                existing["evidence"] = "\n".join(
                    x for x in [existing.get("evidence"), incoming_evidence] if x
                )[:3000]

            return

        # Auto-Remediation Guidance
        remediations = {
            "ssrf": "Implement a whitelist of allowed domains/IPs for outgoing requests. Nullify internal metadata IP access.",
            "lfi": "Use a whitelist for file inclusions or switch to database-driven content loading. Sanitize input paths.",
            "sqli": "Use parameterized queries or prepared statements. Avoid string concatenation for SQL.",
            "xxe": "Disable external entity resolution (DTD) in your XML parser configuration.",
            "open_redirect": "Use a whitelist of allowed redirect destinations or intermediate landing pages.",
            "nosql": "Use specialized libraries for query building; avoid passing raw objects from query strings to find() methods.",
            "secret": "Revoke the exposed credential immediately and rotate all related keys. Implement secret scanning in CI/CD."
        }
        
        remediation = extra.get("reproduction") or ""
        if not remediation:
            cat_lower = (extra.get("category") or "").lower()
            for k, v in remediations.items():
                if k in cat_lower or k in clean_title_lower:
                    remediation = v
                    break

        # Confidence Promotion for Verified findings
        if extra.get("metadata", {}).get("verified"):
            confidence = "certain"
            severity = severity if severity in ["critical", "high"] else "high"

        payload = {
            "id": str(extra.get("id", "")),
            "id_stable": fid,
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "description": description,
            "tool_source": tool_source or "unknown",
            "tool": extra.get("tool", tool_source or "unknown"),
            "target": extra.get("target", ""),
            "endpoint": extra.get("endpoint", ""),
            "parameter": extra.get("parameter", ""),
            "payload": extra.get("payload", ""),
            "request": extra.get("request", ""),
            "response": extra.get("response", ""),
            "repro_command": extra.get("repro_command", ""),
            "raw_output": extra.get("raw_output", ""),
            "screenshot_path": extra.get("screenshot_path", ""),
            "signal_ids": extra.get("signal_ids", []),
            "category": extra.get("category", ""),
            "evidence": extra.get("evidence", ""),
            "reproduction": remediation,
            "module": extra.get("module", tool_source),
            "metadata": extra.get("metadata", {}),
            "source": extra.get("source", tool_source or "unknown"),
            "created_at": extra.get("created_at", ""),
        }
        normalized[fid] = normalize_finding_shape(payload, source=tool_source)

    # ------------------------------------------------------------------
    # SYNTHESIZERS
    # ------------------------------------------------------------------

    @staticmethod
    def _synth_open_ports(recon_data, normalized):
        ports = recon_data.get("open_ports", [])

        if not ports:
            return

        lines = []

        for p in ports:
            if isinstance(p, dict):
                lines.append(
                    f"{p.get('port')}/{p.get('protocol', 'tcp')} "
                    f"{p.get('service', '?')} "
                    f"{p.get('version', '')}"
                )
            else:
                lines.append(str(p))

        fid = DetectionAdapter._make_id("open_ports", len(lines))

        DetectionAdapter._add(
            normalized,
            fid,
            title=f"Open Ports Detected ({len(lines)})",
            severity="info",
            description="\n".join(lines),
            tool_source="nmap",
            confidence="high",
            endpoint=str(ports[0].get('port', '')) if isinstance(ports[0], dict) else ""
        )

    @staticmethod
    def _synth_headers(enum_data, normalized):
        headers = enum_data.get("headers", {})

        for port, header_data in headers.items():
            if not isinstance(header_data, dict):
                continue

            missing = []

            for name, info in header_data.items():
                if isinstance(info, dict) and info.get("status") == "missing":
                    missing.append(name)

            if not missing:
                continue

            fid = DetectionAdapter._make_id("headers_missing", port)

            DetectionAdapter._add(
                normalized,
                fid,
                title=f"Missing Security Headers ({port})",
                severity="low",
                description="\n".join(missing),
                tool_source="header_audit",
                confidence="high",
                endpoint=f"port:{port}"
            )

    @staticmethod
    def _synth_js_secrets(enum_data, normalized):
        js = enum_data.get("js_secrets", {})

        for port, secrets in js.items():
            if not isinstance(secrets, list):
                continue

            for s in secrets:
                if not isinstance(s, dict):
                    continue

                typ = s.get("type", "Secret")
                match = s.get("match", "")
                
                title = s.get("title", f"Secret Found: {typ}")
                context = s.get("line_context", "")
                description = s.get("description", f"Match Preview: `{match}`\nContext: {context}")
                severity = s.get("severity", "medium")
                confidence = s.get("confidence", "medium")
                endpoint = s.get("endpoint") or f"port:{port}"

                fid = DetectionAdapter._make_id(
                    "js_secret",
                    port,
                    typ,
                    match[:40],
                )

                if typ.lower() in ["ipv4 address", "url"]:
                    severity = "info"

                DetectionAdapter._add(
                    normalized,
                    fid,
                    title=title,
                    severity=severity,
                    description=description,
                    tool_source="secret_scanner",
                    confidence=confidence,
                    endpoint=endpoint,
                )

    # ------------------------------------------------------------------
    # NEW SYNTHESIZERS
    # ------------------------------------------------------------------

    @staticmethod
    def _synth_wordpress(vuln_data, normalized):
        """Synthesize findings from vuln.wordpress dict (port → info)."""
        wp = vuln_data.get("wordpress", {})
        if not isinstance(wp, dict):
            return

        for port, info in wp.items():
            if not isinstance(info, dict):
                continue

            version = info.get("version", "Unknown")
            theme = info.get("theme", "Unknown")
            wordfence = info.get("wordfence_detected", False)
            users = info.get("users", [])
            plugins = info.get("plugins", [])
            vulns = info.get("vulns", [])

            # Main WordPress detection finding
            desc_lines = [
                f"**Version**: {version}",
                f"**Theme**: {theme}",
                f"**Wordfence WAF**: {'Detected' if wordfence else 'Not detected'}",
                f"**Enumerated Users**: {len(users)}",
                f"**Plugins**: {len(plugins)}",
            ]
            if users:
                desc_lines.append(
                    "**Users**: " + ", ".join(str(u) for u in users[:10])
                )
            if plugins:
                desc_lines.append(
                    "**Plugins**: " + ", ".join(str(p) for p in plugins[:10])
                )

            fid = DetectionAdapter._make_id("wordpress_intel", port, version)
            DetectionAdapter._add(
                normalized,
                fid,
                title=f"WordPress {version} Detected ({port})",
                severity="info",
                description="\n".join(desc_lines),
                tool_source="wpscan",
                confidence="high",
                category="wordpress",
                endpoint=f"port:{port}",
            )

            # Individual WP vulnerability findings
            if isinstance(vulns, list):
                for v in vulns:
                    if isinstance(v, dict):
                        vtitle = v.get("title", "WordPress Vulnerability")
                        vsev = v.get("severity", "medium")
                        vfid = DetectionAdapter._make_id("wp_vuln", port, vtitle)
                        DetectionAdapter._add(
                            normalized,
                            vfid,
                            title=vtitle,
                            severity=vsev,
                            description=v.get("description", ""),
                            tool_source="wpscan",
                            confidence="high",
                            category="wordpress_vuln",
                            endpoint=f"port:{port}",
                            evidence=v.get("reference", ""),
                        )

    @staticmethod
    def _synth_data_leaks(vuln_data, normalized):
        """Synthesize findings from vuln.data_leaks list of dicts."""
        leaks = vuln_data.get("data_leaks", [])
        if not isinstance(leaks, list):
            return

        for leak in leaks:
            if not isinstance(leak, dict):
                continue

            leak_type = leak.get("type", "unknown")
            count = leak.get("count", 0)
            matches = leak.get("matches", [])
            url = leak.get("url", "")

            severity = "info"
            if any(x in leak_type.lower() for x in ["token", "key", "secret", "password"]):
                severity = "medium"

            fid = DetectionAdapter._make_id("data_leak", leak_type, url)
            DetectionAdapter._add(
                normalized,
                fid,
                title=f"Data Leak: {leak_type.replace('_', ' ').title()} ({count} found)",
                severity=severity,
                description="\n".join(str(m) for m in matches[:20]),
                tool_source="data_miner",
                confidence="high",
                category="data_leak",
                endpoint=url,
            )

    @staticmethod
    def _synth_intel_vectors(intel_data, normalized):
        """Synthesize findings from intel.attack_vectors list."""
        vectors = intel_data.get("attack_vectors", [])
        if not isinstance(vectors, list):
            return

        risk_to_sev = {
            "CRITICAL": "critical",
            "HIGH": "medium",   # Vectors are tips, not confirmed vulns
            "MEDIUM": "info",
            "LOW": "info",
            "INFO": "info",
        }

        for v in vectors:
            if not isinstance(v, dict):
                continue

            name = v.get("name", "Attack Vector")
            risk = v.get("risk", "INFO").upper()
            description = v.get("description", "")
            action = v.get("action", "")
            category = v.get("category", "intel")

            severity = risk_to_sev.get(risk, "info")

            fid = DetectionAdapter._make_id("intel_vector", name, category)
            DetectionAdapter._add(
                normalized,
                fid,
                title=f"Intel: {name}",
                severity=severity,
                description=f"{description}\n\n**Recommended Action**: {action}" if action else description,
                tool_source="attack_intel",
                confidence="medium",
                category="intel_vector",
            )

    @staticmethod
    def _synth_osint_summary(osint_data, normalized):
        """Synthesize summary findings from OSINT data."""
        # Origin IPs
        origin_ips = osint_data.get("origin_ips", [])
        if isinstance(origin_ips, list):
            for entry in origin_ips:
                if isinstance(entry, dict):
                    ip = entry.get("ip", "?")
                    reason = entry.get("reason", "")
                    confidence = entry.get("confidence", "medium")
                    fid = DetectionAdapter._make_id("origin_ip", ip)
                    DetectionAdapter._add(
                        normalized,
                        fid,
                        title=f"Origin IP Detected: {ip}",
                        severity="info",
                        description=f"**Reason**: {reason}\n**Confidence**: {confidence}",
                        tool_source="osint",
                        confidence=confidence,
                        category="osint_origin",
                    )

        # Google Dorks
        dorks = osint_data.get("dorks", [])
        if isinstance(dorks, list) and len(dorks) > 0:
            dork_lines = []
            for d in dorks[:15]:
                if isinstance(d, dict):
                    dork_lines.append(f"• `{d.get('query', '?')}`")
                else:
                    dork_lines.append(f"• `{d}`")

            fid = DetectionAdapter._make_id("osint_dorks", len(dorks))
            DetectionAdapter._add(
                normalized,
                fid,
                title=f"OSINT: {len(dorks)} Google Dork Queries Available",
                severity="info",
                description="\n".join(dork_lines),
                tool_source="osint",
                confidence="medium",
                category="osint_dorks",
            )

        # Wayback / Historic URLs
        historic = osint_data.get("historic_urls", [])
        if isinstance(historic, list) and len(historic) > 50:
            fid = DetectionAdapter._make_id("osint_historic", len(historic))
            DetectionAdapter._add(
                normalized,
                fid,
                title=f"OSINT: {len(historic)} Historic Wayback URLs Discovered",
                severity="info",
                description=f"Wayback Machine returned {len(historic)} archived URLs for this target. These may reveal legacy endpoints, removed pages, or old API surfaces.",
                tool_source="osint",
                confidence="medium",
                category="osint_historic",
            )

    @staticmethod
    def _synth_cortex_recommendations(enum_data, normalized):
        """Synthesize findings from enum.derived.cortex_recommendations."""
        derived = enum_data.get("derived", {})
        if not isinstance(derived, dict):
            return
        recs = derived.get("cortex_recommendations", [])
        if not isinstance(recs, list):
            return

        for item in recs:
            if not isinstance(item, dict):
                continue

            title = item.get("title", "Recommendation")
            reason = item.get("reason", "")
            confidence = item.get("confidence", 50)
            port = item.get("port", "")
            category = item.get("category", "cortex")

            fid = DetectionAdapter._make_id("cortex_rec", title, port)
            DetectionAdapter._add(
                normalized,
                fid,
                title=f"Cortex: {title}",
                severity="info",
                description=f"{reason}" if reason else title,
                tool_source="decision_cortex",
                confidence="high" if confidence >= 70 else "medium",
                category="cortex_recommendation",
                endpoint=f"port:{port}" if port else "",
            )

    @staticmethod
    def _synth_dirbusting(dir_data, normalized):
        """Synthesize findings from dirbusting phase endpoints."""
        if not isinstance(dir_data, dict):
            return

        for tool, data in dir_data.items():
            if not isinstance(data, dict):
                continue
            endpoints = data.get("endpoints", [])
            if not isinstance(endpoints, list):
                continue
            
            for ep in endpoints:
                if not isinstance(ep, dict):
                    continue
                url = ep.get("url", "")
                status = ep.get("status", 200)
                path = ep.get("path", "")
                
                if not url: continue
                
                fid = DetectionAdapter._make_id("dirbusting", tool, url)
                DetectionAdapter._add(
                    normalized,
                    fid,
                    title=f"Directory Discovered: /{path}",
                    severity="info",
                    description=f"Endpoint discovered by {tool}: `{url}` (HTTP {status})",
                    tool_source=tool,
                    confidence="high",
                    category="dirbusting_endpoint",
                    endpoint=url,
                )

    @staticmethod
    def _synth_api_endpoints(enum_data, normalized):
        """Synthesize findings from enum.api.endpoints."""
        api = enum_data.get("api", {})
        if not isinstance(api, dict):
            return
        endpoints = api.get("endpoints", [])
        if not isinstance(endpoints, list):
            return

        sensitive_paths = {"admin", "login", "dashboard", "upload", "api", "swagger",
                          "graphql", "console", "debug", "phpmyadmin", "wp-admin",
                          "actuator", "manager", "panel"}

        for ep in endpoints:
            if not isinstance(ep, dict):
                continue

            url = ep.get("url", "")
            status = ep.get("status", 0)
            path = ep.get("path", "")

            is_sensitive = any(s in path.lower() for s in sensitive_paths)
            severity = "medium" if is_sensitive and status == 200 else "info"

            fid = DetectionAdapter._make_id("api_endpoint", url)
            DetectionAdapter._add(
                normalized,
                fid,
                title=f"API Endpoint: /{path} (HTTP {status})",
                severity=severity,
                description=f"Accessible endpoint discovered at `{url}` returned HTTP {status}.",
                tool_source="api_scanner",
                confidence="high",
                category="api_endpoint",
                endpoint=url,
            )

    @staticmethod
    def _synth_injection_points(enum_data, normalized):
        """Synthesize findings from enum.injection_points dict (port → list)."""
        injection = enum_data.get("injection_points", {})
        if not isinstance(injection, dict):
            return

        for port, points in injection.items():
            if not isinstance(points, list) or len(points) == 0:
                continue

            urls_display = "\n".join(f"• `{u}`" for u in points[:15])

            fid = DetectionAdapter._make_id("injection_points", port, len(points))
            DetectionAdapter._add(
                normalized,
                fid,
                title=f"Injection Points: {len(points)} Injectable URLs (port {port})",
                severity="info",
                description=f"Discovered {len(points)} URLs with injectable parameters:\n{urls_display}",
                tool_source="enum_seed_factory",
                confidence="medium",
                category="injection_surface",
                endpoint=f"port:{port}",
            )

    @staticmethod
    def _synth_favicon_hash(osint_data, normalized):
        """Synthesize finding from osint.favicon hash."""
        favicon = osint_data.get("favicon", {})
        if not isinstance(favicon, dict):
            return

        fav_hash = favicon.get("hash")
        if fav_hash is None:
            return

        url = favicon.get("url", "")
        shodan_query = favicon.get("shodan_query", "")

        fid = DetectionAdapter._make_id("favicon_hash", fav_hash)
        DetectionAdapter._add(
            normalized,
            fid,
            title=f"Favicon Hash: {fav_hash}",
            severity="info",
            description=f"Favicon at `{url}`\n\n**Shodan Query**: `{shodan_query}`\n\nUse this hash to discover other servers hosting the same application.",
            tool_source="favicon_scanner",
            confidence="high",
            category="osint_favicon",
            endpoint=url,
        )

    @staticmethod
    def _synth_nse_results(recon_data, normalized):
        """Synthesize findings from recon.nse_results."""
        nse = recon_data.get("nse_results", {})
        if not isinstance(nse, dict):
            return

        # Scripts that indicate actionable findings when they have output
        SEVERITY_MAP = {
            "ftp-anon": ("medium", lambda o: "allowed" in o.lower()),
            "mysql-empty-password": ("high", lambda o: "empty" in o.lower() or "root" in o.lower()),
            "smb-enum-shares": ("medium", lambda _: True),
            "smb-enum-users": ("medium", lambda _: True),
            "ssh-auth-methods": ("info", lambda _: True),
            "ssh2-enum-algos": ("info", lambda _: True),
            "http-enum": ("low", lambda _: True),
            "http-methods": ("info", lambda o: "PUT" in o or "DELETE" in o),
            "rdp-ntlm-info": ("info", lambda _: True),
            "smtp-commands": ("info", lambda _: True),
            "ssl-cert": ("info", lambda _: True),
            "ssl-enum-ciphers": ("info", lambda o: "weak" in o.lower() or "grade" in o.lower()),
            "dns-recursion": ("medium", lambda o: "enabled" in o.lower()),
        }

        for port_str, scripts in nse.items():
            if not isinstance(scripts, dict):
                continue
            port = str(port_str)

            for script_name, output in scripts.items():
                if not output or len(str(output).strip()) < 3:
                    continue

                output_str = str(output)
                severity = "info"

                if script_name in SEVERITY_MAP:
                    sev, condition = SEVERITY_MAP[script_name]
                    if condition(output_str):
                        severity = sev
                    else:
                        severity = "info"

                # Promote dangerous HTTP methods
                if script_name == "http-methods":
                    if any(m in output_str for m in ["PUT", "DELETE", "TRACE"]):
                        severity = "medium"

                fid = DetectionAdapter._make_id("nse", script_name, port)
                DetectionAdapter._add(
                    normalized,
                    fid,
                    title=f"NSE: {script_name} (port {port})",
                    severity=severity,
                    description=output_str[:2000],
                    tool_source="nse_scanner",
                    confidence="high",
                    category="nse_script",
                    endpoint=f"port:{port}",
                )

    # ------------------------------------------------------------------
    # MAIN NORMALIZER
    # ------------------------------------------------------------------

    @staticmethod
    def normalize_findings(db_findings, json_results):
        normalized = {}

        # -------------------------
        # DB FINDINGS
        # -------------------------

        for f in db_findings:
            fid = f.id_stable or str(f.id)

            DetectionAdapter._add(
                normalized,
                fid,
                title=f.title,
                severity=f.severity,
                description=f.description,
                tool_source=f.tool_source,
                confidence=f.confidence,
                id=f.id,
                request=getattr(f, "request", ""),
                response=getattr(f, "response", ""),
                repro_command=getattr(f, "repro_command", ""),
                screenshot_path=getattr(f, "screenshot_path", ""),
                target=getattr(f, "target", ""),
                endpoint=getattr(f, "endpoint", ""),
                parameter=getattr(f, "parameter", ""),
                payload=getattr(f, "payload", ""),
                raw_output=getattr(f, "raw_output", ""),
                signal_ids=getattr(f, "signal_ids", []),
                category=getattr(f, "category", ""),
                evidence=getattr(f, "evidence", ""),
                reproduction=getattr(f, "reproduction", ""),
                module=getattr(f, "module", f.tool_source),
                metadata=getattr(f, "metadata_json", {}) or {},
            )

        # -------------------------
        # JSON FINDINGS
        # -------------------------

        phases = json_results.get("phases", {}) if isinstance(json_results, dict) else {}

        for phase_name in ["vuln", "enum"]:
            phase = phases.get(phase_name, {})

            if not isinstance(phase, dict):
                continue

            for tool, findings in phase.items():
                items = findings
                if isinstance(findings, dict):
                    if "findings" in findings: items = findings["findings"]
                    elif "vulns" in findings: items = findings["vulns"]
                    elif "endpoints" in findings: items = findings["endpoints"]
                    else: items = [findings]
                
                if not isinstance(items, list):
                    continue

                for item in items:
                    if not isinstance(item, dict):
                        continue

                    fid = item.get("id_stable")
                    if not fid:
                        fid = DetectionAdapter._make_id(
                            tool,
                            item.get("title", ""),
                            item.get("endpoint", ""),
                        )

                    DetectionAdapter._add(
                        normalized,
                        fid,
                        title=item.get("title", "Finding"),
                        severity=item.get("severity", "info"),
                        description=item.get("description", ""),
                        tool_source=tool,
                        confidence=item.get("confidence", "medium"),
                        endpoint=item.get("endpoint", ""),
                        payload=item.get("payload", ""),
                        parameter=item.get("parameter", ""),
                        evidence=item.get("evidence", ""),
                        category=item.get("category", ""),
                        target=item.get("target", ""),
                        raw_output=item.get("raw_output", item.get("description", "")),
                        signal_ids=item.get("signal_ids", []),
                        module=item.get("module", tool),
                        reproduction=item.get(
                            "reproduction",
                            item.get("repro_command", ""),
                        ),
                        request=item.get("request", ""),
                        response=item.get("response", ""),
                        repro_command=item.get("repro_command", ""),
                        screenshot_path=item.get("screenshot_path", ""),
                        metadata=item.get("metadata", {}),
                    )

        # -------------------------
        # SYNTHETIC FINDINGS
        # -------------------------

        if "recon" in phases:
            DetectionAdapter._synth_open_ports(phases["recon"], normalized)
            DetectionAdapter._synth_nse_results(phases["recon"], normalized)

        if "enum" in phases:
            DetectionAdapter._synth_headers(phases["enum"], normalized)
            DetectionAdapter._synth_js_secrets(phases["enum"], normalized)

        if "vuln" in phases:
            DetectionAdapter._synth_wordpress(phases["vuln"], normalized)
            DetectionAdapter._synth_data_leaks(phases["vuln"], normalized)

        if "intel" in phases:
            DetectionAdapter._synth_intel_vectors(phases["intel"], normalized)

        if "osint" in phases:
            DetectionAdapter._synth_osint_summary(phases["osint"], normalized)
            DetectionAdapter._synth_favicon_hash(phases["osint"], normalized)

        if "enum" in phases:
            DetectionAdapter._synth_cortex_recommendations(phases["enum"], normalized)
            DetectionAdapter._synth_api_endpoints(phases["enum"], normalized)
            DetectionAdapter._synth_injection_points(phases["enum"], normalized)

        if "dirbusting" in phases:
            DetectionAdapter._synth_dirbusting(phases["dirbusting"], normalized)

        return list(normalized.values())