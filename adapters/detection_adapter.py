import json
import logging
import os
import re

from scan_engine.helpers.finding_schema import (
    normalize_finding_shape,
    merge_signal_ids,
    deep_merge_metadata,
    merge_field_sources,
    generate_stable_id,
)

logger = logging.getLogger(__name__)


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

    _RAW_JSON_CONTAINER_KEYS = ("findings", "vulns", "endpoints", "items")
    _OBSERVABILITY_KEYS = (
        "findings_received",
        "findings_rejected",
        "findings_exposed",
        "db_findings_received",
        "json_findings_received",
        "phases_skipped_non_mapping",
        "tool_payloads_skipped_non_list",
        "json_items_skipped_empty_dict",
        "json_items_skipped_without_content",
        "title_empty_skipped",
        "dedup_merged",
        "cortex_noise_filtered",
        "cortex_low_confidence_filtered",
    )

    # ------------------------------------------------------------------
    # ID GENERATION
    # ------------------------------------------------------------------

    @staticmethod
    def _make_id(tool, title, endpoint="", parameter="", payload="", severity="info"):
        return generate_stable_id({
            "tool_source": tool,
            "title": title,
            "endpoint": endpoint,
            "parameter": parameter,
            "payload": payload,
            "severity": severity
        })

    @staticmethod
    def _new_observability_stats():
        return {key: 0 for key in DetectionAdapter._OBSERVABILITY_KEYS}

    @staticmethod
    def _observability_debug_enabled():
        env_value = str(os.getenv("REDOPS_FINDINGS_DEBUG", "")).strip().lower()
        if env_value in {"1", "true", "yes", "on"}:
            return True
        return logger.isEnabledFor(logging.DEBUG)

    @staticmethod
    def _debug_observability_event(event, payload):
        if not DetectionAdapter._observability_debug_enabled():
            return
        serialized = {
            key: value
            for key, value in (payload.items() if isinstance(payload, dict) else [])
            if value not in (None, "", [], {})
        }
        logger.debug(
            "DetectionAdapter %s: %s",
            event,
            json.dumps(serialized, sort_keys=True, default=str),
        )

    @staticmethod
    def _log_observability_stats(stats):
        if not isinstance(stats, dict):
            return
        relevant = {key: value for key, value in stats.items() if value}
        if relevant:
            logger.debug("DetectionAdapter normalization stats: %s", json.dumps(relevant, sort_keys=True))

    @staticmethod
    def _extract_raw_items(payload):
        if isinstance(payload, dict):
            for key in DetectionAdapter._RAW_JSON_CONTAINER_KEYS:
                if key in payload:
                    return payload.get(key)
            return [payload]
        return payload

    @staticmethod
    def _looks_like_finding_candidate(item):
        if not isinstance(item, dict):
            return False
        return any(
            key in item
            for key in (
                "title",
                "description",
                "evidence",
                "raw_output",
                "severity",
                "confidence",
                "endpoint",
                "target",
                "parameter",
                "payload",
                "module",
                "category",
                "reproduction",
                "repro_command",
                "request",
                "response",
            )
        )

    @staticmethod
    def _clean_terminal_noise(value):
        if not isinstance(value, str):
            return value
        ansi_regex = re.compile(r"(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]")
        cleaned = ansi_regex.sub("", value)
        cleaned = re.sub(r"\[[0-9]{1,2}K", "", cleaned)
        cleaned = "".join(
            char for char in cleaned if char.isprintable() or char in "\n\r\t"
        )
        return cleaned.strip()

    @staticmethod
    def _derive_title(*candidates):
        for candidate in candidates:
            cleaned = DetectionAdapter._clean_terminal_noise(candidate) or ""
            if not cleaned:
                continue
            first_line = next(
                (line.strip() for line in cleaned.splitlines() if line.strip()),
                "",
            )
            if not first_line:
                continue
            first_line = re.sub(r"[`*_#>]+", " ", first_line)
            first_line = re.sub(r"\s+", " ", first_line).strip(" :-")
            if first_line:
                return first_line[:140]
        return ""

    @staticmethod
    def _sanitize_extra_fields(extra):
        sanitized = dict(extra)
        for field in ["endpoint", "target", "parameter", "payload", "raw_output"]:
            if field in sanitized:
                sanitized[field] = DetectionAdapter._clean_terminal_noise(
                    sanitized[field]
                )
        return sanitized

    @staticmethod
    def _apply_severity_governance(title, severity, metadata=None):
        clean_title = re.sub(
            r"^(critical|high|medium|low|info|warn|warning):\s*",
            "",
            title or "",
            flags=re.IGNORECASE,
        ).strip()
        clean_title_lower = clean_title.lower()
        governed_severity = (severity or "info").lower()

        if any(x in clean_title_lower for x in ["data leak", "data exposure"]):
            if any(x in clean_title_lower for x in ["email", "ip address"]):
                governed_severity = "info"
            elif any(x in clean_title_lower for x in ["api key", "token", "secret"]):
                governed_severity = "high"

        if "missing" in clean_title_lower and "header" in clean_title_lower:
            governed_severity = "low"

        if (
            "probable auth bypass" in clean_title_lower
            and "token detected" in clean_title_lower
            and governed_severity == "high"
        ):
            governed_severity = "medium"

        if isinstance(metadata, dict) and metadata.get("verified"):
            return clean_title_lower, (
                governed_severity
                if governed_severity in ["critical", "high"]
                else "high"
            ), "certain"

        return clean_title_lower, governed_severity, None

    @staticmethod
    def _merge_existing_finding(existing, extra, incoming_raw_output, incoming_evidence):
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

        if incoming_raw_output and incoming_raw_output not in str(
            existing.get("raw_output") or ""
        ):
            existing["raw_output"] = "\n".join(
                x for x in [existing.get("raw_output"), incoming_raw_output] if x
            )[:3000]

        if incoming_evidence and incoming_evidence not in str(existing.get("evidence") or ""):
            existing["evidence"] = "\n".join(
                x for x in [existing.get("evidence"), incoming_evidence] if x
            )[:3000]

    @staticmethod
    def _normalize_metadata_defaults(description, extra):
        metadata = extra.get("metadata", {}) or {}
        if not metadata.get("port_state"):
            state_match = re.search(
                r"State:\s*([a-z+|]+)",
                str(description or ""),
                re.IGNORECASE,
            )
            if state_match:
                metadata["port_state"] = state_match.group(1).lower()
            elif extra.get("category") in {"service_detection", "nse_result"}:
                metadata["port_state"] = "open"
        extra["metadata"] = metadata
        return extra

    @staticmethod
    def _default_remediation(category, clean_title_lower):
        remediations = {
            "ssrf": "Implement a whitelist of allowed domains/IPs for outgoing requests. Nullify internal metadata IP access.",
            "lfi": "Use a whitelist for file inclusions or switch to database-driven content loading. Sanitize input paths.",
            "sqli": "Use parameterized queries or prepared statements. Avoid string concatenation for SQL.",
            "xxe": "Disable external entity resolution (DTD) in your XML parser configuration.",
            "open_redirect": "Use a whitelist of allowed redirect destinations or intermediate landing pages.",
            "nosql": "Use specialized libraries for query building; avoid passing raw objects from query strings to find() methods.",
            "secret": "Revoke the exposed credential immediately and rotate all related keys. Implement secret scanning in CI/CD.",
        }
        cat_lower = (category or "").lower()
        for key, remediation in remediations.items():
            if key in cat_lower or key in clean_title_lower:
                return remediation
        return ""

    @staticmethod
    def _build_payload(
        fid,
        title,
        severity,
        description,
        tool_source,
        confidence,
        extra,
    ):
        reproduction_text = extra.get("reproduction") or extra.get("repro_command") or ""
        remediation = extra.get("remediation") or DetectionAdapter._default_remediation(
            extra.get("category", ""),
            title.lower(),
        )
        return {
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
            "reproduction": reproduction_text,
            "command": extra.get("command", ""),
            "impact": extra.get("impact", ""),
            "references": extra.get("references", []),
            "remediation": remediation,
            "module": extra.get("module", tool_source),
            "metadata": extra.get("metadata", {}),
            "source": extra.get("source", tool_source or "unknown"),
            "created_at": extra.get("created_at", ""),
        }

    @staticmethod
    def _item_missing_primary_content(item):
        return (
            not item.get("title")
            and not item.get("description")
            and not item.get("evidence")
            and not item.get("raw_output")
        )

    @staticmethod
    def _compute_json_finding_id(tool, item):
        fid = item.get("id_stable")
        if fid and len(fid) >= 32:
            return fid
        title_seed = (
            item.get("title")
            or item.get("description")
            or item.get("evidence")
            or item.get("raw_output")
            or item.get("endpoint")
            or item.get("target")
            or "Finding"
        )
        return DetectionAdapter._make_id(
            tool,
            title_seed,
            endpoint=item.get("endpoint", ""),
            parameter=item.get("parameter", ""),
            payload=item.get("payload", ""),
            severity=item.get("severity", "info"),
        )

    @staticmethod
    def _add_db_findings(normalized, stats, db_findings):
        for finding in db_findings:
            fid = finding.id_stable or str(finding.id)
            stats["findings_received"] += 1
            stats["db_findings_received"] += 1

            DetectionAdapter._add(
                normalized,
                fid,
                title=finding.title,
                severity=finding.severity,
                description=finding.description,
                tool_source=finding.tool_source,
                confidence=finding.confidence,
                id=finding.id,
                request=getattr(finding, "request", ""),
                response=getattr(finding, "response", ""),
                repro_command=getattr(finding, "repro_command", ""),
                screenshot_path=getattr(finding, "screenshot_path", ""),
                target=getattr(finding, "target", ""),
                endpoint=getattr(finding, "endpoint", ""),
                parameter=getattr(finding, "parameter", ""),
                payload=getattr(finding, "payload", ""),
                raw_output=getattr(finding, "raw_output", ""),
                signal_ids=getattr(finding, "signal_ids", []),
                category=getattr(finding, "category", ""),
                evidence=getattr(finding, "evidence", ""),
                reproduction=getattr(finding, "reproduction", ""),
                module=getattr(finding, "module", finding.tool_source),
                metadata=getattr(finding, "metadata_json", {}) or {},
                _stats=stats,
                _source_kind="db",
                _trace_context={
                    "source_kind": "db",
                    "tool": getattr(finding, "tool_source", ""),
                    "finding_id": getattr(finding, "id", None),
                },
            )

    @staticmethod
    def _add_json_findings(normalized, stats, phases):
        for phase_name, phase in phases.items():
            if not isinstance(phase, dict):
                stats["phases_skipped_non_mapping"] += 1
                continue

            for tool, findings in phase.items():
                items = DetectionAdapter._extract_raw_items(findings)
                if not isinstance(items, list):
                    stats["tool_payloads_skipped_non_list"] += 1
                    continue

                for item in items:
                    if not isinstance(item, dict):
                        continue
                    if not item:
                        stats["json_items_skipped_empty_dict"] += 1
                        continue
                    if not DetectionAdapter._looks_like_finding_candidate(item):
                        continue

                    stats["findings_received"] += 1
                    stats["json_findings_received"] += 1

                    if DetectionAdapter._item_missing_primary_content(item):
                        stats["json_items_skipped_without_content"] += 1
                        stats["findings_rejected"] += 1
                        DetectionAdapter._debug_observability_event(
                            "finding_rejected",
                            {
                                "source_kind": "json",
                                "phase": phase_name,
                                "tool": tool,
                                "reason": "missing_title_description_evidence_raw_output",
                                "endpoint": item.get("endpoint", ""),
                                "target": item.get("target", ""),
                                "parameter": item.get("parameter", ""),
                            },
                        )
                        continue

                    DetectionAdapter._add(
                        normalized,
                        DetectionAdapter._compute_json_finding_id(tool, item),
                        title=item.get("title", ""),
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
                        _stats=stats,
                        _source_kind="json",
                        _trace_context={
                            "source_kind": "json",
                            "phase": phase_name,
                            "tool": tool,
                        },
                    )

    @staticmethod
    def _synthesize_findings(phases, normalized, stats):
        synthesizers_by_phase = (
            ("recon", (DetectionAdapter._synth_open_ports, DetectionAdapter._synth_nse_results)),
            ("dns", (DetectionAdapter._synth_dns_findings, DetectionAdapter._synth_dns_security)),
            ("enum", (DetectionAdapter._synth_headers, DetectionAdapter._synth_js_secrets)),
            ("vuln", (DetectionAdapter._synth_wordpress, DetectionAdapter._synth_data_leaks, DetectionAdapter._synth_js_vulns)),
            ("osint", (DetectionAdapter._synth_osint_summary, DetectionAdapter._synth_osint_leaks, DetectionAdapter._synth_favicon_hash)),
            ("dirbusting", (DetectionAdapter._synth_dirbusting,)),
        )

        for phase_name, synthesizers in synthesizers_by_phase:
            phase_payload = phases.get(phase_name)
            if phase_payload is None:
                continue
            for synthesizer in synthesizers:
                synthesizer(phase_payload, normalized)

        if "intel" in phases:
            DetectionAdapter._synth_intel_vectors(
                phases["intel"],
                normalized,
                phases=phases,
            )

        if "enum" in phases:
            DetectionAdapter._synth_cortex_recommendations(
                phases["enum"],
                normalized,
                _stats=stats,
            )
            DetectionAdapter._synth_api_endpoints(phases["enum"], normalized)
            DetectionAdapter._synth_injection_points(phases["enum"], normalized)

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
        _stats=None,
        _source_kind="unknown",
        _trace_context=None,
        **extra,
    ):
        title = DetectionAdapter._clean_terminal_noise(title) or ""
        description = DetectionAdapter._clean_terminal_noise(description) or ""

        trace_context = dict(_trace_context) if isinstance(_trace_context, dict) else {}
        extra = DetectionAdapter._sanitize_extra_fields(extra)

        if not title:
            title = DetectionAdapter._derive_title(
                description,
                extra.get("evidence", ""),
                extra.get("raw_output", ""),
                extra.get("endpoint", ""),
                extra.get("target", ""),
            )
        if not title:
            if isinstance(_stats, dict):
                _stats["title_empty_skipped"] += 1
                _stats["findings_rejected"] += 1
            DetectionAdapter._debug_observability_event(
                "finding_rejected",
                {
                    **trace_context,
                    "reason": "missing_title_after_derivation",
                    "tool_source": tool_source,
                    "severity": severity,
                    "endpoint": extra.get("endpoint", ""),
                    "target": extra.get("target", ""),
                },
            )
            return

        clean_title_lower, severity, confidence_override = DetectionAdapter._apply_severity_governance(
            title,
            severity,
            extra.get("metadata"),
        )
        if confidence_override:
            confidence = confidence_override

        if fid in normalized:
            if isinstance(_stats, dict):
                _stats["dedup_merged"] += 1
            existing = normalized[fid]
            DetectionAdapter._debug_observability_event(
                "finding_merged",
                {
                    **trace_context,
                    "id_stable": fid,
                    "tool_source": tool_source,
                    "title": title or existing.get("title", ""),
                    "endpoint": extra.get("endpoint", "") or existing.get("endpoint", ""),
                    "parameter": extra.get("parameter", "") or existing.get("parameter", ""),
                },
            )
            incoming_raw_output = extra.get("raw_output", "")
            incoming_evidence = extra.get("evidence", "")
            DetectionAdapter._merge_existing_finding(
                existing,
                extra,
                incoming_raw_output,
                incoming_evidence,
            )
            return

        extra = DetectionAdapter._normalize_metadata_defaults(description, extra)
        payload = DetectionAdapter._build_payload(
            fid,
            title,
            severity,
            description,
            tool_source,
            confidence,
            extra,
        )
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
                title=f"Missing Security Headers (port {port})",
                severity="low",
                description="\n".join(missing),
                tool_source="header_audit",
                confidence="high",
                endpoint=""
            )

    @staticmethod
    def _synth_js_secrets(enum_data, normalized):
        js = enum_data.get("js_secrets", {})

        for port, secrets_raw in js.items():
            # Handle both formats:
            #   - flat list: [{type, match, line_context, ...}, ...]
            #   - dict keyed by URL: {url: [{type, match, ...}, ...]}
            if isinstance(secrets_raw, dict):
                # JS Expert format: {url: [secrets]}
                items_iter = []
                for url_key, url_secrets in secrets_raw.items():
                    if isinstance(url_secrets, list):
                        for s in url_secrets:
                            if isinstance(s, dict):
                                s = dict(s)  # copy
                                s.setdefault('endpoint', url_key)
                                items_iter.append(s)
            elif isinstance(secrets_raw, list):
                items_iter = secrets_raw
            else:
                continue

            for s in items_iter:
                if not isinstance(s, dict):
                    continue

                typ = s.get("type", "Secret")
                match = s.get("match", "")

                title = s.get("title", f"Secret Found: {typ}")
                context = s.get("line_context", "")
                description = s.get("description", f"Match Preview: `{match}`\nContext: {context}")
                severity = s.get("severity", "medium")
                confidence = s.get("confidence", "medium")
                # Only use endpoint if it's a real URL, never use synthetic port: values
                endpoint = s.get("endpoint", "")
                if endpoint.startswith("port:"):
                    endpoint = ""

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
                f"### WordPress Environment Intel",
                f"**Version**: `{version}`",
                f"**Theme**: `{theme}`",
                f"**Wordfence WAF**: `{'PROTECTED' if wordfence else 'NOT DETECTED'}`",
                f"**Total Plugins**: `{len(plugins)}`",
                f"**Total Users**: `{len(users)}`",
                "\n#### Identified Plugins & Versions",
            ]
            
            if plugins:
                for p in plugins:
                    if isinstance(p, dict):
                        name = p.get("slug", p.get("name", "Unknown"))
                        ver = p.get("version", "Unknown")
                        desc_lines.append(f"• **{name}** (v{ver})")
                    else:
                        desc_lines.append(f"• {p}")
            else:
                desc_lines.append("_No plugins identified._")

            if users:
                desc_lines.append("\n#### Enumerated Users")
                user_names = []
                for u in users:
                    if isinstance(u, dict):
                        user_names.append(f"`{u.get('name', 'unknown')}`")
                    else:
                        user_names.append(f"`{u}`")
                desc_lines.append(", ".join(user_names))

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
                endpoint="",
                repro_command=f"wpscan --url {info.get('url', 'http://TARGET')} --enumerate p,t,u --disable-tls-checks",
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
                            endpoint="",
                            evidence=v.get("reference", ""),
                            repro_command=f"# Refer to: {v.get('reference', 'CVE details')}",
                            references=[v.get("reference")] if v.get("reference") else [],
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
                category="intelligence",
                endpoint=url,
                repro_command=f"curl -ik {url}" if url else "",
            )

    @staticmethod
    def _synth_intel_vectors(intel_data, normalized, phases=None):
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
            version = v.get("service_version") or v.get("matched_version")
            port = v.get("port")
 
            severity = risk_to_sev.get(risk, "info")
            
            # Use metadata to store structured lineage
            metadata = {
                "version": version,
                "port": port,
                "vector_score": v.get("score"),
                "matched_rule": v.get("matched_version"),
                "suggested_action": action
            }
 
            # Screenshot association
            screenshot = None
            if phases and "recon" in phases and port:
                recon = phases["recon"]
                open_ports = recon.get("open_ports", [])
                for p in open_ports:
                    if p.get("port") == port and p.get("screenshot_path"):
                        screenshot = p.get("screenshot_path")
                        break
 
            fid = DetectionAdapter._make_id("intel_vector", f"Intel: {name}", endpoint=f"port:{port}" if port else "", severity=severity)
            DetectionAdapter._add(
                normalized,
                fid,
                title=f"Intel: {name}",
                severity=severity,
                description=f"{description}\n\n**Recommended Action**: {action}" if action else description,
                tool_source="attack_intel",
                confidence="medium",
                category="intel_vector",
                reproduction=action, # Mapping action to reproduction command
                repro_command=action,
                endpoint="",
                metadata=metadata,
                raw_output=f"Vector matched for service version: {version}\nRule: {name}\nAction: {action}",
                evidence=description,
                screenshot_path=screenshot
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
        if isinstance(historic, list) and len(historic) > 0:
            historic_count = len(historic)
            confidence = "medium" if historic_count >= 25 else "low"
            fid = DetectionAdapter._make_id("osint_historic", len(historic))
            DetectionAdapter._add(
                normalized,
                fid,
                title=f"OSINT: {historic_count} Historic Wayback URLs Discovered",
                severity="info",
                description=(
                    f"Wayback Machine returned {historic_count} archived URLs for this target. "
                    "These may reveal legacy endpoints, removed pages, or old API surfaces."
                ),
                tool_source="osint",
                confidence=confidence,
                category="osint_historic",
            )

    # Cortex recommendations that are generic/unconditional (triggered for ALL HTTP ports).
    # These create noise without adding signal — filtered to avoid false brief pollution.
    _CORTEX_NOISE_PREFIXES = (
        "virtual host brute",
        "waf & ips behavioral",
        "waf fingerprint",
        "h2c smuggling",
    )

    @staticmethod
    def _synth_cortex_recommendations(enum_data, normalized, _stats=None):
        """Synthesize findings from enum.derived.cortex_recommendations.

        Filters out generic unconditional recommendations (noise) and clearly labels
        the remaining ones as Cortex suggestions, not confirmed findings.
        """
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
            rec_id = item.get("id", "")

            # Skip generic noise recommendations that fire unconditionally on every HTTP port
            title_lower = title.lower()
            if (
                any(title_lower.startswith(prefix) for prefix in DetectionAdapter._CORTEX_NOISE_PREFIXES)
                and not reason
            ):
                if isinstance(_stats, dict):
                    _stats["cortex_noise_filtered"] += 1
                continue

            # Skip low-confidence suggestions (< 65) when no concrete signal is in the reason
            if confidence < 65:
                if isinstance(_stats, dict):
                    _stats["cortex_low_confidence_filtered"] += 1
                continue

            port_label = f" (port {port})" if port else ""
            port_note = f"\n\n> **Port**: `{port}`" if port else ""

            description = (
                f"**🔎 Cortex Suggestion** — *This is an automated scan recommendation, not a confirmed finding.*\n\n"
                f"{reason}{port_note}\n\n"
                f"**Confidence**: {confidence}%  \n"
                f"**Category**: `{category}`"
            )
            metadata = item.get("metadata", {}) if isinstance(item.get("metadata"), dict) else {}
            if item.get("family"):
                metadata["family"] = item.get("family")
            if isinstance(item.get("reason_tags"), list):
                metadata["reason_tags"] = [str(tag) for tag in item.get("reason_tags") if str(tag).strip()]
            if isinstance(item.get("trigger_signals"), list):
                metadata["trigger_signals"] = [str(signal) for signal in item.get("trigger_signals") if str(signal).strip()]
            if isinstance(item.get("evidence_sources"), list):
                metadata["evidence_sources"] = [str(source) for source in item.get("evidence_sources") if str(source).strip()]

            fid = DetectionAdapter._make_id("cortex_rec", rec_id or title, port)
            DetectionAdapter._add(
                normalized,
                fid,
                title=f"Cortex: {title}",
                severity="info",
                description=description,
                tool_source="decision_cortex",
                confidence="high" if confidence >= 80 else "medium",
                category="cortex_recommendation",
                endpoint="",  # Never inject synthetic port: values
                repro_command="",  # No repro command — these are suggestions, not proved findings
                metadata=metadata,
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
                    category="endpoint",
                    endpoint=url,
                    repro_command=f"curl -ik {url}",
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
                repro_command=f"curl -ik {url}",
            )

    @staticmethod
    def _synth_injection_points(enum_data, normalized):
        """Synthesize findings from enum.injection_points dict (port → list)."""
        injection = enum_data.get("injection_points", {})
        seed_meta = enum_data.get("seed_meta", {})
        if not isinstance(injection, dict):
            return

        for port, points in injection.items():
            if not isinstance(points, list) or len(points) == 0:
                continue
            
            # Map by classification
            port_meta = seed_meta.get(str(port), {})
            by_class = {
                "candidate_injection_surface": [],
                "legitimate_framework_parameter": [],
                "parameterized_asset": []
            }
            
            for url in points:
                meta = port_meta.get(url, {})
                cls = meta.get("classification")
                
                # Fallback classification if missing
                if not cls:
                    u_low = url.lower()
                    if any(x in u_low for x in [".js?", ".css?", ".png?", ".jpg?", ".jpeg?", ".gif?", ".svg?", ".ico?"]):
                        cls = "parameterized_asset"
                    elif any(k in u_low for k in ["?ver=", "&ver=", "redirect_to=", "reauth=", "wp_lang="]):
                        cls = "legitimate_framework_parameter"
                    else:
                        cls = "candidate_injection_surface"
                
                if cls in by_class:
                    by_class[cls].append(url)
                else:
                    by_class["candidate_injection_surface"].append(url)

            # 1. Main Candidate Surface Finding
            candidates = by_class["candidate_injection_surface"]
            if candidates:
                urls_display = "\n".join(f"• `{u}`" for u in candidates[:10])
                fid = DetectionAdapter._make_id("injection_points_candidate", port, len(candidates))
                DetectionAdapter._add(
                    normalized,
                    fid,
                    title=f"Injection Points: {len(candidates)} Candidate Endpoints (port {port})",
                    severity="info",
                    description=f"Discovered {len(candidates)} URLs with high-potential input parameters:\n{urls_display}" + (f"\n...and {len(candidates)-10} more" if len(candidates) > 10 else ""),
                    tool_source="enum_seed_factory",
                    confidence="medium",
                    category="injection_surface",
                    endpoint="",
                    metadata={"classification": "candidate"},
                    repro_command=f"# Use burp or ffuf to fuzz parameters for these URLs:\n# {candidates[0]}",
                )

            # 2. Framework/Asset Surface (Lower Priority)
            others = by_class["legitimate_framework_parameter"] + by_class["parameterized_asset"]
            if others:
                fid = DetectionAdapter._make_id("injection_points_other", port, len(others))
                DetectionAdapter._add(
                    normalized,
                    fid,
                    title=f"Discovered Low-Risk Parameters ({len(others)}) (port {port})",
                    severity="info",
                    description=f"Identified {len(others)} parameterized endpoints classified as low-risk (framework/static assets). Example: `{others[0]}`",
                    tool_source="enum_seed_factory",
                    confidence="low",
                    category="parameterized_surface",
                    endpoint="",
                    metadata={"classification": "low_risk"}
                )

    @staticmethod
    def _synth_js_vulns(vuln_data, normalized):
        """Synthesize findings from vuln.js_vulns (port → list)."""
        js_vulns = vuln_data.get("js_vulns", {})
        if not isinstance(js_vulns, dict):
            return

        for port, vulns in js_vulns.items():
            if not isinstance(vulns, list):
                continue

            for v in vulns:
                if not isinstance(v, dict):
                    continue

                title = v.get("title", "JS Vulnerability")
                desc = v.get("description", "")
                sev = v.get("severity", "medium")
                tool = v.get("tool_source", "js_vuln_audit")
                endpoint = v.get("endpoint") or v.get("target") or ""

                fid = DetectionAdapter._make_id(tool, title, endpoint=endpoint, severity=sev)
                DetectionAdapter._add(
                    normalized,
                    fid,
                    title=title,
                    severity=sev,
                    description=desc,
                    tool_source=tool,
                    confidence="medium",
                    category="vulnerability",
                    endpoint=endpoint,
                    repro_command=f"curl -ik {endpoint}" if endpoint.startswith("http") else "",
                )

    @staticmethod
    def _synth_dns_findings(dns_data, normalized):
        """Synthesize findings from dns phase data (subdomains, records)."""
        subdomains = dns_data.get("subdomains", [])
        if isinstance(subdomains, list) and subdomains:
            fid = DetectionAdapter._make_id("dns_enum", f"Subdomains Discovered ({len(subdomains)})")
            DetectionAdapter._add(
                normalized,
                fid,
                title=f"Subdomains Discovered ({len(subdomains)})",
                severity="info",
                description=f"DNS enumeration found {len(subdomains)} subdomains: " + ", ".join(str(s) for s in subdomains[:10]) + ("..." if len(subdomains) > 10 else ""),
                tool_source="dns_enum",
                confidence="high",
                category="recon_dns"
            )

        records = dns_data.get("records", [])
        if isinstance(records, list) and records:
            fid = DetectionAdapter._make_id("dns_enum", f"DNS Records ({len(records)})")
            DetectionAdapter._add(
                normalized,
                fid,
                title=f"DNS Records ({len(records)})",
                severity="info",
                description="\n".join([f"• {r.get('type','?')}: {r.get('value','')}" for r in records[:20] if isinstance(r, dict)]),
                tool_source="dns_enum",
                confidence="high",
                category="dns_intelligence"
            )

    @staticmethod
    def _synth_dns_security(dns_data, normalized):
        """Synthesize findings from dns.security analysis (SPF/DMARC/MX/CDN)."""
        sec = dns_data.get("security", {})
        if not isinstance(sec, dict):
            return

        # 1. SPF / DMARC Intelligence
        spf = sec.get("spf", {})
        dmarc = sec.get("dmarc", {})
        
        if spf.get("present") or dmarc.get("present"):
            desc = f"**SPF Policy**: {spf.get('policy', 'N/A')} ({spf.get('rating', 'Unknown')})\n"
            desc += f"**DMARC Policy**: {dmarc.get('policy', 'N/A')} ({dmarc.get('rating', 'Unknown')})"
            
            fid = DetectionAdapter._make_id("dns_security_policy", desc[:50])
            DetectionAdapter._add(
                normalized,
                fid,
                title="DNS Security Policy (SPF/DMARC) Analysis",
                severity="info" if spf.get("rating") == "Secure" and dmarc.get("rating") == "Secure" else "low",
                description=desc,
                tool_source="dns_analyzer",
                confidence="high",
                category="dns_intelligence"
            )

        # 2. Takeovers
        takeovers = sec.get("takeovers", [])
        if takeovers:
            desc = "Potential subdomain takeover vulnerabilities detected:\n"
            for t in takeovers:
                desc += f"• `{t.get('alias')}` pointing to `{t.get('target')}`\n"
            
            fid = DetectionAdapter._make_id("dns_takeover_potential", len(takeovers))
            DetectionAdapter._add(
                normalized,
                fid,
                title=f"Potential Subdomain Takeover ({len(takeovers)})",
                severity="high",
                description=desc,
                tool_source="dns_analyzer",
                confidence="medium",
                category="dns_vulnerability"
            )

        # 3. CDN / Infrastructure
        cdns = sec.get("cdn", [])
        if cdns:
            desc = "Frontline infrastructure detected via DNS:\n" + "\n".join(f"• `{c}`" for c in cdns)
            fid = DetectionAdapter._make_id("dns_infra_intel", len(cdns))
            DetectionAdapter._add(
                normalized,
                fid,
                title="Infrastructure Discovery (CDN/Cloud)",
                severity="info",
                description=desc,
                tool_source="dns_analyzer",
                confidence="high",
                category="dns_intelligence"
            )

    @staticmethod
    def _synth_osint_leaks(osint_data, normalized):
        """Synthesize findings from OSINT leaks (emails, github)."""
        emails = osint_data.get("emails", [])
        if isinstance(emails, list) and emails:
            email_list = emails if isinstance(emails[0], str) else [e.get("email", "") for e in emails]
            fid = DetectionAdapter._make_id("osint", f"Exposed Email Addresses ({len(emails)})")
            DetectionAdapter._add(
                normalized,
                fid,
                title=f"OSINT: Exposed Email Addresses ({len(emails)})",
                severity="info",
                description="The following email addresses were discovered in public records or leaks:\n" + "\n".join(f"• {e}" for e in email_list[:20]),
                tool_source="osint",
                confidence="medium",
                category="osint_email"
            )

        github = osint_data.get("github", [])
        if isinstance(github, list) and github:
            fid = DetectionAdapter._make_id("osint", f"GitHub Code Exposure ({len(github)} results)")
            DetectionAdapter._add(
                normalized,
                fid,
                title=f"OSINT: GitHub Code Exposure ({len(github)} results)",
                severity="low",
                description=f"GitHub search identified {len(github)} potential code or secret exposures related to the target domain.",
                tool_source="osint",
                confidence="medium",
                category="osint_github"
            )

        cloud = osint_data.get("cloud", [])
        if isinstance(cloud, list) and cloud:
            fid = DetectionAdapter._make_id("osint", f"Cloud Assets Discovered ({len(cloud)})")
            DetectionAdapter._add(
                normalized,
                fid,
                title=f"OSINT: Cloud Assets Discovered ({len(cloud)})",
                severity="info",
                description="The following cloud assets/buckets were identified:\n" + "\n".join(f"• {c}" for c in cloud[:20]),
                tool_source="osint",
                confidence="medium",
                category="osint_cloud"
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
                    category="recon",
                    endpoint="",
                    repro_command=f"nmap -sV -p {port} --script {script_name} TARGET",
                )

    # ------------------------------------------------------------------
    # MAIN NORMALIZER
    # ------------------------------------------------------------------

    @staticmethod
    def normalize_findings(db_findings, json_results, return_stats=False):
        normalized = {}
        stats = DetectionAdapter._new_observability_stats()
        phases = json_results.get("phases", {}) if isinstance(json_results, dict) else {}
        DetectionAdapter._add_db_findings(normalized, stats, db_findings)
        DetectionAdapter._add_json_findings(normalized, stats, phases)
        DetectionAdapter._synthesize_findings(phases, normalized, stats)

        findings = list(normalized.values())
        stats["findings_exposed"] = len(findings)
        DetectionAdapter._log_observability_stats(stats)
        if return_stats:
            return findings, stats
        return findings
