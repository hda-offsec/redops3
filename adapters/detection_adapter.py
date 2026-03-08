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
            "reproduction": extra.get("reproduction", ""),
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

                fid = DetectionAdapter._make_id(
                    "js_secret",
                    port,
                    typ,
                    match[:40],
                )

                severity = "medium"
                if typ.lower() in ["ipv4 address", "url"]:
                    severity = "info"

                DetectionAdapter._add(
                    normalized,
                    fid,
                    title=f"Secret Found: {typ}",
                    severity=severity,
                    description=f"{match}",
                    tool_source="secret_scanner",
                    confidence="medium",
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
                if not isinstance(findings, list):
                    continue

                for item in findings:
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

        if "enum" in phases:
            DetectionAdapter._synth_headers(phases["enum"], normalized)
            DetectionAdapter._synth_js_secrets(phases["enum"], normalized)

        return list(normalized.values())