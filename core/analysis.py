from core.models import db, Finding, Suggestion, Signal
from scan_engine.helpers.finding_schema import (
    deep_merge_metadata,
    merge_field_sources,
    merge_score_factors,
)


class AnalysisEngine:
    @staticmethod
    def analyze_nmap_results(scan_id, open_ports):
        """
        Analyzes open ports and generates findings and suggestions.
        """
        finding = Finding(
            scan_id=scan_id,
            title=f"Open Ports Detected: {', '.join(str(p['port']) for p in open_ports)}",
            description=f"Nmap discovered {len(open_ports)} open ports.\nDetails: {open_ports}",
            severity="info",
            tool_source="nmap",
            confidence="high",
            category="surface",
            module="recon",
        )
        db.session.add(finding)

        for service in open_ports:
            port = service["port"]
            name = service["service_name"]
            if port in [80, 443, 8080, 8443] or "http" in name:
                SuggestionEngine.create(
                    scan_id,
                    "whatweb",
                    f"whatweb http://<target>:{port}",
                    "Web service detected. Fingerprint technologies.",
                )
                SuggestionEngine.create(
                    scan_id,
                    "gobuster",
                    f"gobuster dir -u http://<target>:{port} -w common.txt",
                    "Web service detected. Enumerate directories.",
                )
            if port == 445 or "smb" in name:
                SuggestionEngine.create(
                    scan_id,
                    "enum4linux",
                    "enum4linux -a <target>",
                    "SMB detected. Enumerate shares and users.",
                )
            if port == 22:
                SuggestionEngine.create(
                    scan_id,
                    "hydra",
                    "hydra -l root -P rockyou.txt ssh://<target>",
                    "SSH detected. Check for weak credentials (careful).",
                )

        db.session.commit()


class SuggestionEngine:
    @staticmethod
    def create(scan_id, tool, command, reason):
        s = Suggestion(
            scan_id=scan_id,
            tool_name=tool,
            command_suggestion=command,
            reason=reason,
        )
        db.session.add(s)


def run_signal_correlation(scan_id, add_finding_cb):
    """Create attack-chain findings from immutable signals without deleting originals."""
    signals = Signal.query.filter_by(scan_id=scan_id).all()
    if not signals:
        return 0

    grouped = {}
    for s in signals:
        grouped.setdefault((s.tool or "", s.type or ""), []).append(s)

    created = 0

    backup_like = grouped.get(("backup_expert", "finding"), []) + grouped.get(
        ("backup_scanner", "finding"), []
    )
    git_like = grouped.get(("git_scanner", "finding"), [])
    if backup_like and git_like:
        signal_ids = [x.id for x in backup_like[:2] + git_like[:2]]
        add_finding_cb(
            scan_id=scan_id,
            title="Attack Chain: Exposed Repository + Backup Artifacts",
            description="Detected both repository exposure and backup artifact disclosure. This chain typically enables source recovery and credential extraction.",
            severity="high",
            confidence="high",
            tool_source="correlation_engine",
            category="attack_chain",
            module="correlation",
            signal_ids=signal_ids,
            evidence="Cross-signal correlation: git exposure + backup archive exposure.",
        )
        created += 1

    js_like = grouped.get(("js_scanner", "finding"), []) + grouped.get(
        ("js_deep_scanner", "finding"), []
    )
    api_like = grouped.get(("api_expert", "finding"), []) + grouped.get(
        ("api_scanner", "finding"), []
    )
    if js_like and api_like:
        signal_ids = [x.id for x in js_like[:2] + api_like[:2]]
        add_finding_cb(
            scan_id=scan_id,
            title="Attack Chain: JavaScript Endpoint Discovery -> Hidden API Surface",
            description="JavaScript intelligence and API discovery both identified hidden endpoints, indicating a reachable but weakly documented attack surface.",
            severity="medium",
            confidence="medium",
            tool_source="correlation_engine",
            category="attack_chain",
            module="correlation",
            signal_ids=signal_ids,
            evidence="Cross-signal correlation: JavaScript endpoint extraction + API discovery.",
        )
        created += 1

    if created:
        db.session.commit()
    return created


class CortexEngine:
    """Reason over findings/signals to generate deterministic attack path intelligence."""

    @staticmethod
    def _mk_text(f):
        return (
            f"{(getattr(f, 'title', '') or '').lower()} "
            f"{(getattr(f, 'description', '') or '').lower()} "
            f"{(getattr(f, 'category', '') or '').lower()}"
        )

    @classmethod
    def derive_attack_paths(cls, findings):
        paths = []
        texts = [cls._mk_text(f) for f in findings]

        def has(pred):
            return any(pred(f, t) for f, t in zip(findings, texts))

        def add(title, description, severity="high", confidence="medium", chain=None):
            paths.append(
                {
                    "title": title,
                    "description": description,
                    "severity": severity,
                    "confidence": confidence,
                    "tool_source": "cortex_engine",
                    "module": "cortex_reasoning",
                    "category": "attack_path",
                    "metadata": {"chain": chain or []},
                }
            )

        has_auth_surface = has(
            lambda f, t: "auth" in t
            or (getattr(f, "category", "") or "") in {"authentication_surface", "auth_surface"}
        )
        has_token = has(
            lambda f, t: "token" in t
            or "jwt" in t
            or (getattr(f, "category", "") or "") in {"jwt_exposure", "token_leakage", "api_key_exposure"}
        )
        if has_auth_surface and has_token:
            add(
                "Cortex Attack Path: Auth Surface + Token Material -> Authenticated API Access",
                "Reasoning engine linked authentication surface with token leakage indicators, enabling probable authenticated API abuse path.",
                severity="high",
                confidence="high",
                chain=["auth_surface", "token_leakage", "authenticated_api_access"],
            )

        has_upload = has(
            lambda f, t: "upload" in t or (getattr(f, "category", "") or "") == "upload_surface"
        )
        has_methods = has(
            lambda f, t: "dangerous http methods" in t
            or (getattr(f, "category", "") or "") == "http_method_exposure"
        )
        if has_upload and has_methods:
            add(
                "Cortex Attack Path: Upload Surface + Dangerous Methods -> Arbitrary File Write Risk",
                "Reasoning engine correlated upload exposure and unsafe HTTP methods, producing a probable arbitrary file write/webshell route.",
                severity="high",
                confidence="high",
                chain=["upload_surface", "dangerous_http_methods", "arbitrary_file_write"],
            )

        has_ssrf = has(
            lambda f, t: "ssrf" in t
            or (getattr(f, "category", "") or "") in {"ssrf_surface", "metadata_service_exposure"}
        )
        has_metadata = has(
            lambda f, t: "169.254.169.254" in t
            or "metadata service" in t
            or (getattr(f, "category", "") or "") == "metadata_service_exposure"
        )
        if has_ssrf and has_metadata:
            add(
                "Cortex Attack Path: SSRF Surface -> Cloud Metadata Credential Theft",
                "Reasoning engine identified SSRF-capable input and metadata-service exposure signals, indicating probable cloud credential theft path.",
                severity="high",
                confidence="medium",
                chain=["ssrf_surface", "metadata_service", "credential_theft"],
            )

        has_js_route = has(
            lambda f, t: "javascript" in t
            or "hidden route" in t
            or (getattr(f, "category", "") or "") == "api_surface"
        )
        if has_js_route:
            paths.append(
                {
                    "title": "Cortex Attack Plan: Investigate JS-Derived Routes",
                    "description": "Planning layer recommends focused validation of JavaScript-derived routes, especially admin/auth paths already present in telemetry.",
                    "severity": "medium",
                    "confidence": "high",
                    "tool_source": "cortex_engine",
                    "module": "cortex_planner",
                    "category": "attack_plan",
                    "metadata": {
                        "title": "Inspect JS-derived admin route",
                        "description": "Validate authorization and hidden-route accessibility for JS-mined endpoints.",
                        "rationale": "Deterministic route intelligence from passive telemetry and API surface findings.",
                        "related_signal_ids": [],
                        "related_finding_ids": [],
                        "attack_chain": "js_routes_auth_surface",
                        "attack_priority": "medium",
                        "action_priority": 65,
                        "action_type": "guided_probe",
                        "estimated_value": "high",
                        "estimated_complexity": "medium",
                    },
                }
            )

        if has_ssrf:
            paths.append(
                {
                    "title": "Cortex Next Step: Probe SSRF Metadata Path",
                    "description": "Recommended bounded probe: validate SSRF controls against metadata service patterns using non-destructive request variants.",
                    "severity": "medium",
                    "confidence": "medium",
                    "tool_source": "cortex_engine",
                    "module": "cortex_planner",
                    "category": "next_step",
                    "metadata": {
                        "title": "Investigate SSRF against metadata service",
                        "description": "Replay safe SSRF patterns to metadata endpoints only where existing evidence indicates input control.",
                        "rationale": "SSRF and metadata-service indicators appear in findings telemetry.",
                        "related_signal_ids": [],
                        "related_finding_ids": [],
                        "endpoint": "metadata_service",
                        "attack_chain": "ssrf_to_metadata",
                        "attack_priority": "high",
                        "action_priority": 85,
                        "action_type": "guided_probe",
                        "estimated_value": "high",
                        "estimated_complexity": "medium",
                    },
                }
            )

        return paths


class RiskScoringEngine:
    """Deterministic exploit prioritization based on existing finding evidence."""

    SEVERITY_WEIGHT = {
        "critical": 1.0,
        "high": 0.8,
        "medium": 0.6,
        "low": 0.3,
        "info": 0.1,
    }
    CONFIDENCE_WEIGHT = {
        "high": 1.0,
        "certain": 1.0,
        "medium": 0.65,
        "low": 0.35,
    }

    @classmethod
    def score_finding(cls, finding, attack_graph_node_ids=None, include_factors=False):
        attack_graph_node_ids = attack_graph_node_ids or set()
        severity = cls.SEVERITY_WEIGHT.get((getattr(finding, "severity", None) or "info").lower(), 0.1)
        confidence = cls.CONFIDENCE_WEIGHT.get((getattr(finding, "confidence", None) or "medium").lower(), 0.65)
        metadata_raw = getattr(finding, "metadata_json", None)
        metadata = dict(metadata_raw) if isinstance(metadata_raw, dict) else {}

        signal_ids = getattr(finding, "signal_ids", None)
        signal_count = len(signal_ids) if isinstance(signal_ids, list) else 0
        chain = metadata.get("chain") if isinstance(metadata.get("chain"), list) else []
        try:
            chain_length = len(chain) if chain else int(metadata.get("chain_length") or 0)
        except (TypeError, ValueError):
            chain_length = len(chain) if chain else 0
        signal_weight = min(1.0, signal_count / 5.0)
        attack_path_weight = min(1.0, chain_length / 4.0)
        finding_id = getattr(finding, "id_stable", None)
        in_attack_graph = (
            1.0
            if (finding_id and f"finding:db:{finding_id}" in attack_graph_node_ids)
            else 0.0
        )

        component = str(metadata.get("component") or "").lower()
        dependency_risk = 0.0
        category = (getattr(finding, "category", None) or "").lower()
        if category in {"dependency_surface", "cve_candidate"}:
            dependency_risk = 0.8
        elif category == "tech_fingerprint":
            dependency_risk = 0.5
        if component in {"jquery", "wordpress", "apache", "nginx"}:
            dependency_risk = max(dependency_risk, 0.6)

        title = (getattr(finding, "title", None) or "")
        description = (getattr(finding, "description", None) or "")
        tool_source = getattr(finding, "tool_source", None) or ""
        validated = 1.0 if (
            metadata.get("exploit_validated") is True
            or "exploit validation" in (f"{title} {description}".lower())
            or tool_source == "exploit_validation_engine"
        ) else 0.0

        score_factors = {
            "severity_weight": round(severity * 0.35, 5),
            "confidence_weight": round(confidence * 0.20, 5),
            "signal_count_bonus": round(signal_weight * 0.15, 5),
            "chain_length_bonus": round(attack_path_weight * 0.15, 5),
            # Elevated weighting: explicit exploit validation should dominate prioritization.
            "validation_bonus": round(validated * 0.25, 5),
            "dependency_risk_bonus": round(dependency_risk * 0.03, 5),
            "attack_graph_bonus": round(in_attack_graph * 0.10, 5),
        }

        exploit_score = sum(score_factors.values()) * 100
        exploit_score = round(max(0.0, min(100.0, exploit_score)), 2)

        if exploit_score >= 80:
            risk_level = "critical"
        elif exploit_score >= 65:
            risk_level = "high"
        elif exploit_score >= 40:
            risk_level = "medium"
        else:
            risk_level = "low"

        if exploit_score >= 85 or chain_length >= 4 or (validated >= 1.0 and exploit_score >= 80):
            attack_priority = "critical"
        elif exploit_score >= 70 or chain_length >= 3:
            attack_priority = "high"
        elif exploit_score >= 45 or chain_length >= 2:
            attack_priority = "medium"
        else:
            attack_priority = "low"

        if include_factors:
            return (
                exploit_score,
                risk_level,
                attack_priority,
                chain_length,
                signal_count,
                dependency_risk,
                score_factors,
            )

        return (
            exploit_score,
            risk_level,
            attack_priority,
            chain_length,
            signal_count,
            dependency_risk,
        )


def apply_risk_scores(scan_id, graph=None):
    findings = Finding.query.filter_by(scan_id=scan_id).all()
    if not findings:
        return 0

    node_ids = set()
    if isinstance(graph, dict):
        node_ids = {
            n.get("id")
            for n in graph.get("nodes", [])
            if isinstance(n, dict) and n.get("id")
        }

    updated = 0
    for finding in findings:
        metadata = dict(finding.metadata_json) if isinstance(finding.metadata_json, dict) else {}

        (
            exploit_score,
            risk_level,
            attack_priority,
            chain_length,
            signal_count,
            dependency_risk,
            score_factors,
        ) = RiskScoringEngine.score_finding(
            finding,
            node_ids,
            include_factors=True,
        )

        chain = metadata.get("chain") if isinstance(metadata.get("chain"), list) else []
        category = (finding.category or "").lower()

        if category in {"attack_path", "attack_chain"}:
            attack_complexity = "high" if chain_length >= 4 else "medium" if chain_length >= 2 else "low"
            metadata["attack_complexity"] = attack_complexity

        metadata["attack_priority"] = attack_priority
        metadata["action_priority"] = int(exploit_score)
        metadata["action_type"] = (
            "guided_probe"
            if category in {"attack_plan", "next_step", "attack_path", "attack_chain"}
            else "triage"
        )
        metadata["estimated_value"] = "high" if exploit_score >= 70 else "medium" if exploit_score >= 40 else "low"
        metadata["estimated_complexity"] = "high" if exploit_score >= 80 else "medium" if exploit_score >= 45 else "low"
        metadata["exploit_score"] = exploit_score
        metadata["risk_level"] = risk_level
        metadata["signal_count"] = signal_count
        metadata["chain_length"] = chain_length
        metadata["dependency_risk"] = dependency_risk
        metadata["score_factors"] = merge_score_factors(
            metadata.get("score_factors"),
            score_factors,
        )
        metadata["field_sources"] = merge_field_sources(
            metadata.get("field_sources"),
            {
                "exploit_score": "risk_scoring_engine",
                "attack_priority": "risk_scoring_engine",
            },
        )

        metadata = deep_merge_metadata(
            finding.metadata_json if isinstance(finding.metadata_json, dict) else {},
            metadata,
        )
        finding.metadata_json = metadata
        updated += 1

    if updated:
        db.session.commit()
    return updated


def run_cortex_attack_reasoning(scan_id, add_finding_cb):
    findings = Finding.query.filter_by(scan_id=scan_id).all()
    if not findings:
        return 0

    paths = CortexEngine.derive_attack_paths(findings)
    if not paths:
        return 0

    created = 0
    existing_titles = {f.title for f in findings}
    for item in paths:
        if item["title"] in existing_titles:
            continue
        add_finding_cb(
            scan_id=scan_id,
            title=item["title"],
            description=item["description"],
            severity=item["severity"],
            confidence=item["confidence"],
            tool_source=item["tool_source"],
            module=item["module"],
            category=item["category"],
            metadata=item.get("metadata") or {},
            evidence=item["description"],
            reproduction="Trace prerequisite findings and validate each hop using recorded evidence and endpoints.",
        )
        created += 1

    return created
