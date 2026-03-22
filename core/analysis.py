from typing import Any, Dict, List, Sequence, Set, Tuple

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

    CATEGORY_SORT = {
        "attack_path": 0,
        "attack_plan": 1,
        "next_step": 2,
    }
    SEVERITY_SORT = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0,
    }
    CONFIDENCE_SORT = {
        "high": 3,
        "certain": 3,
        "medium": 2,
        "low": 1,
    }

    @staticmethod
    def _mk_text(f):
        return (
            f"{(getattr(f, 'title', '') or '').lower()} "
            f"{(getattr(f, 'description', '') or '').lower()} "
            f"{(getattr(f, 'category', '') or '').lower()}"
        )

    @staticmethod
    def _metadata_dict(finding):
        metadata = getattr(finding, "metadata_json", None)
        return dict(metadata) if isinstance(metadata, dict) else {}

    @classmethod
    def _finding_entry(cls, finding):
        text = cls._mk_text(finding)
        category = (getattr(finding, "category", "") or "").lower()
        markers: Set[str] = set()

        def mark(marker, condition):
            if condition:
                markers.add(marker)

        mark(
            "auth_surface",
            "auth" in text
            or category in {"authentication_surface", "auth_surface"},
        )
        mark(
            "token_surface",
            "token" in text
            or "jwt" in text
            or category in {"api_key_exposure", "jwt_exposure", "secret_exposure", "token_leakage"},
        )
        mark(
            "upload_surface",
            "upload" in text or category == "upload_surface",
        )
        mark(
            "dangerous_http_methods",
            "dangerous http methods" in text or category == "http_method_exposure",
        )
        mark(
            "ssrf_surface",
            "ssrf" in text or category in {"metadata_service_exposure", "ssrf_surface"},
        )
        mark(
            "metadata_service",
            "169.254.169.254" in text
            or "metadata service" in text
            or category == "metadata_service_exposure",
        )
        mark(
            "javascript_surface",
            "javascript" in text
            or "hidden route" in text
            or category in {"api_surface", "hidden_route", "internal_api", "js_intelligence"},
        )
        mark(
            "api_surface",
            "api" in text
            or "graphql" in text
            or category in {"api_surface", "graphql", "hidden_route", "internal_api"},
        )
        mark(
            "graphql_surface",
            "graphql" in text or category == "graphql",
        )
        mark(
            "oauth_surface",
            any(token in text for token in ("oauth", "oidc", "openid", "callback", "authorize")),
        )
        mark(
            "object_reference_surface",
            any(token in text for token in ("bola", "idor", "object access", "object reference", "owner_id", "account_id", "tenant_id", "user_id")),
        )
        mark(
            "admin_surface",
            any(token in text for token in ("admin", "dashboard", "internal", "manage", "swagger", "debug")),
        )

        signal_ids_raw = getattr(finding, "signal_ids", None)
        signal_ids = sorted({int(item) for item in signal_ids_raw if isinstance(item, int)}) if isinstance(signal_ids_raw, list) else []

        return {
            "finding": finding,
            "id": getattr(finding, "id", None),
            "title": getattr(finding, "title", "") or "",
            "category": category,
            "text": text,
            "markers": markers,
            "signal_ids": signal_ids,
            "metadata": cls._metadata_dict(finding),
        }

    @staticmethod
    def _available_markers(entries: Sequence[Dict[str, Any]]) -> Set[str]:
        markers: Set[str] = set()
        for entry in entries:
            markers.update(entry.get("markers", set()))
        return markers

    @classmethod
    def _matching_entries(
        cls,
        entries: Sequence[Dict[str, Any]],
        *,
        required_all: Sequence[str],
        required_any: Sequence[str] = (),
    ) -> List[Dict[str, Any]]:
        available = cls._available_markers(entries)
        if not set(required_all).issubset(available):
            return []
        if required_any and not (set(required_any) & available):
            return []

        relevant_markers = set(required_all).union(required_any)
        relevant = [entry for entry in entries if entry.get("markers", set()) & relevant_markers]
        return sorted(
            relevant,
            key=lambda entry: (
                str(entry.get("category") or ""),
                str(entry.get("title") or ""),
                int(entry.get("id") or 0),
            ),
        )

    @classmethod
    def _build_metadata(
        cls,
        *,
        description: str,
        related_entries: Sequence[Dict[str, Any]],
        chain: Sequence[str],
        reason_tags: Sequence[str],
        metadata_extra: Dict[str, Any] = None,
        likely_next_action: str = "",
    ) -> Dict[str, Any]:
        metadata = dict(metadata_extra or {})
        related_finding_ids = sorted({entry["id"] for entry in related_entries if isinstance(entry.get("id"), int)})
        related_signal_ids = sorted({signal_id for entry in related_entries for signal_id in entry.get("signal_ids", [])})
        trigger_titles = sorted({str(entry.get("title") or "") for entry in related_entries if str(entry.get("title") or "").strip()})
        trigger_categories = sorted({str(entry.get("category") or "") for entry in related_entries if str(entry.get("category") or "").strip()})

        metadata["chain"] = list(chain)
        metadata["reason_tags"] = sorted(set(metadata.get("reason_tags", [])).union(reason_tags))
        metadata["trigger_titles"] = trigger_titles[:12]
        metadata["trigger_categories"] = trigger_categories
        metadata["related_finding_ids"] = related_finding_ids
        metadata["related_signal_ids"] = related_signal_ids
        metadata["chain_explanation"] = {
            "reason": description,
            "source_categories": trigger_categories,
            "related_signal_ids": related_signal_ids,
            "related_finding_ids": related_finding_ids,
            "likely_next_action": likely_next_action or description,
        }
        metadata["field_sources"] = merge_field_sources(
            metadata.get("field_sources"),
            {
                "chain": "cortex_engine",
                "chain_explanation": "cortex_engine",
                "related_finding_ids": "cortex_engine",
                "related_signal_ids": "cortex_engine",
            },
        )
        return metadata

    @classmethod
    def _build_path(
        cls,
        *,
        title: str,
        description: str,
        severity: str,
        confidence: str,
        category: str,
        module: str,
        chain: Sequence[str],
        reason_tags: Sequence[str],
        related_entries: Sequence[Dict[str, Any]],
        metadata_extra: Dict[str, Any] = None,
        likely_next_action: str = "",
    ) -> Dict[str, Any]:
        return {
            "title": title,
            "description": description,
            "severity": severity,
            "confidence": confidence,
            "tool_source": "cortex_engine",
            "module": module,
            "category": category,
            "metadata": cls._build_metadata(
                description=description,
                related_entries=related_entries,
                chain=chain,
                reason_tags=reason_tags,
                metadata_extra=metadata_extra,
                likely_next_action=likely_next_action,
            ),
        }

    @classmethod
    def _path_sort_key(cls, item: Dict[str, Any]) -> Tuple[Any, ...]:
        return (
            cls.CATEGORY_SORT.get(str(item.get("category") or ""), 99),
            -cls.SEVERITY_SORT.get(str(item.get("severity") or "info").lower(), 0),
            -cls.CONFIDENCE_SORT.get(str(item.get("confidence") or "low").lower(), 0),
            str(item.get("title") or ""),
        )

    @classmethod
    def derive_attack_paths(cls, findings):
        entries = [cls._finding_entry(finding) for finding in findings]
        if not entries:
            return []

        rules = [
            {
                "title": "Cortex Attack Path: Auth Surface + Token Material -> Authenticated API Access",
                "description": "Reasoning engine linked authentication surface with token leakage indicators, enabling probable authenticated API abuse path.",
                "severity": "high",
                "confidence": "high",
                "category": "attack_path",
                "module": "cortex_reasoning",
                "chain": ["auth_surface", "token_leakage", "authenticated_api_access"],
                "reason_tags": ["auth_surface", "token_surface"],
                "required_all": ["auth_surface", "token_surface"],
                "likely_next_action": "Validate token scope and replay controls on authenticated endpoints already discovered.",
            },
            {
                "title": "Cortex Attack Path: Upload Surface + Dangerous Methods -> Arbitrary File Write Risk",
                "description": "Reasoning engine correlated upload exposure and unsafe HTTP methods, producing a probable arbitrary file write/webshell route.",
                "severity": "high",
                "confidence": "high",
                "category": "attack_path",
                "module": "cortex_reasoning",
                "chain": ["upload_surface", "dangerous_http_methods", "arbitrary_file_write"],
                "reason_tags": ["upload_surface", "dangerous_http_methods"],
                "required_all": ["upload_surface", "dangerous_http_methods"],
                "likely_next_action": "Revalidate upload constraints and method handling using bounded content-type and extension checks.",
            },
            {
                "title": "Cortex Attack Path: SSRF Surface -> Cloud Metadata Credential Theft",
                "description": "Reasoning engine identified SSRF-capable input and metadata-service exposure signals, indicating probable cloud credential theft path.",
                "severity": "high",
                "confidence": "medium",
                "category": "attack_path",
                "module": "cortex_reasoning",
                "chain": ["ssrf_surface", "metadata_service", "credential_theft"],
                "reason_tags": ["ssrf_surface", "metadata_service"],
                "required_all": ["ssrf_surface", "metadata_service"],
                "likely_next_action": "Use safe SSRF canaries and metadata-specific allowlist checks before any active replay.",
            },
            {
                "title": "Cortex Attack Path: API Object References + Auth Context -> Authorization Drift",
                "description": "API/object-reference telemetry combined with authentication or admin context suggests a likely object-level authorization testing path.",
                "severity": "high",
                "confidence": "medium",
                "category": "attack_path",
                "module": "cortex_reasoning",
                "chain": ["api_surface", "object_reference_surface", "authorization_drift"],
                "reason_tags": ["api_surface", "object_reference_surface", "authorization"],
                "required_all": ["api_surface", "object_reference_surface"],
                "required_any": ["auth_surface", "admin_surface", "token_surface"],
                "likely_next_action": "Compare object access responses across principals or tokens already observed in telemetry.",
            },
            {
                "title": "Cortex Attack Path: OAuth Surface + Token Material -> Session Abuse",
                "description": "OAuth/OIDC indicators and token material together point to a probable token replay or scope-confusion path worth bounded validation.",
                "severity": "medium",
                "confidence": "medium",
                "category": "attack_path",
                "module": "cortex_reasoning",
                "chain": ["oauth_surface", "token_surface", "session_abuse"],
                "reason_tags": ["oauth_surface", "token_surface"],
                "required_all": ["oauth_surface", "token_surface"],
                "likely_next_action": "Validate token audience, redirect URI handling, and scope boundaries with non-destructive replay.",
            },
            {
                "title": "Cortex Attack Plan: Investigate JS-Derived Routes",
                "description": "Planning layer recommends focused validation of JavaScript-derived routes, especially admin/auth paths already present in telemetry.",
                "severity": "medium",
                "confidence": "high",
                "category": "attack_plan",
                "module": "cortex_planner",
                "chain": ["javascript_surface", "api_surface", "route_validation"],
                "reason_tags": ["javascript_surface", "api_surface"],
                "required_any": ["javascript_surface", "api_surface"],
                "metadata_extra": {
                    "title": "Inspect JS-derived admin route",
                    "description": "Validate authorization and hidden-route accessibility for JS-mined endpoints.",
                    "rationale": "Deterministic route intelligence from passive telemetry and API surface findings.",
                    "attack_chain": "js_routes_auth_surface",
                    "attack_priority": "medium",
                    "action_priority": 65,
                    "action_type": "guided_probe",
                    "estimated_value": "high",
                    "estimated_complexity": "medium",
                },
                "likely_next_action": "Enumerate JS-derived admin or auth routes and validate access control without state changes.",
            },
            {
                "title": "Cortex Next Step: Probe SSRF Metadata Path",
                "description": "Recommended bounded probe: validate SSRF controls against metadata service patterns using non-destructive request variants.",
                "severity": "medium",
                "confidence": "medium",
                "category": "next_step",
                "module": "cortex_planner",
                "chain": ["ssrf_surface", "metadata_service", "guided_probe"],
                "reason_tags": ["ssrf_surface", "metadata_service"],
                "required_all": ["ssrf_surface"],
                "metadata_extra": {
                    "title": "Investigate SSRF against metadata service",
                    "description": "Replay safe SSRF patterns to metadata endpoints only where existing evidence indicates input control.",
                    "rationale": "SSRF and metadata-service indicators appear in findings telemetry.",
                    "endpoint": "metadata_service",
                    "attack_chain": "ssrf_to_metadata",
                    "attack_priority": "high",
                    "action_priority": 85,
                    "action_type": "guided_probe",
                    "estimated_value": "high",
                    "estimated_complexity": "medium",
                },
                "likely_next_action": "Replay safe SSRF patterns against metadata-like targets only where request control already exists.",
            },
        ]

        paths = []
        for rule in rules:
            related_entries = cls._matching_entries(
                entries,
                required_all=rule.get("required_all", ()),
                required_any=rule.get("required_any", ()),
            )
            if not related_entries:
                continue
            paths.append(
                cls._build_path(
                    title=rule["title"],
                    description=rule["description"],
                    severity=rule["severity"],
                    confidence=rule["confidence"],
                    category=rule["category"],
                    module=rule["module"],
                    chain=rule["chain"],
                    reason_tags=rule.get("reason_tags", ()),
                    related_entries=related_entries,
                    metadata_extra=rule.get("metadata_extra"),
                    likely_next_action=rule.get("likely_next_action", ""),
                )
            )

        deduped = {}
        for item in paths:
            deduped[(item["category"], item["title"])] = item
        return sorted(deduped.values(), key=cls._path_sort_key)


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
