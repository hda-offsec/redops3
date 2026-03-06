from core.models import db, Finding, Suggestion, Signal


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
            port = service['port']
            name = service['service_name']
            if port in [80, 443, 8080, 8443] or 'http' in name:
                SuggestionEngine.create(scan_id, "whatweb", f"whatweb http://<target>:{port}", "Web service detected. Fingerprint technologies.")
                SuggestionEngine.create(scan_id, "gobuster", f"gobuster dir -u http://<target>:{port} -w common.txt", "Web service detected. Enumerate directories.")
            if port == 445 or 'smb' in name:
                SuggestionEngine.create(scan_id, "enum4linux", f"enum4linux -a <target>", "SMB detected. Enumerate shares and users.")
            if port == 22:
                SuggestionEngine.create(scan_id, "hydra", f"hydra -l root -P rockyou.txt ssh://<target>", "SSH detected. Check for weak credentials (careful).")

        db.session.commit()


class SuggestionEngine:
    @staticmethod
    def create(scan_id, tool, command, reason):
        s = Suggestion(
            scan_id=scan_id,
            tool_name=tool,
            command_suggestion=command,
            reason=reason
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

    backup_like = grouped.get(("backup_expert", "finding"), []) + grouped.get(("backup_scanner", "finding"), [])
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
            evidence="Cross-signal correlation: git exposure + backup archive exposure."
        )
        created += 1

    js_like = grouped.get(("js_scanner", "finding"), []) + grouped.get(("js_deep_scanner", "finding"), [])
    api_like = grouped.get(("api_expert", "finding"), []) + grouped.get(("api_scanner", "finding"), [])
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
            evidence="Cross-signal correlation: JavaScript endpoint extraction + API discovery."
        )
        created += 1

    if created:
        db.session.commit()
    return created


class CortexEngine:
    """Reason over findings/signals to generate deterministic attack path intelligence."""

    @staticmethod
    def _mk_text(f):
        return f"{(getattr(f, 'title', '') or '').lower()} {(getattr(f, 'description', '') or '').lower()} {(getattr(f, 'category', '') or '').lower()}"

    @classmethod
    def derive_attack_paths(cls, findings):
        paths = []
        texts = [cls._mk_text(f) for f in findings]

        def has(pred):
            return any(pred(f, t) for f, t in zip(findings, texts))

        def add(title, description, severity='high', confidence='medium', chain=None):
            paths.append({
                'title': title,
                'description': description,
                'severity': severity,
                'confidence': confidence,
                'tool_source': 'cortex_engine',
                'module': 'cortex_reasoning',
                'category': 'attack_path',
                'metadata': {'chain': chain or []},
            })

        has_auth_surface = has(lambda f, t: 'auth' in t or (getattr(f, 'category', '') or '') in {'authentication_surface', 'auth_surface'})
        has_token = has(lambda f, t: 'token' in t or 'jwt' in t or (getattr(f, 'category', '') or '') in {'jwt_exposure', 'token_leakage', 'api_key_exposure'})
        if has_auth_surface and has_token:
            add(
                'Cortex Attack Path: Auth Surface + Token Material -> Authenticated API Access',
                'Reasoning engine linked authentication surface with token leakage indicators, enabling probable authenticated API abuse path.',
                severity='high',
                confidence='high',
                chain=['auth_surface', 'token_leakage', 'authenticated_api_access'],
            )

        has_upload = has(lambda f, t: 'upload' in t or (getattr(f, 'category', '') or '') == 'upload_surface')
        has_methods = has(lambda f, t: 'dangerous http methods' in t or (getattr(f, 'category', '') or '') == 'http_method_exposure')
        if has_upload and has_methods:
            add(
                'Cortex Attack Path: Upload Surface + Dangerous Methods -> Arbitrary File Write Risk',
                'Reasoning engine correlated upload exposure and unsafe HTTP methods, producing a probable arbitrary file write/webshell route.',
                severity='high',
                confidence='high',
                chain=['upload_surface', 'dangerous_http_methods', 'arbitrary_file_write'],
            )

        has_ssrf = has(lambda f, t: 'ssrf' in t or (getattr(f, 'category', '') or '') in {'ssrf_surface', 'metadata_service_exposure'})
        has_metadata = has(lambda f, t: '169.254.169.254' in t or 'metadata service' in t or (getattr(f, 'category', '') or '') == 'metadata_service_exposure')
        if has_ssrf and has_metadata:
            add(
                'Cortex Attack Path: SSRF Surface -> Cloud Metadata Credential Theft',
                'Reasoning engine identified SSRF-capable input and metadata-service exposure signals, indicating probable cloud credential theft path.',
                severity='high',
                confidence='medium',
                chain=['ssrf_surface', 'metadata_service', 'credential_theft'],
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
        "medium": 0.65,
        "low": 0.35,
    }

    @classmethod
    def score_finding(cls, finding, attack_graph_node_ids=None):
        attack_graph_node_ids = attack_graph_node_ids or set()
        severity = cls.SEVERITY_WEIGHT.get((finding.severity or "info").lower(), 0.1)
        confidence = cls.CONFIDENCE_WEIGHT.get((finding.confidence or "medium").lower(), 0.65)

        surface_exposure = 1.0 if (finding.endpoint or finding.target) else 0.2
        in_attack_graph = 1.0 if (finding.id_stable and f"finding:db:{finding.id_stable}" in attack_graph_node_ids) else 0.0

        metadata = finding.metadata_json if isinstance(finding.metadata_json, dict) else {}
        validated = 1.0 if (
            metadata.get("exploit_validated") is True
            or "exploit validation" in ((finding.title or "") + " " + (finding.description or "")).lower()
            or (finding.tool_source or "") == "exploit_validation_engine"
        ) else 0.0

        exploit_score = (
            (severity * 0.35)
            + (confidence * 0.25)
            + (surface_exposure * 0.15)
            + (in_attack_graph * 0.15)
            + (validated * 0.10)
        ) * 100
        exploit_score = round(max(0.0, min(100.0, exploit_score)), 2)

        if exploit_score >= 80:
            risk_level = "critical"
        elif exploit_score >= 65:
            risk_level = "high"
        elif exploit_score >= 40:
            risk_level = "medium"
        else:
            risk_level = "low"

        return exploit_score, risk_level


def apply_risk_scores(scan_id, graph=None):
    findings = Finding.query.filter_by(scan_id=scan_id).all()
    if not findings:
        return 0

    node_ids = set()
    if isinstance(graph, dict):
        node_ids = {n.get("id") for n in graph.get("nodes", []) if isinstance(n, dict) and n.get("id")}

    updated = 0
    for finding in findings:
        metadata = finding.metadata_json if isinstance(finding.metadata_json, dict) else {}
        exploit_score, risk_level = RiskScoringEngine.score_finding(finding, node_ids)
        chain = metadata.get("chain") if isinstance(metadata.get("chain"), list) else []
        category = (finding.category or "").lower()

        if category == "attack_path":
            chain_length = len(chain)
            if chain_length >= 3 or risk_level == "critical":
                attack_priority = "critical"
            elif chain_length == 2 or risk_level == "high":
                attack_priority = "high"
            elif chain_length == 1 or risk_level == "medium":
                attack_priority = "medium"
            else:
                attack_priority = "low"
            attack_complexity = "high" if chain_length >= 4 else "medium" if chain_length >= 2 else "low"
            metadata["attack_priority"] = attack_priority
            metadata["chain_length"] = chain_length
            metadata["attack_complexity"] = attack_complexity

        metadata["exploit_score"] = exploit_score
        metadata["risk_level"] = risk_level
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
        if item['title'] in existing_titles:
            continue
        add_finding_cb(
            scan_id=scan_id,
            title=item['title'],
            description=item['description'],
            severity=item['severity'],
            confidence=item['confidence'],
            tool_source=item['tool_source'],
            module=item['module'],
            category=item['category'],
            metadata=item.get('metadata') or {},
            evidence=item['description'],
            reproduction='Trace prerequisite findings and validate each hop using recorded evidence and endpoints.',
        )
        created += 1

    return created
