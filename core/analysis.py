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
