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
