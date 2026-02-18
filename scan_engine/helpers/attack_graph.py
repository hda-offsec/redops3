class AttackGraphBuilder:
    def __init__(self):
        self.nodes = []
        self.edges = []
        self._actions = []

    def build(self, results):
        phases = results.get("phases", {})
        recon_ports = phases.get("recon", {}).get("open_ports", [])
        enum = phases.get("enum", {})
        vuln = phases.get("vuln", {})

        for p in recon_ports:
            port = str(p.get("port"))
            self.nodes.append({"type": "service", "id": f"service:{port}", "data": p})
            for ep in enum.get("targets", {}).get(port, []):
                node_id = f"endpoint:{port}:{ep}"
                self.nodes.append({"type": "endpoint", "id": node_id, "data": {"url": ep}})
                self.edges.append({"from": f"service:{port}", "to": node_id, "type": "exposes"})

        waf_map = enum.get("waf", {}) if isinstance(enum.get("waf", {}), dict) else {}
        for port, waf in waf_map.items():
            self.nodes.append({"type": "waf", "id": f"waf:{port}", "data": {"name": waf}})
            self.edges.append({"from": f"service:{port}", "to": f"waf:{port}", "type": "protected_by"})

        nuclei_findings = vuln.get("nuclei", {}).get("findings", [])
        for idx, finding in enumerate(nuclei_findings, 1):
            fid = f"finding:nuclei:{idx}"
            self.nodes.append({"type": "finding", "id": fid, "data": finding})
            port = str(finding.get("port", "0"))
            self.edges.append({"from": f"service:{port}", "to": fid, "type": "has_finding"})

        self._actions = self._derive_actions(results)
        return {"nodes": self.nodes, "edges": self.edges}

    def _derive_actions(self, results):
        actions = []
        enum = results.get("phases", {}).get("enum", {})
        vuln = results.get("phases", {}).get("vuln", {})
        for port, targets in enum.get("targets", {}).items():
            if targets:
                actions.append({
                    "id": f"action-enum-{port}",
                    "title": f"Deep endpoint testing on port {port}",
                    "category": "enum",
                    "priority": 60,
                    "confidence": 70,
                    "effort": "M",
                    "noise": "low",
                    "justification": [f"{len(targets)} targets discovered"],
                    "suggested_tasks": [f"vuln_{port}"]
                })
        nuclei_findings = vuln.get("nuclei", {}).get("findings", [])
        if nuclei_findings:
            actions.append({
                "id": "action-triage-nuclei",
                "title": "Triage high-value nuclei findings",
                "category": "vuln",
                "priority": 90,
                "confidence": 85,
                "effort": "S",
                "noise": "low",
                "justification": [f"{len(nuclei_findings)} nuclei findings"],
                "suggested_tasks": ["global_vuln"]
            })
        return actions

    def rank_actions(self):
        return sorted(self._actions, key=lambda x: (x.get("priority", 0), x.get("confidence", 0)), reverse=True)
