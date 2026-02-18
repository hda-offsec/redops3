class AttackGraphBuilder:
    def __init__(self):
        self.nodes = []
        self.edges = []
        self._actions = []

    def build(self, results):
        self.nodes = []
        self.edges = []
        phases = results.get("phases", {})
        recon_ports = phases.get("recon", {}).get("open_ports", [])
        enum = phases.get("enum", {})
        vuln = phases.get("vuln", {})

        for p in recon_ports:
            port = str(p.get("port"))
            service_id = f"service:{port}"
            self.nodes.append({"type": "service", "id": service_id, "data": p})

            for ep in enum.get("targets", {}).get(port, []):
                endpoint_id = f"endpoint:{port}:{ep}"
                self.nodes.append({"type": "endpoint", "id": endpoint_id, "data": {"url": ep}})
                self.edges.append({"from": service_id, "to": endpoint_id, "type": "exposes"})

            for injection in enum.get("injection_points", {}).get(port, []):
                injection_id = f"injection:{port}:{injection}"
                self.nodes.append({"type": "injection_point", "id": injection_id, "data": {"value": injection}})
                self.edges.append({"from": service_id, "to": injection_id, "type": "has_param"})

            attack_profile = enum.get("attack_profile", {}).get(port)
            mutation_strategy = enum.get("mutation_strategy", {}).get(port)
            if attack_profile or mutation_strategy:
                tech_profile_id = f"tech_profile:{port}"
                self.nodes.append({
                    "type": "tech_profile",
                    "id": tech_profile_id,
                    "data": {
                        "attack_profile": attack_profile or {},
                        "mutation_strategy": mutation_strategy or {},
                    },
                })
                self.edges.append({"from": service_id, "to": tech_profile_id, "type": "runs_stack"})

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

        for idx, xss_finding in enumerate(vuln.get("xss", []), 1):
            fid = f"finding:xss:{idx}"
            self.nodes.append({"type": "finding", "id": fid, "data": xss_finding})
            port = str(xss_finding.get("port", "0")) if isinstance(xss_finding, dict) else "0"
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
        def score(action):
            justification = action.get("justification", [])
            if isinstance(justification, list):
                just_len = len(" ".join(str(item) for item in justification))
            else:
                just_len = len(str(justification))
            return (action.get("priority", 0) * 0.5) + (action.get("confidence", 0) * 0.3) + (just_len * 5)

        return sorted(self._actions, key=score, reverse=True)
