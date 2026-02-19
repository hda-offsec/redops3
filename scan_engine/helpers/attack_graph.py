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

        endpoint_ids_by_port = {}
        for p in recon_ports:
            port = str(p.get("port"))
            service_id = f"service:{port}"
            self.nodes.append({"type": "service", "id": service_id, "data": p})

            for ep in enum.get("targets", {}).get(port, []):
                endpoint_id = f"endpoint:{port}:{ep}"
                endpoint_ids_by_port.setdefault(port, []).append(endpoint_id)
                self.nodes.append({"type": "endpoint", "id": endpoint_id, "data": {"url": ep}})
                self.edges.append({"from": service_id, "to": endpoint_id, "type": "exposes"})

            for injection in enum.get("injection_points", {}).get(port, []):
                injection_id = f"injection:{port}:{injection}"
                self.nodes.append({"type": "injection_point", "id": injection_id, "data": {"value": injection}})
                self.edges.append({"from": service_id, "to": injection_id, "type": "has_param"})
                for endpoint_id in endpoint_ids_by_port.get(port, []):
                    self.edges.append({"from": endpoint_id, "to": injection_id, "type": "has_param"})

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
                for endpoint_id in endpoint_ids_by_port.get(port, []):
                    self.edges.append({"from": tech_profile_id, "to": endpoint_id, "type": "influences"})

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
            for endpoint_id in endpoint_ids_by_port.get(port, []):
                self.edges.append({"from": endpoint_id, "to": fid, "type": "vulnerable_to"})

        self._actions = self._derive_actions(results)
        return {"nodes": self.nodes, "edges": self.edges}

    def _derive_actions(self, results):
        actions = []
        enum = results.get("phases", {}).get("enum", {})
        vuln = results.get("phases", {}).get("vuln", {})
        for port, targets in enum.get("targets", {}).items():
            if targets:
                injection_points = enum.get("injection_points", {}).get(port, [])
                waf_present = bool(enum.get("waf", {}).get(port)) if isinstance(enum.get("waf", {}), dict) else False
                attack_profile = enum.get("attack_profile", {}).get(port, {})
                profile_text = " ".join(str(v).lower() for v in attack_profile.values()) if isinstance(attack_profile, dict) else str(attack_profile).lower()
                modern_frontend = any(token in profile_text for token in ["spa", "angular", "react"])
                priority = 60 + (len(injection_points) * 0.2)
                if waf_present:
                    priority += 10
                if modern_frontend:
                    priority += 5
                priority = max(0, min(priority, 100))
                actions.append({
                    "id": f"action-enum-{port}",
                    "title": f"Deep endpoint testing on port {port}",
                    "category": "enum",
                    "priority": priority,
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
                just_score = len(justification)
            elif isinstance(justification, str):
                just_score = 1 if justification.strip() else 0
            else:
                just_score = 0
            return (action.get("priority", 0) * 0.5) + (action.get("confidence", 0) * 0.3) + (just_score * 5)

        return sorted(self._actions, key=score, reverse=True)
