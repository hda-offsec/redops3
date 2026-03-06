class AttackGraphBuilder:
    def __init__(self, options=None):
        self.options = options
        self.nodes = []
        self.edges = []
        self._edge_keys = set()
        self._actions = []

    def _add_edge(self, from_id, to_id, edge_type):
        key = (from_id, to_id, edge_type)
        if key in self._edge_keys:
            return
        self._edge_keys.add(key)
        self.edges.append({"from": from_id, "to": to_id, "type": edge_type})

    def _reset(self):
        self.nodes = []
        self.edges = []
        self._edge_keys = set()
        self._actions = []

    def build(self, results):
        self._reset()
        phases = results.get("phases", {})
        recon_ports = phases.get("recon", {}).get("open_ports", [])
        enum = phases.get("enum", {})
        vuln = phases.get("vuln", {})
        target_name = results.get("target", "unknown")
        target_node_id = f"target:{target_name}"
        
        # Ensure Target Node exists
        self.nodes.append({"type": "target", "id": target_node_id, "label": target_name, "data": {"target": target_name}})

        # DNS Subdomains
        subdomains = phases.get("dns", {}).get("subdomains", [])
        for sub in subdomains:
            node_id = f"subdomain:{sub}"
            self.nodes.append({"type": "subdomain", "id": node_id, "label": sub, "data": {"domain": sub}})
            self._add_edge(target_node_id, node_id, "subdomain_of")

        # Cloud Assets
        cloud_assets = phases.get("osint", {}).get("cloud", [])
        for asset in cloud_assets:
            provider = asset.get("provider", "Cloud")
            bucket = asset.get("bucket") or asset.get("account") or "unknown"
            node_id = f"cloud:{provider}:{bucket}"
            self.nodes.append({"type": "cloud_asset", "id": node_id, "label": f"{provider}: {bucket}", "data": asset})
            self._add_edge(target_node_id, node_id, "associated_asset")

        endpoint_ids_by_port = {}
        for p in recon_ports:
            port = str(p.get("port"))
            service_id = f"service:{port}"
            self.nodes.append({"type": "service", "id": service_id, "data": p})
            self._add_edge(target_node_id, service_id, "exposes_port")

            for ep in enum.get("targets", {}).get(port, []):
                endpoint_id = f"endpoint:{port}:{ep}"
                endpoint_ids_by_port.setdefault(port, set()).add(endpoint_id)
                self.nodes.append({"type": "endpoint", "id": endpoint_id, "data": {"url": ep}})
                self._add_edge(service_id, endpoint_id, "exposes")

            for injection in enum.get("injection_points", {}).get(port, []):
                injection_id = f"injection:{port}:{injection}"
                self.nodes.append({"type": "injection_point", "id": injection_id, "data": {"value": injection}})
                self._add_edge(service_id, injection_id, "has_param")
                for endpoint_id in endpoint_ids_by_port.get(port, []):
                    self._add_edge(endpoint_id, injection_id, "has_param")

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
                self._add_edge(service_id, tech_profile_id, "runs_stack")
                for endpoint_id in endpoint_ids_by_port.get(port, []):
                    self._add_edge(tech_profile_id, endpoint_id, "influences")

        waf_map = enum.get("waf", {}) if isinstance(enum.get("waf", {}), dict) else {}
        for port, waf in waf_map.items():
            self.nodes.append({"type": "waf", "id": f"waf:{port}", "data": {"name": waf}})
            self._add_edge(f"service:{port}", f"waf:{port}", "protected_by")

        nuclei_findings = vuln.get("nuclei", {}).get("findings", [])
        for idx, finding in enumerate(nuclei_findings, 1):
            fid = f"finding:nuclei:{idx}"
            self.nodes.append({"type": "finding", "id": fid, "data": finding})
            port = str(finding.get("port", "0"))
            self._add_edge(f"service:{port}", fid, "has_finding")

        for idx, xss_finding in enumerate(vuln.get("xss", []), 1):
            fid = f"finding:xss:{idx}"
            self.nodes.append({"type": "finding", "id": fid, "data": xss_finding})
            port = str(xss_finding.get("port", "0")) if isinstance(xss_finding, dict) else "0"
            self._add_edge(f"service:{port}", fid, "has_finding")
            for endpoint_id in endpoint_ids_by_port.get(port, []):
                self._add_edge(endpoint_id, fid, "vulnerable_to")


        # DB-normalized findings (if attached by UI/API layer)
        for idx, finding in enumerate(results.get("findings", []) or [], 1):
            if not isinstance(finding, dict):
                continue
            fid = f"finding:db:{finding.get('id_stable') or idx}"
            self.nodes.append({"type": "vulnerability", "id": fid, "label": finding.get("title", "Finding"), "data": finding})
            endpoint = finding.get("endpoint") or finding.get("target")
            param = finding.get("parameter")
            if endpoint:
                endpoint_id = f"endpoint:derived:{endpoint}"
                self.nodes.append({"type": "endpoint", "id": endpoint_id, "label": endpoint, "data": {"url": endpoint}})
                self._add_edge(target_node_id, endpoint_id, "exposes")
                self._add_edge(endpoint_id, fid, "exploitable")
            else:
                self._add_edge(target_node_id, fid, "contains")
            if param:
                param_id = f"parameter:{param}"
                self.nodes.append({"type": "parameter", "id": param_id, "label": param, "data": {"parameter": param}})
                self._add_edge(fid, param_id, "leads_to")
            payload = finding.get("payload")
            if payload:
                payload_id = f"payload:{abs(hash(str(payload))) % (10 ** 10)}"
                self.nodes.append({"type": "payload", "id": payload_id, "label": str(payload)[:120], "data": {"payload": payload}})
                self._add_edge(fid, payload_id, "depends_on")
            category = (finding.get("category") or "").lower()
            if "secret" in category or any(k in (finding.get("title") or "").lower() for k in ["secret", "token", "api key", "credential"]):
                secret_id = f"secret:{finding.get('id_stable') or idx}"
                self.nodes.append({"type": "secret", "id": secret_id, "label": finding.get("title", "Secret"), "data": finding})
                self._add_edge(target_node_id, secret_id, "contains")
                if endpoint:
                    endpoint_id = f"endpoint:derived:{endpoint}"
                    self._add_edge(endpoint_id, secret_id, "exposes")
            if category == "attack_chain":
                chain_id = f"attack_chain:{finding.get('id_stable') or idx}"
                self.nodes.append({"type": "attack_chain", "id": chain_id, "label": finding.get("title", "Attack Chain"), "data": finding})
                self._add_edge(target_node_id, chain_id, "contains")
                if endpoint:
                    self._add_edge(chain_id, f"endpoint:derived:{endpoint}", "leads_to")
                chain_meta = (finding.get("metadata") or {}).get("chain", []) if isinstance(finding.get("metadata"), dict) else []
                for link in chain_meta:
                    link_id = f"vulnerability:chain_link:{link}"
                    self.nodes.append({"type": "vulnerability", "id": link_id, "label": str(link), "data": {"name": link}})
                    self._add_edge(chain_id, link_id, "depends_on")
        # --- PHASE 4.5: BACKEND SURFACE EXPOSURE (ARCHITECTURE DRIVEN) ---
        surface_mapping = vuln.get("surface_mapping", {})
        for port, data in surface_mapping.items():
            for root, items in data.get("tree", {}).items():
                for item in items:
                    node_id = f"surface:{port}:{item['path']}"
                    # Add Route Node
                    self.nodes.append({
                        "type": "backend_endpoint",
                        "id": node_id,
                        "data": item
                    })
                    self._add_edge(f"service:{port}", node_id, "exposes_surface")
                    
                    # Link to Risks
                    for risk in item.get("risks", []):
                        if risk in ["mutation_surface", "object_lookup", "admin_surface"]:
                            risk_node_id = f"risk:{port}:{risk}"
                            # Add Risk Node if not exists
                            if not any(n["id"] == risk_node_id for n in self.nodes):
                                self.nodes.append({
                                    "type": "risk_surface",
                                    "id": risk_node_id,
                                    "data": {"category": risk}
                                })
                            self._add_edge(node_id, risk_node_id, "contributes_to_risk")

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
                just_len = len(justification)
            elif isinstance(justification, str):
                just_len = 1 if justification.strip() else 0
            else:
                just_len = 0
            return (action.get("priority", 0) * 0.5) + (action.get("confidence", 0) * 0.3) + (just_len * 5)

        return sorted(self._actions, key=score, reverse=True)
