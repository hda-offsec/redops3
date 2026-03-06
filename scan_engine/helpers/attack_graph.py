class AttackGraphBuilder:
    def __init__(self, options=None):
        self.options = options
        self.nodes = []
        self.edges = []
        self._edge_keys = set()
        self._node_ids = set()
        self._actions = []

    def _add_node(self, node):
        node_id = node.get("id")
        if not node_id or node_id in self._node_ids:
            return
        self._node_ids.add(node_id)
        self.nodes.append(node)

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
        self._node_ids = set()
        self._actions = []

    def _endpoint_node_id(self, endpoint):
        return f"endpoint:derived:{endpoint}"

    def build(self, results):
        self._reset()
        phases = results.get("phases", {})
        recon_ports = phases.get("recon", {}).get("open_ports", [])
        enum = phases.get("enum", {})
        vuln = phases.get("vuln", {})
        target_name = results.get("target", "unknown")
        target_node_id = f"target:{target_name}"
        self._add_node({"type": "target", "id": target_node_id, "label": target_name, "data": {"target": target_name}})

        for sub in phases.get("dns", {}).get("subdomains", []) or []:
            node_id = f"subdomain:{sub}"
            self._add_node({"type": "subdomain", "id": node_id, "label": sub, "data": {"domain": sub}})
            self._add_edge(target_node_id, node_id, "subdomain_of")

        for asset in phases.get("osint", {}).get("cloud", []) or []:
            provider = asset.get("provider", "cloud")
            bucket = asset.get("bucket") or asset.get("account") or "unknown"
            node_id = f"cloud:{provider}:{bucket}"
            self._add_node({"type": "cloud_resource", "id": node_id, "label": f"{provider}: {bucket}", "data": asset})
            self._add_edge(target_node_id, node_id, "exposes_asset")

        endpoint_ids_by_port = {}
        for p in recon_ports:
            port = str(p.get("port"))
            service_id = f"service:{port}"
            self._add_node({"type": "service", "id": service_id, "data": p})
            self._add_edge(target_node_id, service_id, "exposes_port")

            for ep in enum.get("targets", {}).get(port, []) or []:
                endpoint_id = f"endpoint:{port}:{ep}"
                endpoint_ids_by_port.setdefault(port, set()).add(endpoint_id)
                self._add_node({"type": "endpoint", "id": endpoint_id, "data": {"url": ep}})
                self._add_edge(service_id, endpoint_id, "exposes")

            for injection in enum.get("injection_points", {}).get(port, []) or []:
                injection_id = f"injection:{port}:{injection}"
                self._add_node({"type": "parameter", "id": injection_id, "data": {"value": injection}})
                self._add_edge(service_id, injection_id, "has_param")
                for endpoint_id in endpoint_ids_by_port.get(port, []):
                    self._add_edge(endpoint_id, injection_id, "reachable_from")

        for idx, finding in enumerate(results.get("findings", []) or [], 1):
            if not isinstance(finding, dict):
                continue
            fid = f"finding:db:{finding.get('id_stable') or idx}"
            self._add_node({"type": "vulnerability", "id": fid, "label": finding.get("title", "Finding"), "data": finding})
            endpoint = finding.get("endpoint") or finding.get("target")
            parameter = finding.get("parameter")
            category = (finding.get("category") or "").lower()
            metadata = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}

            endpoint_id = None
            if endpoint:
                endpoint_id = self._endpoint_node_id(endpoint)
                self._add_node({"type": "endpoint", "id": endpoint_id, "label": endpoint, "data": {"url": endpoint}})
                self._add_edge(target_node_id, endpoint_id, "reachable_from")
                self._add_edge(endpoint_id, fid, "leads_to_attack")
            else:
                self._add_edge(target_node_id, fid, "contains")

            if parameter:
                param_id = f"parameter:{parameter}"
                self._add_node({"type": "parameter", "id": param_id, "label": parameter, "data": {"parameter": parameter}})
                self._add_edge(fid, param_id, "depends_on")
                if endpoint_id:
                    self._add_edge(endpoint_id, param_id, "reachable_from")

            if category in {"auth_surface", "authentication_surface"}:
                auth_id = f"auth_surface:{finding.get('id_stable') or idx}"
                self._add_node({"type": "auth_surface", "id": auth_id, "label": finding.get("title", "Auth Surface"), "data": finding})
                self._add_edge(target_node_id, auth_id, "exposes_asset")
                if endpoint_id:
                    self._add_edge(auth_id, endpoint_id, "auth_exposes")

            if category in {"api_surface"}:
                api_id = f"api_endpoint:{finding.get('id_stable') or idx}"
                self._add_node({"type": "api_endpoint", "id": api_id, "label": finding.get("title", "API Endpoint"), "data": finding})
                self._add_edge(target_node_id, api_id, "exposes_asset")
                if endpoint_id:
                    self._add_edge(api_id, endpoint_id, "reachable_from")

            if category in {"jwt_exposure", "token_leakage", "api_key_exposure"}:
                token_id = f"token:{finding.get('id_stable') or idx}"
                self._add_node({"type": "token", "id": token_id, "label": finding.get("title", "Token"), "data": finding})
                self._add_edge(target_node_id, token_id, "contains")
                if endpoint_id:
                    self._add_edge(token_id, endpoint_id, "token_authenticates")

            if category in {"parameter_surface"} and parameter:
                ps_id = f"parameter_surface:{finding.get('id_stable') or idx}:{parameter}"
                self._add_node({"type": "parameter", "id": ps_id, "label": parameter, "data": finding})
                if endpoint_id:
                    self._add_edge(endpoint_id, ps_id, "depends_on")

            if category in {"asset_discovery", "cloud_asset"}:
                discovered = metadata.get("discovered_asset") or endpoint or finding.get("target")
                if discovered:
                    node_type = "cloud_resource" if category == "cloud_asset" else "asset"
                    asset_id = f"{node_type}:{discovered}"
                    self._add_node({"type": node_type, "id": asset_id, "label": str(discovered), "data": finding})
                    self._add_edge(target_node_id, asset_id, "exposes_asset")
                    if endpoint_id:
                        self._add_edge(asset_id, endpoint_id, "depends_on")

            if category == "secret_exposure":
                secret_type = metadata.get("secret_type") or finding.get("title") or "secret"
                secret_id = f"secret:{secret_type}:{finding.get('id_stable') or idx}"
                self._add_node({"type": "secret", "id": secret_id, "label": str(secret_type), "data": finding})
                self._add_edge(target_node_id, secret_id, "leaks_secret")
                if endpoint_id:
                    self._add_edge(endpoint_id, secret_id, "leads_to_attack")

            if category in {"attack_chain", "attack_path"}:
                chain_id = f"attack_chain:{finding.get('id_stable') or idx}"
                self._add_node({"type": "attack_chain", "id": chain_id, "label": finding.get("title", "Attack Chain"), "data": finding})
                self._add_edge(target_node_id, chain_id, "leads_to_attack")
                if endpoint_id:
                    self._add_edge(chain_id, endpoint_id, "leads_to")
                chain = metadata.get("chain", []) if isinstance(metadata.get("chain"), list) else []
                for link in chain:
                    link_id = f"attack_chain_link:{link}"
                    self._add_node({"type": "attack_path_link", "id": link_id, "label": str(link), "data": {"name": link}})
                    self._add_edge(chain_id, link_id, "depends_on")

        surface_mapping = vuln.get("surface_mapping", {})
        for port, data in surface_mapping.items():
            for _, items in data.get("tree", {}).items():
                for item in items:
                    node_id = f"surface:{port}:{item['path']}"
                    self._add_node({"type": "backend_endpoint", "id": node_id, "data": item})
                    self._add_edge(f"service:{port}", node_id, "exposes_surface")

        self._actions = self._derive_actions(results)
        return {"nodes": self.nodes, "edges": self.edges}

    def _derive_actions(self, results):
        actions = []
        enum = results.get("phases", {}).get("enum", {})
        vuln = results.get("phases", {}).get("vuln", {})
        for port, targets in enum.get("targets", {}).items():
            if targets:
                priority = max(0, min(100, 60 + (len(enum.get("injection_points", {}).get(port, [])) * 0.2)))
                actions.append({
                    "id": f"action-enum-{port}",
                    "title": f"Deep endpoint testing on port {port}",
                    "category": "enum",
                    "priority": priority,
                    "confidence": 70,
                    "effort": "M",
                    "noise": "low",
                    "justification": [f"{len(targets)} targets discovered"],
                    "suggested_tasks": [f"vuln_{port}"],
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
                "suggested_tasks": ["global_vuln"],
            })
        return actions

    def rank_actions(self):
        def score(action):
            just = action.get("justification", [])
            just_len = len(just) if isinstance(just, list) else 1 if isinstance(just, str) and just.strip() else 0
            return (action.get("priority", 0) * 0.5) + (action.get("confidence", 0) * 0.3) + (just_len * 5)

        return sorted(self._actions, key=score, reverse=True)
