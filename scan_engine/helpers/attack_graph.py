from scan_engine.helpers.finding_schema import classify_visible_truth


class AttackGraphBuilder:
    def _norm_token(self, value):
        return str(value or "").strip().lower()

    def _node_id(self, prefix, *parts):
        token = ":".join(self._norm_token(p) for p in parts if str(p or "").strip())
        return f"{prefix}:{token}" if token else f"{prefix}:unknown"

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
        return self._node_id("endpoint", "derived", endpoint)

    def build(self, results):
        self._reset()
        phases = results.get("phases", {})
        recon_ports = phases.get("recon", {}).get("open_ports", [])
        enum = phases.get("enum", {})
        vuln = phases.get("vuln", {})
        target_name = results.get("target", "unknown")
        target_node_id = self._node_id("target", target_name)
        self._add_node({"type": "target", "id": target_node_id, "label": target_name, "data": {"target": target_name}})

        for sub in phases.get("dns", {}).get("subdomains", []) or []:
            node_id = self._node_id("subdomain", sub)
            self._add_node({"type": "subdomain", "id": node_id, "label": sub, "data": {"domain": sub}})
            self._add_edge(target_node_id, node_id, "subdomain_of")

        for asset in phases.get("osint", {}).get("cloud", []) or []:
            provider = asset.get("provider", "cloud")
            bucket = asset.get("bucket") or asset.get("account") or "unknown"
            node_id = self._node_id("cloud", provider, bucket)
            self._add_node({"type": "cloud_resource", "id": node_id, "label": f"{provider}: {bucket}", "data": asset})
            self._add_edge(target_node_id, node_id, "exposes_asset")

        endpoint_ids_by_port = {}
        for p in recon_ports:
            port = str(p.get("port"))
            service_id = self._node_id("service", port)
            self._add_node({"type": "service", "id": service_id, "data": p})
            self._add_edge(target_node_id, service_id, "exposes_port")

            for ep in enum.get("targets", {}).get(port, []) or []:
                endpoint_id = self._node_id("endpoint", port, ep)
                endpoint_ids_by_port.setdefault(port, set()).add(endpoint_id)
                self._add_node({"type": "endpoint", "id": endpoint_id, "data": {"url": ep}})
                self._add_edge(service_id, endpoint_id, "exposes")

            for injection in enum.get("injection_points", {}).get(port, []) or []:
                injection_id = self._node_id("injection", port, injection)
                self._add_node({"type": "parameter", "id": injection_id, "data": {"value": injection}})
                self._add_edge(service_id, injection_id, "has_param")
                for endpoint_id in endpoint_ids_by_port.get(port, []):
                    self._add_edge(endpoint_id, injection_id, "reachable_from")

        for idx, finding in enumerate(results.get("findings", []) or [], 1):
            if not isinstance(finding, dict):
                continue
            fid = f"finding:db:{finding.get('id_stable') or idx}"
            visible_truth = classify_visible_truth(finding)
            node_type = {
                "confirmed_vulnerability": "vulnerability",
                "recommendation": "recommendation",
                "suspicion": "suspicion",
            }.get(visible_truth, "observation")
            node_label = finding.get("title", "Finding")
            self._add_node({
                "type": node_type,
                "id": fid,
                "label": node_label,
                "data": {**finding, "visible_truth": visible_truth},
            })
            endpoint = finding.get("endpoint") or finding.get("target")
            parameter = finding.get("parameter")
            category = (finding.get("category") or "").lower()
            metadata = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
            chain_meta = finding.get("chain_metadata") if isinstance(finding.get("chain_metadata"), dict) else {}

            endpoint_id = None
            if endpoint:
                endpoint_id = self._endpoint_node_id(endpoint)
                self._add_node({"type": "endpoint", "id": endpoint_id, "label": endpoint, "data": {"url": endpoint}})
                self._add_edge(target_node_id, endpoint_id, "reachable_from")
                self._add_edge(
                    endpoint_id,
                    fid,
                    "leads_to_attack" if visible_truth == "confirmed_vulnerability" else "supports_assessment",
                )
            else:
                self._add_edge(target_node_id, fid, "contains")

            if parameter:
                param_id = self._node_id("parameter", parameter)
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

            if category in {"asset_discovery", "cloud_asset", "infra_discovery"}:
                discovered = metadata.get("discovered_asset") or endpoint or finding.get("target")
                provider = metadata.get("provider") if isinstance(metadata, dict) else None
                if discovered:
                    if category == "cloud_asset":
                        node_type = "cloud_resource"
                    elif category == "infra_discovery" and provider == "internal":
                        node_type = "internal_host"
                    elif category == "infra_discovery":
                        node_type = "asset"
                    else:
                        node_type = "asset"
                    asset_id = self._node_id(node_type, discovered)
                    self._add_node({"type": node_type, "id": asset_id, "label": str(discovered), "data": finding})
                    self._add_edge(target_node_id, asset_id, "exposes_asset")
                    if provider:
                        provider_id = self._node_id("provider", provider)
                        self._add_node({"type": "provider", "id": provider_id, "label": str(provider), "data": {"provider": provider}})
                        self._add_edge(asset_id, provider_id, "hosted_by")
                    if endpoint_id:
                        self._add_edge(asset_id, endpoint_id, "depends_on")

            if category == "secret_exposure":
                secret_type = metadata.get("secret_type") or finding.get("title") or "secret"
                secret_id = f"secret:{secret_type}:{finding.get('id_stable') or idx}"
                self._add_node({"type": "secret", "id": secret_id, "label": str(secret_type), "data": finding})
                self._add_edge(target_node_id, secret_id, "leaks_secret")
                if endpoint_id:
                    self._add_edge(
                        endpoint_id,
                        secret_id,
                        "leads_to_attack" if visible_truth == "confirmed_vulnerability" else "supports_assessment",
                    )

            if category in {"attack_chain", "attack_path"} or chain_meta.get("is_chain_root"):
                chain_id = f"attack_chain:{finding.get('id_stable') or idx}"
                label = finding.get("title", "Attack Chain")
                if chain_meta.get("attack_path_summary"):
                    label = chain_meta.get("attack_path_summary")

                chain_type = "attack_chain" if visible_truth == "confirmed_vulnerability" else "attack_hypothesis"
                self._add_node({
                    "type": chain_type,
                    "id": chain_id,
                    "label": label,
                    "data": {**finding, "visible_truth": visible_truth},
                })
                self._add_edge(target_node_id, chain_id, "leads_to_attack" if visible_truth == "confirmed_vulnerability" else "correlates_to")
                if endpoint_id:
                    self._add_edge(chain_id, endpoint_id, "leads_to" if visible_truth == "confirmed_vulnerability" else "references")
                
                # Link related findings in the graph
                for related_id in chain_meta.get("related_findings", []):
                    related_node_id = f"finding:db:{related_id}"
                    self._add_edge(chain_id, related_node_id, "correlates_to")

                chain = metadata.get("chain", []) if isinstance(metadata.get("chain"), list) else []
                for link in chain:
                    link_id = f"attack_chain_link:{link}"
                    self._add_node({"type": "attack_path_link", "id": link_id, "label": str(link), "data": {"name": link}})
                    self._add_edge(chain_id, link_id, "depends_on")

            if category in {"tech_fingerprint", "dependency_surface", "cve_candidate"}:
                component = metadata.get("component") or finding.get("title")
                version = metadata.get("version")
                if component:
                    comp_id = self._node_id("component", component)
                    self._add_node({"type": "component", "id": comp_id, "label": str(component), "data": finding})
                    self._add_edge(target_node_id, comp_id, "runs_component")
                    if version:
                        ver_id = self._node_id("version", component, version)
                        self._add_node({"type": "version", "id": ver_id, "label": str(version), "data": {"component": component, "version": version}})
                        self._add_edge(comp_id, ver_id, "uses_version")
                    cve_id = metadata.get("cve_id")
                    if cve_id:
                        cve_node = self._node_id("cve_candidate", cve_id)
                        self._add_node({"type": "cve_candidate", "id": cve_node, "label": str(cve_id), "data": finding})
                        self._add_edge(comp_id, cve_node, "depends_on")

            if category in {"attack_plan", "next_step"}:
                plan_type = "attack_plan" if category == "attack_plan" else "next_step"
                plan_id = f"{plan_type}:{finding.get('id_stable') or idx}"
                self._add_node({"type": plan_type, "id": plan_id, "label": finding.get("title", plan_type), "data": finding})
                self._add_edge(target_node_id, plan_id, "prioritizes")
                if endpoint_id:
                    self._add_edge(plan_id, endpoint_id, "suggests")

            if category in {"mission_prep", "objective_path"}:
                objective_type = metadata.get("objective_type") or "objective"
                objective_id = self._node_id(category, objective_type, finding.get('id_stable') or idx)
                self._add_node({"type": category, "id": objective_id, "label": finding.get("title", objective_type), "data": finding})
                self._add_edge(target_node_id, objective_id, "supports_objective")
                for related in metadata.get("supporting_findings", []) if isinstance(metadata.get("supporting_findings"), list) else []:
                    related_id = f"finding:db:{related}"
                    self._add_edge(objective_id, related_id, "requires")

        surface_mapping = vuln.get("surface_mapping", {})
        for port, data in surface_mapping.items():
            for _, items in data.get("tree", {}).items():
                for item in items:
                    node_id = self._node_id("surface", port, item["path"])
                    self._add_node({"type": "backend_endpoint", "id": node_id, "data": item})
                    self._add_edge(self._node_id("service", port), node_id, "exposes_surface")

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


    def build_mission_graph(self, mission_overview):
        self._reset()
        mission = mission_overview.get("mission", {}) if isinstance(mission_overview, dict) else {}
        mission_id = mission.get("id", "unknown")
        mission_node = self._node_id("mission", mission_id, mission.get("name", "mission"))
        self._add_node({"type": "mission", "id": mission_node, "label": mission.get("name", "Mission"), "data": mission})

        for asset in mission_overview.get("assets", []) if isinstance(mission_overview, dict) else []:
            asset_node = self._node_id("asset", asset.get("id"), asset.get("type"), asset.get("identifier"))
            self._add_node({"type": "asset", "id": asset_node, "label": asset.get("label") or asset.get("identifier"), "data": asset})
            self._add_edge(mission_node, asset_node, "contains")
            for target_id in asset.get("target_ids", []) if isinstance(asset.get("target_ids"), list) else []:
                target_node = self._node_id("target", target_id)
                self._add_node({"type": "target", "id": target_node, "label": f"target:{target_id}", "data": {"target_id": target_id}})
                self._add_edge(asset_node, target_node, "belongs_to")

        for finding in mission_overview.get("top_findings", []) if isinstance(mission_overview, dict) else []:
            finding_node = self._node_id("finding", finding.get("id_stable") or finding.get("id"))
            self._add_node({"type": "finding", "id": finding_node, "label": finding.get("title", "Finding"), "data": finding})
            scan_node = self._node_id("scan", finding.get("scan_id"))
            self._add_node({"type": "scan", "id": scan_node, "label": f"scan:{finding.get('scan_id')}", "data": {"scan_id": finding.get("scan_id")}})
            self._add_edge(scan_node, finding_node, "contains")

        for path in mission_overview.get("cross_asset_paths", []) if isinstance(mission_overview, dict) else []:
            path_node = self._node_id(path.get("category") or "attack_chain", path.get("title"))
            self._add_node({"type": path.get("category") or "attack_chain", "id": path_node, "label": path.get("title", "Path"), "data": path})
            self._add_edge(mission_node, path_node, "supports_objective")
            for aid in path.get("related_asset_ids", []) if isinstance(path.get("related_asset_ids"), list) else []:
                asset_node = self._node_id("asset", aid)
                self._add_node({"type": "asset", "id": asset_node, "label": f"asset:{aid}", "data": {"asset_id": aid}})
                self._add_edge(path_node, asset_node, "references")

        return {"nodes": self.nodes, "edges": self.edges}
