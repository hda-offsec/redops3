from urllib.parse import urlparse

class ContextAttackEngine:
    """
    V6 Evolution: Analyzes enumeration intelligence to adapt the offensive strategy.
    Transforms raw tech detection into actionable attack profiles.
    """
    def __init__(self, results, logger=None):
        self.results = results
        self.log = logger
        
    def build_attack_profile(self, port):
        """
        Analyzes WhatWeb, tech scores, and endpoint semantics for a specific port.
        """
        stack = []
        risk_vectors = []
        port_str = str(port)
        
        # 1. Extract Tech Stack from WhatWeb
        enum_data = self.results.get('phases', {}).get('enum', {})
        ww_data = enum_data.get('whatweb', {}).get(port_str, {})
        
        # Heuristics for stack detection
        full_text = str(ww_data).lower()
        if any(x in full_text for x in ['php', 'apache', 'phpsessid']):
            stack.append("php")
        if any(x in full_text for x in ['node', 'express', 'next.js', 'react']):
            stack.append("node")
        if any(x in full_text for x in ['wordpress', 'wp-content']):
            stack.append("wordpress")
        if any(x in full_text for x in ['python', 'django', 'flask', 'gunicorn']):
            stack.append("python_web")
        if any(x in full_text for x in ['asp.net', 'iis', '.net', 'aspx']):
            stack.append("dotnet")

        # 2. Analyze Endpoint Semantics (Risk Vectors)
        # We look at normalized endpoints found on this port
        endpoints = enum_data.get('normalized', {}).get(port_str, {}).get('endpoints', [])
        
        vector_keywords = {
            "redirect": ["redirect", "url=", "next=", "dest=", "return", "goto"],
            "file": ["file", "path", "page", "include", "template", "doc"],
            "auth": ["login", "admin", "auth", "session", "user"],
            "api": ["api", "v1", "v2", "json", "graphql", "rest"],
            "upload": ["upload", "import", "attachment"]
        }
        
        seen_paths = " ".join([ep.get('url', '').lower() for ep in endpoints])
        for vector, keywords in vector_keywords.items():
            if any(kw in seen_paths for kw in keywords):
                risk_vectors.append(vector)

        profile = {
            "stack": list(set(stack)),
            "risk_vectors": list(set(risk_vectors)),
            "confidence": 70 if stack else 40
        }
        
        if self.log:
            self.log(f"ContextAttackEngine: profile={profile['stack']} vectors={profile['risk_vectors']}", "DEBUG")
            
        return profile

    def derive_mutation_strategy(self, profile):
        """
        Transforms a profile into a set of enabled mutation flags and extra parameters.
        """
        strategy = {
            "enable_lfi": False,
            "enable_ssrf": False,
            "enable_proto_pollution": False,
            "enable_wp_routes": False,
            "enable_json_mutations": False,
            "extra_params": []
        }
        
        stack = profile.get("stack", [])
        vectors = profile.get("risk_vectors", [])
        
        if "php" in stack:
            strategy["enable_lfi"] = True
            strategy["extra_params"].extend(["file", "path", "page", "include"])
            
        if "node" in stack:
            strategy["enable_json_mutations"] = True
            strategy["enable_proto_pollution"] = True
            strategy["extra_params"].extend(["__proto__", "constructor", "prototype"])
            
        if "wordpress" in stack:
            strategy["enable_wp_routes"] = True
            strategy["extra_params"].extend(["rest_route", "action"])
            
        if "redirect" in vectors or "api" in vectors:
            strategy["enable_ssrf"] = True
            strategy["extra_params"].extend(["url", "redirect", "next", "dest", "uri", "callback"])
            
        # Deduplicate extra params
        strategy["extra_params"] = list(set(strategy["extra_params"]))
        
        if self.log:
            self.log(f"Mutation Strategy Enabled: {strategy}", "INFO")
            
        return strategy
