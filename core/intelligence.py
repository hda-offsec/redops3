from core.kb import RED_TEAM_KB, GENERAL_TIPS

class AttackVectorMapper:
    """
    The Brain of RedOps3.
    Maps discovered services/versions to specific Red Team TTPs and exploitable vectors.
    Includes prioritization scoring.
    """

    @staticmethod
    def analyze_service(service_name, version, port):
        vectors = []
        
        # Ensure we have strings even if nmap returns None
        service_name = (service_name or "").lower()
        version = (version or "").lower()

        # 1. Rule-based KB Lookup
        for category, subcats in RED_TEAM_KB.items():
            for subcat, rules in subcats.items():
                if subcat in service_name or subcat in version:
                    for rule in rules:
                        # Match version or "all"
                        if rule["match"] == "all" or rule["match"] in version:
                            vectors.append({
                                "category": category.upper(),
                                "risk": rule["risk"],
                                "score": rule.get("score", 50),
                                "name": rule["name"],
                                "description": rule["desc"],
                                "action": rule["action"]
                            })

        # 2. General TTP Tips based on Port
        for tip in GENERAL_TIPS:
            if tip["port"] == port:
                vectors.append({
                    "category": "TIP",
                    "risk": "INFO",
                    "score": 10,
                    "name": f"Offensive Tip (Port {port})",
                    "description": tip["tip"],
                    "action": f"Use {tip['tool']} for further enumeration."
                })

        # 3. Default Fallback for Web
        if not any(v['category'] == 'WEB' for v in vectors):
            if 'http' in service_name or port in [80, 443, 8080, 8443]:
                vectors.append({
                    "category": "WEB",
                    "risk": "HIGH",
                    "score": 70,
                    "name": "Web Application Surface",
                    "description": "Port runs a web server. Potential for SQLi, XSS, RCE.",
                    "action": f"Check tech stack (Wappalyzer) and fuzz directories (ffuf). Access: http://<target>:{port}"
                })

        # Sort by score descending (Prioritization)
        vectors.sort(key=lambda x: x['score'], reverse=True)
        
        return vectors

    @staticmethod
    def get_ip_geolocation(target, callback=None):
        """
        Retrieves real-time geographical data for an IP/Domain.
        Uses ip-api.com (free for non-commercial use).
        If callback is provided, runs in a separate thread and calls callback(result).
        Otherwise, runs synchronously.
        """
        def _fetch():
            import requests
            try:
                # We don't need an API key for the basic JSON endpoint up to 45 requests/min
                res = requests.get(f"http://ip-api.com/json/{target}?fields=status,message,country,city,isp,lat,lon", timeout=5)
                if res.status_code == 200:
                    data = res.json()
                    if data.get("status") == "success":
                        return {
                            "country": data.get("country"),
                            "city": data.get("city"),
                            "isp": data.get("isp"),
                            "lat": data.get("lat"),
                            "lon": data.get("lon")
                        }
            except:
                pass
            return None

        if callback:
            import threading
            def _runner():
                result = _fetch()
                callback(result)
            t = threading.Thread(target=_runner)
            t.daemon = True
            t.start()
            return t
        else:
            return _fetch()
