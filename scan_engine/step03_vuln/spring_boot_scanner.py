from scan_engine.helpers.http_client import get_session

class SpringBootScanner:
    """
    Expert Scanner for Spring Boot Actuators & Sensitive Endpoints.
    Checks for exposed actuator endpoints that leak environment variables, heap dumps, or allow RCE.
    """
    def __init__(self, target, options=None):
        self.options = options
        self.target = target
        self.endpoints = [
            "/actuator",
            "/actuator/env",
            "/actuator/health",
            "/actuator/metrics",
            "/actuator/httptrace",
            "/actuator/mappings",
            "/actuator/beans",
            "/actuator/configprops",
            "/actuator/heapdump",
            "/actuator/threaddump",
            "/actuator/loggers",
            "/actuator/auditevents",
            "/env",
            "/v2/api-docs",
            "/swagger-ui.html"
        ]

    def scan_actuators(self, port, protocol='http', logger=None):
        """
        Scans for common Spring Boot Actuator endpoints.
        """
        findings = []
        base_url = f"{protocol}://{self.target}:{port}"
        
        if logger: 
            logger(f"Spring Boot Expert: Probing for {len(self.endpoints)} actuator endpoints on port {port}...", "INFO")

        # Session for speed & reuse
        session = get_session(self.options)
        session.verify = True
        # Set a generic User-Agent
        session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; RedOps3/SpringBootAudit)"})
        
        for endpoint in self.endpoints:
            url = f"{base_url}{endpoint}"
            try:
                # Use GET with a short timeout
                resp = session.get(url, timeout=4, allow_redirects=False)
                
                # Check for successful response
                if resp.status_code == 200:
                    # Heuristics to confirm it's actually an Actuator endpoint
                    content_type = resp.headers.get("Content-Type", "").lower()
                    text_sample = resp.text[:500].lower()
                    
                    is_valid = False
                    severity = "low"
                    title = f"Spring Boot Actuator Exposed: {endpoint}"
                    desc = f"Exposed endpoint at {url} returns 200 OK."

                    # Specific checks per endpoint
                    if "env" in endpoint:
                        if "profiles" in text_sample or "server.port" in text_sample or "masked" in text_sample:
                            is_valid = True
                            severity = "critical"
                            title = "CRITICAL: Spring Boot Env Leak"
                            desc += "\n\nEvidence: Response contains environment properties."
                    elif "heapdump" in endpoint:
                        # Heapdump is binary, check content-type or size
                        if "application/octet-stream" in content_type or len(resp.content) > 10000:
                            is_valid = True
                            severity = "critical"
                            title = "CRITICAL: Spring Boot Heap Dump"
                            desc += "\n\nEvidence: Heap dump file accessible. Contains ALL memory data (passwords, keys)."
                    elif "mappings" in endpoint or "beans" in endpoint:
                        if "bean" in text_sample or "dispatcherServlet" in text_sample:
                            is_valid = True
                            severity = "medium"
                    elif "health" in endpoint:
                        if "status" in text_sample and "up" in text_sample:
                            is_valid = True
                            severity = "info" # Health is often public
                    elif "swagger" in endpoint or "api-docs" in endpoint:
                        if "swagger" in text_sample or "openapi" in text_sample:
                            is_valid = True
                            severity = "low"
                            title = "Swagger UI / API Docs Exposed"
                    else:
                        # Fallback: if it looks like JSON and has typical actuator keywords
                        if "application/json" in content_type or "application/vnd.spring-boot" in content_type:
                            is_valid = True
                            severity = "medium"

                    if is_valid:
                        if logger: 
                            logger(f"🌱 Spring Boot: Found {endpoint} ({severity.upper()})", "WARN")
                        
                        from scan_engine.helpers.finding_normalizer import FindingNormalizer
                        findings.append(FindingNormalizer.from_response(
                            resp,
                            title=title,
                            description=desc,
                            severity=severity,
                            tool_source="spring_boot_scanner",
                            category="vuln",
                            method="GET"
                        ))
            
            except Exception as e:
                # logger(f"Debug: {url} failed: {e}", "DEBUG")
                continue

        return findings
