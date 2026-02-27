from scan_engine.helpers.http_client import get_session

class EnterpriseScanner:
    """
    V6 EXPERT: Enterprise Technology Auditor.
    Specialized probes for ColdFusion, AEM (Adobe Experience Manager), and Telerik.
    """
    def __init__(self, target, options=None):
        self.options = options
        self.target = target
        self.session = get_session(self.options)
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (RedOps3-Enterprise-Expert)"})

    def check_coldfusion(self, base_url, logger=None):
        findings = []
        # CVE-2010-2861, etc.
        paths = [
            "/CFIDE/administrator/enter.cfm",
            "/CFIDE/administrator/entermany.cfm",
            "/CFIDE/administrator/settings/index.cfm"
        ]
        for p in paths:
            url = f"{base_url}{p}"
            try:
                r = self.session.get(url, timeout=5, verify=False)
                # Hardened Detection: Page must be 200 OK and contains specific markers
                # Generic "ColdFusion" string is too weak.
                is_detected = False
                if r.status_code == 200:
                    if "ColdFusion Administrator" in r.text or "CFIDE" in r.text or "RDSPassword" in r.text:
                        is_detected = True

                if is_detected:
                    # Build evidence
                    req_dump = f"GET {url} HTTP/1.1\nHost: {self.target}\n"
                    res_dump = f"HTTP/1.1 {r.status_code} {r.reason}\n"
                    res_dump += f"\n{r.text[:2000]}..." # Snippet

                    findings.append({
                        "title": "Medium: Adobe ColdFusion Admin Panel Exposed",
                        "description": (
                            f"A ColdFusion administrator interface was confirmed at `{url}`.\n\n"
                            f"**Validation Evidence**:\n"
                            f"- Status Code: 200 OK\n"
                            f"- Source Code Check: Found 'ColdFusion Administrator' login markers."
                        ),
                        "severity": "medium",
                        "tool_source": "enterprise_expert",
                        "url": url,
                        "request": req_dump,
                        "response": res_dump,
                        "repro_command": f"curl -v '{url}'"
                    })
                    if logger: logger(f"🚩 ENTERPRISE: ColdFusion Admin found at {url}", "SUCCESS")
            except Exception: pass
        return findings

    def check_aem(self, base_url, logger=None):
        findings = []
        # Adobe Experience Manager Info Leaks
        paths = [
            "/content/dam.json",
            "/etc/cloudservices.json",
            "/libs/cq/ui/widgets.js",
            "/system/console/configMgr"
        ]
        for p in paths:
            url = f"{base_url}{p}"
            try:
                r = self.session.get(url, timeout=3, verify=False)
                if r.status_code == 200:
                    severity = "high" if "system/console" in p else "low"
                    findings.append({
                        "title": f"AEM: Exposed Endpoint Detected ({p})",
                        "description": f"Adobe Experience Manager sensitive path leaked: `{url}`.",
                        "severity": severity,
                        "tool_source": "enterprise_expert",
                        "url": url
                    })
            except Exception: pass
        return findings

    def check_telerik(self, base_url, logger=None):
        findings = []
        # Telerik UI for ASP.NET AJAX vulnerabilities (CVE-2017-11317, etc.)
        paths = [
            "/Telerik.Web.UI.WebResource.axd",
            "/Telerik.Web.UI.DialogHandler.aspx"
        ]
        for p in paths:
            url = f"{base_url}{p}"
            try:
                r = self.session.get(url, timeout=3, verify=False)
                if r.status_code == 200 and "Telerik" in r.text:
                    findings.append({
                        "title": "Low: Telerik UI Component Detected",
                        "description": f"Telerik UI components identified at `{url}`. Check for version-specific CVEs (e.g. CVE-2019-18935).",
                        "severity": "low",
                        "tool_source": "enterprise_expert",
                        "url": url
                    })
            except Exception: pass
        return findings

    def scan(self, port, protocol='http', logger=None):
        findings = []
        base_url = f"{protocol}://{self.target}:{port}"
        if logger: logger(f"Enterprise Expert: Auditing Technology stack on {base_url}...", "INFO")
        
        findings.extend(self.check_coldfusion(base_url, logger))
        findings.extend(self.check_aem(base_url, logger))
        findings.extend(self.check_telerik(base_url, logger))
        
        return findings
