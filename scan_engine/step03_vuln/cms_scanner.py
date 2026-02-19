from scan_engine.helpers.process_manager import ProcessManager
import shlex

class CMSScanner:
    def __init__(self, target):
        self.target = target
        # Map CMS names to Nuclei tags/templates
        self.cms_map = {
            "wordpress": {"tag": "wordpress", "tool": "wpscan"},
            "joomla": {"tag": "joomla", "tool": "joomla-scan"},
            "drupal": {"tag": "drupal", "tool": "droopescan"},
            "magento": {"tag": "magento", "tool": "magento-scan"},
            "prestashop": {"tag": "prestashop", "tool": "prestashop-scan"},
            "bitrix": {"tag": "bitrix", "tool": "bitrix-scan"},
            "typo3": {"tag": "typo3", "tool": "typo3-scan"}
        }

    def detect_cms(self, whatweb_output):
        """Identifies CMS from WhatWeb findings."""
        detected = []
        for cms in self.cms_map.keys():
            if cms.lower() in whatweb_output.lower():
                detected.append(cms)
        return detected

    def audit_cms(self, url, cms_name, logger=None):
        """
        Runs a specialized audit for a detected CMS using Nuclei expert templates.
        """
        findings = []
        if logger: logger(f"CMS Audit: Running deep scan for {cms_name.upper()} on {url}...", "INFO")
        
        # We use Nuclei with specific tags for the CMS
        tag = self.cms_map.get(cms_name.lower(), {}).get("tag", cms_name.lower())
        
        command = [
            "nuclei",
            "-u", url,
            "-tags", tag,
            "-severity", "low,medium,high,critical",
            "-jsonl",
            "-silent"
        ]
        
        try:
            stream = ProcessManager.stream_command(command)
            for event in stream:
                if event['type'] == 'stdout':
                    import json
                    try:
                        data = json.loads(event['line'])
                        findings.append({
                            "title": f"CMS Vulnerability [{cms_name.upper()}]: {data.get('info', {}).get('name')}",
                            "description": f"Template: {data.get('template-id')}\nDescription: {data.get('info', {}).get('description')}\nURL: {data.get('matched-at')}",
                            "severity": data.get('info', {}).get('severity', 'info'),
                            "tool_source": f"cms_scanner_{cms_name}"
                        })
                    except Exception: continue
        except Exception as e:
            if logger: logger(f"CMS Audit failed for {cms_name}: {e}", "DEBUG")
            
        return findings

    def run_all(self, web_results, logger=None):
        """
        Dispatches scans based on detected technologies.
        web_results is a dict: {port: whatweb_output}
        """
        all_findings = []
        for port, output in web_results.items():
            detected = self.detect_cms(output)
            if detected:
                # Determine protocol
                proto = "https" if "443" in str(port) else "http"
                url = f"{proto}://{self.target}:{port}"
                
                for cms in detected:
                    findings = self.audit_cms(url, cms, logger)
                    all_findings.extend(findings)
                    
        return all_findings
