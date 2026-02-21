from scan_engine.helpers.process_manager import ProcessManager
import json

class JSVulnScanner:
    def __init__(self, target, options=None):
        self.options = options
        self.target = target

    def audit_js_endpoints(self, url, logger=None):
        """
        Uses Nuclei to identify vulnerable JavaScript libraries on a specific URL.
        """
        findings = []
        if logger: logger(f"JS Audit: Checking for vulnerable JS dependencies on {url}...", "INFO")
        
        command = [
            "nuclei",
            "-u", url,
            "-tags", "tech-detect,vuln,library",
            "-severity", "low,medium,high,critical",
            "-jsonl",
            "-silent"
        ]
        
        try:
            stream = ProcessManager.stream_command(command)
            for event in stream:
                if event['type'] == 'stdout':
                    try:
                        data = json.loads(event['line'])
                        name = data.get('info', {}).get('name', 'Vulnerability')
                        
                        # Only keep findings related to JS tech/libraries or common vulns
                        findings.append({
                            "title": f"JS Vulnerability: {name}",
                            "description": f"Library/Technology: {data.get('matched-at')}\nDescription: {data.get('info', {}).get('description')}",
                            "severity": data.get('info', {}).get('severity', 'info'),
                            "tool_source": "js_dependency_scanner"
                        })
                    except Exception: continue
        except Exception as e:
            if logger: logger(f"JS Audit failed: {e}", "DEBUG")
            
        return findings
