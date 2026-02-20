from scan_engine.helpers.process_manager import ProcessManager

class KatanaScanner:
    def __init__(self, target):
        self.target = target

    def check_tools(self):
        return ProcessManager.find_binary_path("katana") is not None

    def get_command(self, port, protocol='http', quick=False):
        url = f"{protocol}://{self.target}:{port}"
        katana_path = ProcessManager.find_binary_path("katana") or "katana"
        
        # --- IP TARGET SAFETY ---
        import re
        is_ip = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", self.target)
        
        cmd = [
            katana_path,
            "-u", url,
            "-jc",           # JSON output
            "-jsl",          # JS Library detection
            "-kf", "all",    # Keep all fields
            "-d", "1" if quick else "3",
            "-ct", "5" if quick else "10",
            "-silent",
            "-nc",
            "-aff",          # Automatic Form Filling
        ]
        
        if not quick:
            cmd.extend([
                "-js-crawl",     # Enable JavaScript crawling
                "-xhr",          # Extract XHR requests
            ])
        
        # Only apply Root Domain Filter if NOT an IP
        if not is_ip:
            cmd.extend(["-fs", "rdn"])
            
        # REDIRECT STRATEGY: removed -dr to allow katana handle redirects properly for coverage
        # unless explicit strict mode is enabled (hardcoded to False for offensive depth)
        ENABLE_STRICT_REDIRECT_MODE = False
        if ENABLE_STRICT_REDIRECT_MODE:
            cmd.append("-dr")
            
        return cmd

    def stream_katana(self, port, protocol='http', quick=False):
        import json
        command = self.get_command(port, protocol, quick=quick)
        
        # Parse JSON output because -jc is used
        for event in ProcessManager.stream_command(command):
            if event.get("type") == "stdout":
                line = event.get("line", "").strip()
                if not line: continue
                
                try:
                    # Katana output is JSON line
                    data = json.loads(line)
                    # --- FALLBACK CHAIN FOR JSON EXTRACTION ---
                    req = data.get("request", {})
                    resp = data.get("response", {})
                    
                    url = req.get("endpoint") or req.get("url") or resp.get("endpoint") or resp.get("url")
                    
                    if url and isinstance(url, str) and url.startswith("http"):
                        # Replace raw JSON line with cleaned URL
                        yield {"type": "stdout", "line": url, "original": line}
                    else:
                        # Silently drop invalid/meta lines or yield info
                        if "level" in data: pass
                        else: yield event
                except (json.JSONDecodeError, Exception):
                    # Not JSON or extraction failed? Just yield if looks like URL
                    if line.startswith("http"):
                        yield {"type": "stdout", "line": line}
                    else:
                        yield event
            else:
                yield event

    def stream_scan(self, port, protocol='http', quick=False):
        """Alias for stream_katana to satisfy enum.py contract"""
        return self.stream_katana(port, protocol, quick=quick)
