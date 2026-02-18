from scan_engine.helpers.process_manager import ProcessManager

class KatanaScanner:
    def __init__(self, target):
        self.target = target

    def check_tools(self):
        return ProcessManager.find_binary_path("katana") is not None

    def get_command(self, port, protocol='http'):
        url = f"{protocol}://{self.target}:{port}"
        katana_path = ProcessManager.find_binary_path("katana") or "katana"
        return [
            katana_path,
            "-u", url,
            "-jc",           # JSON output
            "-jsl",          # JS Library detection
            "-kf", "all",    # Keep all fields
            "-d", "3",       # Reduced depth slightly for speed
            "-fs", "rdn",    # Filter scope (Root Domain - captures static, cdn, etc)
            "-ct", "10",     # Crawl duration
            "-silent",
            "-nc",
            
            # DEEP CRAWL FLAGS (Removed -headless as it causes issues)
            "-js-crawl",     # Enable JavaScript crawling
            "-xhr",          # Extract XHR requests
            "-aff",          # Automatic Form Filling
            "-dr",           # Disable redirect following (let katana handle it)
        ]

    def stream_katana(self, port, protocol='http'):
        import json
        command = self.get_command(port, protocol)
        
        # Parse JSON output because -jc is used
        for event in ProcessManager.stream_command(command):
            if event.get("type") == "stdout":
                line = event.get("line", "").strip()
                try:
                    # Katana output is JSON line
                    data = json.loads(line)
                    # Robust extraction: check multiple potential fields
                    req = data.get("request", {})
                    resp = data.get("response", {})
                    
                    url = req.get("endpoint") or req.get("url") or resp.get("endpoint")
                    
                    if url:
                        # Replace raw JSON line with cleaned URL
                        yield {"type": "stdout", "line": url, "original": line}
                    else:
                        # Fallback for non-request lines (info, etc)
                        yield event
                except json.JSONDecodeError:
                    # Not JSON? Just yield as is (maybe error or info)
                    yield event
                except Exception:
                    yield event
            else:
                yield event

    def stream_scan(self, port, protocol='http'):
        """Alias for stream_katana to satisfy enum.py contract"""
        return self.stream_katana(port, protocol)
