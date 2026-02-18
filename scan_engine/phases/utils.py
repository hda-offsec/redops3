from scan_engine.helpers.process_manager import ProcessManager

def extract_wp_data(stream, port, logger_func):
    """
    Parses WPScan CLI output into a structured dictionary for the UI.
    Returns (structured_data, full_raw_log)
    """
    data = {
        "version": "Unknown",
        "theme": "Unknown",
        "users": [],
        "plugins": [],
        "vulns": []
    }
    
    full_logs = []
    current_plugin = None
    
    for event in stream:
        if event["type"] == "stdout":
            line = ProcessManager.strip_ansi(event["line"].strip())
            if not line: continue
            
            # Log via the provided logger function
            logger_func(line, "INFO")
            full_logs.append(line)
            
            # 1. Version Detection
            if "WordPress version" in line and "identified" in line:
                import re
                ver_match = re.search(r"version\s+([\d\.]+)", line)
                if ver_match:
                    data["version"] = ver_match.group(1)
            
            # 2. Theme Detection
            if "Theme Name:" in line:
                data["theme"] = line.split("Theme Name:")[-1].strip()
            
            # 3. User Enumeration
            if "[+]" in line and "found" in line and "user" in line.lower():
                parts = line.split()
                if len(parts) > 1:
                    username = parts[1]
                    if username not in [u['name'] for u in data["users"]]:
                        data["users"].append({"name": username, "id": len(data["users"]) + 1})
            
            # 4. Plugin Detection (Matches Template Expectations)
            if "[+]" in line and "plugin" in line.lower() and not any(x in line.lower() for x in ["theme", "user", "version"]):
                # Simple slug extraction: [+] plugin-name
                parts = line.split()
                if len(parts) > 1:
                    slug = parts[1].strip()
                    if slug.islower():
                        current_plugin = {
                            "slug": slug,
                            "version": "Unknown",
                            "location": f"wp-content/plugins/{slug}",
                            "vulns": []
                        }
                        data["plugins"].append(current_plugin)

            # Capture version/location for the current plugin
            if current_plugin:
                if "Version:" in line:
                    current_plugin["version"] = line.split(":", 1)[1].strip()
                if "Location:" in line:
                    current_plugin["location"] = line.split(":", 1)[1].strip()

            # 5. Vulnerability indicators (Matches Template Expectations)
            if "[!]" in line:
                vuln_title = line.replace("[!]", "").strip()
                vuln_obj = {
                    "type": "Vulnerability",
                    "title": vuln_title,
                    "fixed_in": "Check WPScan"
                }
                data["vulns"].append(vuln_obj)
                if current_plugin:
                    current_plugin["vulns"].append(vuln_obj)
                
        elif event["type"] == "exit":
            logger_func(f"WPScan process for port {port} finished with code {event['code']}", "SUCCESS")
            
    return data, "\n".join(full_logs)

def emit_progress(orchestrator, percent, phase_name):
    """
    Emits progress update via the orchestrator's save_results method.
    """
    orchestrator.save_results(orchestrator.scan_id, {
        "progress": {
            "percent": percent,
            "current_phase": phase_name
        }
    })
