import re
from scan_engine.helpers.process_manager import ProcessManager


def extract_wp_data(stream, port, logger_func):
    """
    Parses WPScan CLI output into a structured dictionary for the UI.
    Uses a state machine to track which component (core, theme, plugin)
    each vulnerability belongs to.

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
    current_section = None  # 'core', 'theme', or 'plugin'
    current_component_name = None  # name of the theme/plugin currently being parsed

    for event in stream:
        if event["type"] == "stdout":
            line = ProcessManager.strip_ansi(event["line"].strip())
            if not line:
                continue

            # logger_func(line, "INFO")
            full_logs.append(line)

            # === SECTION DETECTION ===
            if "WordPress version" in line and "identified" in line:
                ver_match = re.search(r"version\s+([\d\.]+)", line)
                if ver_match: data["version"] = ver_match.group(1)
                current_section = "core"
                current_component_name = f"WordPress Core {data['version']}"
                current_plugin = None

            elif "theme in use:" in line.lower() or "theme name:" in line.lower():
                current_section = "theme"
                theme_name = line.split(":")[-1].strip() if ":" in line else "Unknown"
                if data["theme"] == "Unknown":
                    data["theme"] = theme_name
                current_component_name = f"Theme: {theme_name}"
                current_plugin = None

            elif "plugin(s) identified" in line.lower() or "enumerating plugins" in line.lower() or "enumerating vulnerable plugins" in line.lower():
                current_section = "plugin"
                current_plugin = None

            elif "User(s) Identified" in line or "Enumerating Identifiers" in line:
                current_section = "users"
                current_plugin = None

            elif current_section == "plugin" and line.startswith("[+]"):
                slug_part = line.replace("[+]", "").strip().split()[0]
                # exclude common WPScan headers
                if slug_part and slug_part.lower() not in ["enumerating", "plugins", "wordpress", "wp"] and re.match(r'^[a-zA-Z0-9_-]+$', slug_part):
                    current_plugin = {
                        "slug": slug_part,
                        "version": "Unknown",
                        "location": f"wp-content/plugins/{slug_part}",
                        "vulns": []
                    }
                    data["plugins"].append(current_plugin)
                    current_component_name = f"Plugin: {slug_part}"

            # 2. Individual User Entry: [+] <name>
            elif current_section == "users" and line.startswith("[+]"):
                username = line.replace("[+]", "").strip().split()[0]
                # Filter out WPScan summary/meta lines
                wp_meta_keywords = ["Finished:", "Requests", "Cached", "Data", "Memory", "Elapsed"]
                if username and username not in wp_meta_keywords and username not in [u['name'] for u in data["users"]]:
                    data["users"].append({"name": username, "id": len(data["users"]) + 1})
                    logger_func(f"WordPress User Found: {username}", "SUCCESS")

            # === METADATA & VULNS ===
            if "Version:" in line and current_plugin:
                vmatch = re.search(r"Version:\s*([\d\.]+)", line)
                if vmatch: current_plugin["version"] = vmatch.group(1)
            
            if "Location:" in line and current_plugin:
                current_plugin["location"] = line.split("Location:")[-1].strip()

            if "[!]" in line:
                vuln_title_raw = line.replace("[!]", "").strip().lstrip("| ").strip()
                vuln_title = f"[{current_component_name}] {vuln_title_raw}" if current_component_name else vuln_title_raw
                
                vuln_obj = {
                    "type": "Vulnerability",
                    "title": vuln_title,
                    "component": current_component_name or "Unknown",
                    "raw_title": vuln_title_raw,
                    "fixed_in": "Check WPScan"
                }
                fixed_match = re.search(r"fixed in (?:version )?([\d\.]+)", vuln_title_raw, re.IGNORECASE)
                if fixed_match: vuln_obj["fixed_in"] = fixed_match.group(1)

                data["vulns"].append(vuln_obj)
                if current_plugin: current_plugin["vulns"].append(vuln_obj)

            latest_match = re.search(r"latest version is ([\d\.]+)", line, re.IGNORECASE)
            if latest_match and current_plugin:
                current_plugin["latest_version"] = latest_match.group(1)

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
