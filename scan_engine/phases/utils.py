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

            logger_func(line, "INFO")
            full_logs.append(line)

            # === SECTION DETECTION ===
            # WPScan outputs sections like:
            #   [+] WordPress version 6.4.3 identified
            #   [+] WordPress theme in use: flavor
            #   [i] Plugin(s) Identified:
            #   [+] contact-form-7
            #   [+] revslider

            # 1. WordPress Core Version
            if "WordPress version" in line and "identified" in line:
                ver_match = re.search(r"version\s+([\d\.]+)", line)
                if ver_match:
                    data["version"] = ver_match.group(1)
                current_section = "core"
                current_component_name = f"WordPress Core {data['version']}"
                current_plugin = None

            # 2. Theme Detection
            elif "WordPress theme in use:" in line or "Theme Name:" in line:
                current_section = "theme"
                if "theme in use:" in line:
                    theme_name = line.split("theme in use:")[-1].strip()
                elif "Theme Name:" in line:
                    theme_name = line.split("Theme Name:")[-1].strip()
                else:
                    theme_name = "Unknown"
                data["theme"] = theme_name
                current_component_name = f"Theme: {theme_name}"
                current_plugin = None

            # 3. Plugin Section Header
            elif "Plugin(s) Identified" in line or "plugin(s) identified" in line.lower():
                current_section = "plugin"
                current_plugin = None

            # 4. Individual Plugin Entry: [+] <slug>
            # WPScan prints plugin names as "[+] slug" with no extra keywords
            elif current_section == "plugin" and line.startswith("[+]"):
                slug_part = line.replace("[+]", "").strip()
                # Plugin slugs are lowercase, may contain dashes/underscores
                if slug_part and re.match(r'^[a-z0-9_-]+$', slug_part):
                    current_plugin = {
                        "slug": slug_part,
                        "version": "Unknown",
                        "location": f"wp-content/plugins/{slug_part}",
                        "vulns": []
                    }
                    data["plugins"].append(current_plugin)
                    current_component_name = f"Plugin: {slug_part}"

            # 5. User Enumeration
            elif "[+]" in line and "found" in line and "user" in line.lower():
                parts = line.split()
                if len(parts) > 1:
                    username = parts[1]
                    if username not in [u['name'] for u in data["users"]]:
                        data["users"].append({"name": username, "id": len(data["users"]) + 1})

            # === METADATA for current plugin/theme ===
            if "Version:" in line and "version" not in line.lower().split("version:")[0][-10:].lower():
                version_val = line.split("Version:")[-1].strip().split()[0] if line.split("Version:")[-1].strip() else "Unknown"
                # Remove trailing punctuation
                version_val = version_val.rstrip(",;.")
                if current_plugin:
                    current_plugin["version"] = version_val
            if "Location:" in line:
                loc_val = line.split("Location:")[-1].strip()
                if current_plugin:
                    current_plugin["location"] = loc_val

            # === VULNERABILITY INDICATORS ===
            # Lines with [!] are warnings/vulns
            if "[!]" in line:
                vuln_title_raw = line.replace("[!]", "").strip().lstrip("| ").strip()

                # Prepend the component name so the UI shows WHAT is affected
                if current_component_name:
                    vuln_title = f"[{current_component_name}] {vuln_title_raw}"
                else:
                    vuln_title = vuln_title_raw

                vuln_obj = {
                    "type": "Vulnerability",
                    "title": vuln_title,
                    "component": current_component_name or "Unknown",
                    "raw_title": vuln_title_raw,
                    "fixed_in": "Check WPScan"
                }

                # Try to extract "fixed in" version
                fixed_match = re.search(r"fixed in (?:version )?([\d\.]+)", vuln_title_raw, re.IGNORECASE)
                if fixed_match:
                    vuln_obj["fixed_in"] = fixed_match.group(1)

                data["vulns"].append(vuln_obj)
                if current_plugin:
                    current_plugin["vulns"].append(vuln_obj)

            # === Latest Version info (captures "latest version is X.Y.Z") ===
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
