from scan_engine.helpers.process_manager import ProcessManager
import scan_engine.helpers.http_client as http_client
import json
import re


class JSVulnScanner:
    """
    V8: JS Vulnerability + WordPress Plugin Validator.
    Includes evidence-based WPS Hide Login validation.
    """
    def __init__(self, target, options=None):
        self.options = options
        self.target = target

    def audit_js_endpoints(self, url, logger=None):
        """
        Uses Nuclei to identify vulnerable JavaScript libraries on a specific URL.
        Applies post-validation for known false-positive-prone templates.
        """
        raw_findings = []
        if logger:
            logger(f"JS Audit: Checking for vulnerable JS dependencies on {url}...", "INFO")

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
                        matched_at = data.get('matched-at', '')
                        template_id = data.get('template-id', '')

                        raw_findings.append({
                            "title": f"JS Vulnerability: {name}",
                            "description": f"Library/Technology: {matched_at}\nDescription: {data.get('info', {}).get('description')}",
                            "severity": data.get('info', {}).get('severity', 'info'),
                            "tool_source": "js_dependency_scanner",
                            "template_id": template_id,
                            "matched_at": matched_at,
                            "raw_data": data,
                        })
                    except Exception:
                        continue
        except Exception as e:
            if logger:
                logger(f"JS Audit failed: {e}", "DEBUG")

        # Post-validation: WPS Hide Login requires evidence
        validated = []
        for f in raw_findings:
            if 'wps-hide-login' in f.get('template_id', '').lower() or 'wps hide login' in f.get('title', '').lower():
                # Apply WPS Hide Login validation
                result = self._validate_wps_hide_login(url, logger)
                if result:
                    validated.append(result)
                else:
                    if logger:
                        logger(f"JS Audit: WPS Hide Login FP suppressed — validation failed", "DEBUG")
            else:
                # Remove internal fields before returning
                f.pop('template_id', None)
                f.pop('matched_at', None)
                f.pop('raw_data', None)
                validated.append(f)

        return validated

    # ------------------------------------------------------------------
    # WPS HIDE LOGIN VALIDATOR
    # ------------------------------------------------------------------

    def _validate_wps_hide_login(self, base_url, logger=None):
        """
        V9 Formal WPS Hide Login Validator.

        Finding valid only if ALL predicates hold:
          L₀ blocked:         /wp-login.php returns 404 or non-login redirect
          L₁ accessible:      custom slug works (if discoverable)
          P reveals L₀:       /wp-admin/?action=postpass exposes login form
          Plugin confirmed:   readme.txt or wp-json enumeration
          Version ≤ 1.9.15.2: extracted from readme

        Redirect equality with default WordPress = NOT VULNERABLE.
        """
        validation_path = []
        evidence = {
            "login_hidden": False,
            "custom_slug_works": None,  # None = not tested
            "plugin_installed": False,
            "version_vulnerable": False,
            "version_detected": "Unknown",
            "bypass_confirmed": False,
        }

        # STEP 1 — L₀: Is login actually hidden?
        login_hidden = False
        default_redirects_to_login = False
        for path in ['/wp-login.php', '/wp-admin/']:
            try:
                r = http_client.get(
                    f"{base_url}{path}",
                    options=self.options,
                    timeout=8,
                    allow_redirects=False
                )
                if r.status_code == 404:
                    login_hidden = True
                elif r.status_code in [301, 302, 303, 307]:
                    loc = r.headers.get('Location', '').lower()
                    if 'wp-login' in loc or 'wp-admin' in loc:
                        # Default WP redirect behavior → NOT hidden
                        default_redirects_to_login = True
                    else:
                        login_hidden = True
                elif r.status_code == 200:
                    body_lower = r.text[:2000].lower()
                    if 'loginform' in body_lower or 'user_login' in body_lower:
                        # Login form accessible → NOT hidden
                        default_redirects_to_login = True
            except Exception:
                continue

        validation_path.append(f"L0_blocked={login_hidden}")

        if not login_hidden:
            if logger:
                logger(
                    "WPS V9: L₀ NOT blocked. Default login accessible. "
                    "No vulnerability.", "DEBUG"
                )
            return None

        # Redirect equality guard: if both paths just redirect to each other
        # this is default WP behavior, not WPS Hide Login
        if default_redirects_to_login:
            if logger:
                logger(
                    "WPS V9: Redirect equality with default WP behavior. "
                    "Suppressing.", "DEBUG"
                )
            return None

        evidence["login_hidden"] = True

        # STEP 2 — Confirm plugin installed
        plugin_paths = [
            '/wp-content/plugins/wps-hide-login/readme.txt',
            '/wp-content/plugins/wps-hide-login/wps-hide-login.php',
        ]
        version = None

        for path in plugin_paths:
            try:
                r = http_client.get(
                    f"{base_url}{path}",
                    options=self.options,
                    timeout=5,
                    allow_redirects=True
                )
                if r.status_code == 200 and (
                    'wps hide login' in r.text.lower()
                    or 'stable tag' in r.text.lower()
                ):
                    evidence["plugin_installed"] = True
                    ver_match = re.search(
                        r'Stable tag:\s*(\d+\.\d+[\.\d]*)', r.text, re.I
                    )
                    if ver_match:
                        version = ver_match.group(1)
                        evidence["version_detected"] = version
                    break
            except Exception:
                continue

        # REST API fallback
        if not evidence["plugin_installed"]:
            try:
                r = http_client.get(
                    f"{base_url}/wp-json/wp/v2/plugins",
                    options=self.options,
                    timeout=5
                )
                if r.status_code == 200 and 'wps-hide-login' in r.text.lower():
                    evidence["plugin_installed"] = True
            except Exception:
                pass

        validation_path.append(f"plugin_installed={evidence['plugin_installed']}")

        if not evidence["plugin_installed"]:
            if logger:
                logger(
                    "WPS V9: Plugin NOT confirmed. Suppressing.", "DEBUG"
                )
            return None

        # STEP 3 — Version vulnerability (≤ 1.9.15.2)
        if version:
            try:
                vparts = [int(x) for x in version.split('.')]
                vuln_parts = [1, 9, 15, 2]
                is_vuln = False
                for i in range(max(len(vparts), len(vuln_parts))):
                    a = vparts[i] if i < len(vparts) else 0
                    b = vuln_parts[i] if i < len(vuln_parts) else 0
                    if a < b:
                        is_vuln = True
                        break
                    elif a > b:
                        break
                else:
                    is_vuln = True
                evidence["version_vulnerable"] = is_vuln
            except Exception:
                pass

        validation_path.append(f"version_vuln={evidence['version_vulnerable']}")

        if not evidence["version_vulnerable"]:
            if logger:
                logger(
                    f"WPS V9: v{version} NOT vulnerable. INFO only.", "DEBUG"
                )
            return {
                "title": f"WPS Hide Login Detected (v{evidence['version_detected']})",
                "description": (
                    f"WPS Hide Login plugin is installed and active.\n"
                    f"Version {evidence['version_detected']} is NOT vulnerable "
                    f"to login page disclosure (requires ≤ 1.9.15.2).\n\n"
                    f"**WPS HIDE LOGIN VALIDATION (V9)**:\n"
                    f"- Plugin installed: YES\n"
                    f"- Version vulnerable: NO (v{evidence['version_detected']})\n"
                    f"- Login actually hidden (L₀): YES\n"
                    f"- Real bypass confirmed (P): N/A\n"
                    f"- Validation path: {validation_path}\n"
                ),
                "severity": "info",
                "tool_source": "js_vuln_audit",
            }

        # STEP 3.5 — L₁: Try to discover custom login slug
        # Common custom slugs used with WPS Hide Login
        common_slugs = [
            '/connexion', '/login-custom', '/secret-login',
            '/mon-login', '/admin-secret', '/connexion-admin',
        ]
        for slug in common_slugs:
            try:
                r = http_client.get(
                    f"{base_url}{slug}",
                    options=self.options,
                    timeout=5,
                    allow_redirects=True
                )
                if r.status_code == 200:
                    body_lower = r.text[:3000].lower()
                    if 'loginform' in body_lower or 'user_login' in body_lower:
                        evidence["custom_slug_works"] = slug
                        break
            except Exception:
                continue

        validation_path.append(
            f"custom_slug={evidence['custom_slug_works'] or 'not_found'}"
        )

        # STEP 4 — P: Confirm real bypass via postpass
        for bypass_path in [
            '/wp-admin/?action=postpass',
            '/wp-login.php?action=postpass'
        ]:
            try:
                r = http_client.get(
                    f"{base_url}{bypass_path}",
                    options=self.options,
                    timeout=8,
                    allow_redirects=True
                )
                if r.status_code == 200 and (
                    'wp-login' in r.url.lower()
                    or 'user_login' in r.text.lower()
                    or 'loginform' in r.text.lower()
                ):
                    evidence["bypass_confirmed"] = True
                    break
            except Exception:
                continue

        validation_path.append(f"bypass_confirmed={evidence['bypass_confirmed']}")

        if not evidence["bypass_confirmed"]:
            if logger:
                logger(
                    "WPS V9: Bypass NOT confirmed. "
                    "LOGIN DISCOVERY BEHAVIOR.", "DEBUG"
                )
            return {
                "title": "LOGIN DISCOVERY BEHAVIOR — CORE WORDPRESS",
                "description": (
                    f"WPS Hide Login is installed "
                    f"(v{evidence['version_detected']}) and login is hidden, "
                    f"but the postpass bypass could not be confirmed.\n\n"
                    f"This may be standard WordPress behavior.\n\n"
                    f"**WPS HIDE LOGIN VALIDATION (V9)**:\n"
                    f"- Plugin installed: YES\n"
                    f"- Version vulnerable: YES "
                    f"(v{evidence['version_detected']})\n"
                    f"- Login hidden (L₀): YES\n"
                    f"- Custom slug (L₁): "
                    f"{evidence['custom_slug_works'] or 'Not found'}\n"
                    f"- Bypass confirmed (P): NO\n"
                    f"- Validation path: {validation_path}\n"
                ),
                "severity": "low",
                "tool_source": "js_vuln_audit",
            }

        # ALL predicates satisfied
        return {
            "title": (
                "WPS Hide Login ≤ 1.9.15.2 — "
                "Login Page Disclosure Confirmed"
            ),
            "description": (
                f"The WPS Hide Login plugin "
                f"(v{evidence['version_detected']}) is vulnerable "
                f"to login page disclosure.\n\n"
                f"The hidden login page is accessible via "
                f"`/wp-admin/?action=postpass`.\n\n"
                f"**WPS HIDE LOGIN VALIDATION (V9)**:\n"
                f"- Plugin installed: YES\n"
                f"- Version vulnerable: YES "
                f"(v{evidence['version_detected']})\n"
                f"- Login hidden (L₀): YES\n"
                f"- Custom slug (L₁): "
                f"{evidence['custom_slug_works'] or 'Not found'}\n"
                f"- Bypass confirmed (P): YES\n"
                f"- Validation path: {validation_path}\n"
            ),
            "severity": "medium",
            "tool_source": "js_vuln_audit",
            "repro_command": (
                f"curl -vL '{base_url}/wp-admin/?action=postpass'"
            ),
        }

