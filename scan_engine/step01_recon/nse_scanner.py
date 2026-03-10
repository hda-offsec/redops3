"""
NSE Smart Scanner — Service-aware Nmap Script Engine runner.

Selects and runs safe, non-destructive NSE scripts based on discovered
open ports and service fingerprints.  No brute-force, no exploit, no DoS.
"""

import logging
import re
from scan_engine.helpers.process_manager import ProcessManager

logger = logging.getLogger(__name__)

# ── Blocklist: never run these categories / scripts ──────────────────
BLOCKED_PATTERNS = {
    "brute", "exploit", "dos", "fuzzer", "vuln",
    "pgsql-brute", "smtp-open-relay", "smb-vuln-ms17-010",
    "rdp-vuln-ms12-020", "http-slowloris",
}


def _is_blocked(script_name: str) -> bool:
    """Return True if a script name matches any blocked pattern."""
    lower = script_name.lower()
    for pat in BLOCKED_PATTERNS:
        if pat in lower:
            return True
    return False


# ── Safe script mapping per service keyword ──────────────────────────
SERVICE_SCRIPTS = {
    "http": [
        "http-title", "http-headers", "http-methods", "http-enum",
        "http-robots.txt", "http-generator", "http-security-headers",
        "http-server-header",
    ],
    "ssl": [
        "ssl-cert", "ssl-enum-ciphers", "ssl-date",
    ],
    "ssh": [
        "ssh2-enum-algos", "ssh-hostkey", "ssh-auth-methods",
    ],
    "ftp": [
        "ftp-anon", "ftp-syst",
    ],
    "smb": [
        "smb-os-discovery", "smb-enum-shares", "smb-enum-users",
        "smb2-security-mode",
    ],
    "netbios": [
        "smb-os-discovery", "smb2-security-mode",
    ],
    "dns": [
        "dns-recursion", "dns-service-discovery",
    ],
    "domain": [
        "dns-recursion", "dns-service-discovery",
    ],
    "mysql": [
        "mysql-info", "mysql-empty-password",
    ],
    "postgresql": [
        "banner",
    ],
    "mssql": [
        "ms-sql-info", "ms-sql-ntlm-info",
    ],
    "smtp": [
        "smtp-commands", "smtp-enum-users",
    ],
    "imap": [
        "imap-capabilities",
    ],
    "pop3": [
        "pop3-capabilities",
    ],
    "rdp": [
        "rdp-ntlm-info", "rdp-enum-encryption",
    ],
    "ms-wbt-server": [
        "rdp-ntlm-info", "rdp-enum-encryption",
    ],
    "vnc": [
        "vnc-info",
    ],
}

# Fallback for any service not matched above
FALLBACK_SCRIPTS = ["banner", "ssl-cert", "ssl-enum-ciphers"]


class NSEScanner:
    """Run targeted NSE scripts per port based on service detection."""

    def __init__(self, target, options=None):
        self.target = target
        self.options = options or {}

    @staticmethod
    def scripts_for_service(service_name: str) -> list:
        """
        Return a de-duplicated list of safe NSE scripts for a given
        service string (e.g. "http", "ssl/http", "ssh").
        """
        service_lower = (service_name or "").lower()
        scripts = set()

        matched = False
        for keyword, script_list in SERVICE_SCRIPTS.items():
            if keyword in service_lower:
                scripts.update(script_list)
                matched = True

        if not matched:
            scripts.update(FALLBACK_SCRIPTS)

        # Final safety filter
        return sorted(s for s in scripts if not _is_blocked(s))

    def run_on_ports(self, open_ports, logger_func=None):
        """
        Run NSE scripts on all discovered ports.

        Args:
            open_ports: list of dicts with 'port', 'service'/'service_name' keys
            logger_func: optional callable(msg, level)

        Returns:
            dict: {port_number: {script_name: output_text, ...}, ...}
        """
        log = logger_func or (lambda msg, lvl="INFO": logger.info(msg))

        if not open_ports:
            log("NSE Scanner: No ports to scan.", "DEBUG")
            return {}

        # De-duplicate ports and collect services
        port_map = {}  # port -> service string
        for p_info in open_ports:
            port = p_info.get("port")
            if port is None:
                continue
            svc = p_info.get("service") or p_info.get("service_name") or ""
            # Keep richest service string
            if port not in port_map or len(svc) > len(port_map[port]):
                port_map[port] = svc

        if not port_map:
            return {}

        # Group ports by script set for efficiency (run one nmap per script group)
        script_groups = {}  # frozenset(scripts) -> [ports]
        for port, svc in sorted(port_map.items()):
            scripts = self.scripts_for_service(svc)
            if not scripts:
                continue
            key = frozenset(scripts)
            script_groups.setdefault(key, []).append((port, svc))

        results = {}
        total_scripts = sum(len(k) for k in script_groups)
        log(f"NSE Scanner: {len(port_map)} ports, {total_scripts} script mappings across {len(script_groups)} groups.", "INFO")

        for scripts_set, port_infos in script_groups.items():
            ports_csv = ",".join(str(p) for p, _ in port_infos)
            scripts_csv = ",".join(sorted(scripts_set))

            cmd = [
                "nmap", "-n", "-v", "-sV",
                "--script", scripts_csv,
                "-p", ports_csv,
                "-T4",
                "--stats-every", "15s",
                "--host-timeout", "120s",
                "--script-timeout", "30s",
                self.target,
            ]

            svc_labels = ", ".join(f"{p}({s or '?'})" for p, s in port_infos)
            log(f"NSE: Running {len(scripts_set)} scripts on ports [{svc_labels}]", "INFO")

            try:
                success, stdout, stderr, returncode = ProcessManager.run_command(
                    cmd, timeout=180
                )
            except Exception as e:
                log(f"NSE Scanner error: {e}", "ERROR")
                continue

            if not stdout:
                log(f"NSE: No output for ports {ports_csv}", "DEBUG")
                continue

            # Parse the output
            port_results = self._parse_nse_output(stdout)
            for port_num, script_data in port_results.items():
                if script_data:  # Only store non-empty
                    results[port_num] = script_data
                    log(f"NSE: Port {port_num} → {len(script_data)} script results", "SUCCESS")

        log(f"NSE Scanner complete: {sum(len(v) for v in results.values())} total script results across {len(results)} ports.", "SUCCESS")
        return results

    @staticmethod
    def _parse_nse_output(raw_output: str) -> dict:
        """
        Parse nmap NSE output into {port: {script_name: content}}.
        """
        results = {}
        current_port = None
        current_script = None

        port_pattern = re.compile(r"^(\d+)/(tcp|udp)\s+open")
        script_header = re.compile(r"^\|_?\s*([a-z0-9_-]+):\s*(.*)")
        script_cont = re.compile(r"^\|\s+(.*)")

        for line in raw_output.splitlines():
            stripped = line.strip()

            # Port line
            pm = port_pattern.match(stripped)
            if pm:
                current_port = int(pm.group(1))
                results.setdefault(current_port, {})
                current_script = None
                continue

            if current_port is None:
                continue

            # Script header
            sh = script_header.match(stripped)
            if sh:
                current_script = sh.group(1)
                content = sh.group(2).strip()
                results[current_port][current_script] = content
                continue

            # Script continuation
            if current_script and stripped.startswith("|"):
                sc = script_cont.match(stripped)
                if sc:
                    prev = results[current_port].get(current_script, "")
                    results[current_port][current_script] = (
                        f"{prev}\n{sc.group(1).strip()}" if prev else sc.group(1).strip()
                    )
                continue

            # Non-script line resets script context
            if not stripped.startswith("|"):
                current_script = None

        return results
