import os
import shutil
from datetime import datetime

from scan_engine.helpers.output_parsers import (
    parse_nmap_open_ports,
    parse_whatweb_line,
    parse_nuclei_line,
    parse_ffuf_line,
)
from scan_engine.helpers.target_utils import normalize_target_url
from scan_engine.step01_recon.nmap_scanner import NmapScanner
from scan_engine.step02_enum.whatweb_scanner import WhatWebScanner
from scan_engine.step03_vuln.nuclei_scanner import NucleiScanner
from scan_engine.step05_dirbusting.ffuf_scanner import FfufScanner


WEB_PORTS = {80, 443, 8000, 8080, 8443}


class ScanOrchestrator:
    def __init__(self, scan_id, target, log_fn, finding_fn, suggestion_fn, results_fn):
        self.scan_id = scan_id
        self.target = target
        self.log = log_fn
        self.add_finding = finding_fn
        self.add_suggestion = suggestion_fn
        self.save_results = results_fn

    def run_pipeline(self, profile="quick"):
        self.log("Pipeline initialized: recon -> enum -> vuln -> dirbusting", "INFO")
        self.log(f"Nmap profile selected: {profile}", "INFO")

        results = {
            "scan_id": self.scan_id,
            "target": self.target,
            "started_at": datetime.utcnow().isoformat() + "Z",
            "phases": {},
        }

        if not self._ensure_tool("nmap"):
            self.log("ERROR: 'nmap' binary not found. Please install it.", "ERROR")
            results["completed_at"] = datetime.utcnow().isoformat() + "Z"
            self.save_results(self.scan_id, results)
            return False

        nmap = NmapScanner(self.target)
        stream = nmap.stream_profile(profile)
        nmap_output = self._consume_stream("Recon (Nmap)", stream)
        if nmap_output is None:
            results["completed_at"] = datetime.utcnow().isoformat() + "Z"
            self.save_results(self.scan_id, results)
            return False

        ports = parse_nmap_open_ports("\n".join(nmap_output))
        self.log(
            f"Open ports detected: {', '.join(str(p['port']) for p in ports) or 'none'}",
            "INFO",
        )
        results["phases"]["recon"] = {
            "tool": "nmap",
            "profile": profile,
            "open_ports": ports,
            "raw": nmap_output[:200],
        }
        self.save_results(self.scan_id, results)

        for port_info in ports:
            self.add_finding(
                tool="nmap",
                severity="info",
                title=f"Port {port_info['port']}/tcp open",
                description=f"Service: {port_info['service']}",
            )

        self._suggest_from_ports(ports)

        web_ports = [p["port"] for p in ports if p["port"] in WEB_PORTS]
        if not web_ports:
            self.log("No web ports detected; skipping web enum/vuln/dirbusting.", "WARN")
            results["completed_at"] = datetime.utcnow().isoformat() + "Z"
            self.save_results(self.scan_id, results)
            return True

        for port in web_ports:
            target_url = normalize_target_url(self.target, port=port)
            self.log(f"Web target selected: {target_url}", "INFO")

            if self._ensure_tool("whatweb"):
                whatweb = WhatWebScanner(target_url)
                whatweb_output = self._consume_stream("Enum (WhatWeb)", whatweb.stream_scan())
                if whatweb_output is None:
                    results["completed_at"] = datetime.utcnow().isoformat() + "Z"
                    self.save_results(self.scan_id, results)
                    return False
                whatweb_summary = {}
                for line in whatweb_output:
                    parsed = parse_whatweb_line(line)
                    if parsed:
                        whatweb_summary.update(parsed)
                results["phases"].setdefault("enum", {})
                results["phases"]["enum"]["whatweb"] = {
                    "target": target_url,
                    "summary": whatweb_summary,
                    "raw": whatweb_output[:200],
                }
                self.save_results(self.scan_id, results)
            else:
                self.log("Skipping WhatWeb: binary not found.", "WARN")

            if self._ensure_tool("nuclei"):
                nuclei = NucleiScanner(target_url)
                nuclei_output = self._consume_stream("Vuln (Nuclei)", nuclei.stream_scan())
                if nuclei_output is None:
                    results["completed_at"] = datetime.utcnow().isoformat() + "Z"
                    self.save_results(self.scan_id, results)
                    return False
                vuln_findings = []
                for line in nuclei_output:
                    parsed = parse_nuclei_line(line)
                    if not parsed:
                        continue
                    vuln_findings.append(parsed)
                    self.add_finding(
                        tool="nuclei",
                        severity=parsed["severity"],
                        title=parsed["title"],
                        description=None,
                    )
                results["phases"].setdefault("vuln", {})
                results["phases"]["vuln"]["nuclei"] = {
                    "target": target_url,
                    "findings": vuln_findings,
                    "raw": nuclei_output[:200],
                }
                self.save_results(self.scan_id, results)
            else:
                self.log("Skipping Nuclei: binary not found.", "WARN")

            if self._ensure_tool("ffuf"):
                wordlist = self._resolve_wordlist()
                if not wordlist:
                    self.log("Skipping ffuf: no wordlist configured.", "WARN")
                else:
                    ffuf = FfufScanner(target_url, wordlist)
                    ffuf_output = self._consume_stream("Dirbusting (ffuf)", ffuf.stream_scan())
                    if ffuf_output is None:
                        results["completed_at"] = datetime.utcnow().isoformat() + "Z"
                        self.save_results(self.scan_id, results)
                        return False
                    endpoints = []
                    for line in ffuf_output:
                        parsed = parse_ffuf_line(line)
                        if not parsed:
                            continue
                        endpoints.append(parsed)
                        self.add_finding(
                            tool="ffuf",
                            severity="info",
                            title=f"Endpoint discovered: {parsed['path']}",
                            description=f"Status {parsed['status']} Size {parsed['size']}",
                        )
                    results["phases"].setdefault("dirbusting", {})
                    results["phases"]["dirbusting"]["ffuf"] = {
                        "target": target_url,
                        "endpoints": endpoints,
                        "raw": ffuf_output[:200],
                    }
                    self.save_results(self.scan_id, results)
            else:
                self.log("Skipping ffuf: binary not found.", "WARN")

        results["completed_at"] = datetime.utcnow().isoformat() + "Z"
        self.save_results(self.scan_id, results)
        self.log("Pipeline completed.", "SUCCESS")
        return True

    def _consume_stream(self, label, stream):
        self.log(f"Starting {label}", "INFO")
        output_lines = []
        exit_code = None

        for event in stream:
            if event["type"] == "stdout":
                line = event["line"].strip()
                if line:
                    output_lines.append(line)
                    self.log(line, "INFO")
            elif event["type"] == "exit":
                exit_code = event["code"]

        if exit_code is None:
            self.log(f"{label} did not return an exit code.", "ERROR")
            return None
        if exit_code != 0:
            self.log(f"{label} failed (exit {exit_code}).", "ERROR")
            return None

        self.log(f"{label} completed.", "SUCCESS")
        return output_lines

    def _ensure_tool(self, binary_name):
        return shutil.which(binary_name) is not None

    def _resolve_wordlist(self):
        env_wordlist = os.getenv("WORDLIST_PATH")
        if env_wordlist and os.path.exists(env_wordlist):
            return env_wordlist

        default_wordlist = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "data", "wordlists", "common.txt"
        )
        if os.path.exists(default_wordlist):
            return default_wordlist
        return None

    def _suggest_from_ports(self, ports):
        port_set = {p["port"] for p in ports}
        if 22 in port_set:
            self.add_suggestion(
                tool="ssh",
                command="ssh -v <user>@<target>",
                reason="SSH port open; validate authentication methods and banner.",
            )
        if 445 in port_set or 139 in port_set:
            self.add_suggestion(
                tool="smb",
                command="smbclient -L //<target> -N",
                reason="SMB port open; enumerate shares and signing.",
            )
        if 3389 in port_set:
            self.add_suggestion(
                tool="rdp",
                command="xfreerdp /v:<target>",
                reason="RDP detected; check exposure and NLA.",
            )
