import re

def parse_nmap_open_ports(nmap_output):
    """
    Parses Nmap standard output for open ports.
    Splits by line first to avoid greedy regex across multiple ports.
    """
    open_ports = []
    # Regex matching: 80/tcp open  http  Apache 2.4
    port_pattern = re.compile(r"(\d+)/(tcp|udp)\s+open\s+([^\s]+)\s*(.*)")
    
    for line in nmap_output.splitlines():
        line = line.strip()
        match = port_pattern.search(line)
        if match:
            port = int(match.group(1))
            service = match.group(3)
            version = match.group(4).strip()
            
            open_ports.append({
                "port": port,
                "service": service, # Normalized schema (backend)
                "service_name": service, # Template-compatible key
                "version": version if version else None,
                "priority_score": 0
            })
            
    return open_ports

def parse_nmap_full_output(nmap_output):
    """
    Enriched Nmap Parser that extracts:
    - Scripts results (NSE)
    - OS Detection
    - CPEs
    - CVEs (from NSE scripts)
    - Traceroute/Enriched metadata
    """
    if not nmap_output:
        return {"open_ports_enriched": [], "enriched": {}}

    enriched_data = {
        "os_details": {"os": "Unknown", "accuracy": 0},
        "script_summary": {},
        "vuln_hints": []
    }
    
    # Split by port blocks (roughly) or parse line by line with state tracking
    lines = nmap_output.splitlines()
    ports_metadata = {} # port -> data
    
    current_port = None
    in_script_block = False
    current_script_name = None
    
    # Patterns
    os_pattern = re.compile(r"OS details: ([^,]+)(?:, accuracy (\d+)%)?")
    cpe_pattern = re.compile(r"cpe:/([aboh]):")
    script_header = re.compile(r"^\|_?\s*([a-z0-9_-]+):(.*)")
    script_line = re.compile(r"^\|\s+(.*)")
    
    for line in lines:
        stripped = line.strip()
        
        # 1. OS Detection
        os_match = os_pattern.search(line)
        if os_match:
            enriched_data["os_details"]["os"] = os_match.group(1)
            if os_match.group(2):
                enriched_data["os_details"]["accuracy"] = int(os_match.group(2))

        # 2. Port matching (to track context)
        # 80/tcp open  http  Apache 2.4
        port_match = re.search(r"^(\d+)/(tcp|udp)\s+open", line)
        if port_match:
            current_port = int(port_match.group(1))
            ports_metadata.setdefault(current_port, {
                "script_results": {},
                "os_guess": None,
                "cpe": None,
                "nse_findings": [],
                "extra_info": {}
            })
            # If we were in a script block for another port, reset
            in_script_block = False
            continue

        # 3. CPE Extraction for current port
        if current_port and "cpe:/" in line:
            cpe_m = cpe_pattern.search(line)
            if cpe_m:
                 # Extract full CPE string if possible
                 full_cpe = re.search(r"cpe:[^\s]+", line)
                 if full_cpe:
                     ports_metadata[current_port]["cpe"] = full_cpe.group(0)

        # 4. NSE Script Results
        # Headers: |_ http-title: Welcome to Apache
        s_header_match = script_header.search(line)
        if current_port and s_header_match:
            in_script_block = True
            current_script_name = s_header_match.group(1)
            content = s_header_match.group(2).strip()
            ports_metadata[current_port]["script_results"][current_script_name] = content
            
            # Global summary
            enriched_data["script_summary"][current_script_name] = enriched_data["script_summary"].get(current_script_name, 0) + 1
            
            # CVE Detection in NSE results
            if "CVE-" in line:
                cves = re.findall(r"CVE-\d{4}-\d+", line)
                ports_metadata[current_port]["nse_findings"].extend(cves)
                enriched_data["vuln_hints"].extend(cves)
            continue
            
        # Multi-line script content: |   Server: Apache/2.4.41
        if current_port and in_script_block and line.startswith("|"):
            s_line_match = script_line.search(line)
            if s_line_match:
                content = s_line_match.group(1).strip()
                # Append to current script result
                if current_script_name:
                    old_val = ports_metadata[current_port]["script_results"].get(current_script_name, "")
                    ports_metadata[current_port]["script_results"][current_script_name] = f"{old_val}\n{content}".strip()
                
                if "CVE-" in line:
                    cves = re.findall(r"CVE-\d{4}-\d+", line)
                    ports_metadata[current_port]["nse_findings"].extend(cves)
                    enriched_data["vuln_hints"].extend(cves)
            continue
        elif current_port and not line.startswith("|") and not line.strip():
             in_script_block = False

    # Unique vuln hints
    enriched_data["vuln_hints"] = list(set(enriched_data["vuln_hints"]))
    
    return {
        "ports_metadata": ports_metadata,
        "enriched": enriched_data
    }

# --- CORTEX & INTELLIGENCE CONSUMPTION ---
# The data extracted by parse_nmap_full_output is used as follows:
#
# 1. Decision Cortex (scan_engine/helpers/decision_cortex.py):
#    - 'nse_findings': Triggers high-confidence 'cortex-vuln-nse-triage' suggestions for identified CVEs.
#    - 'script_results': Used to detect administrative interfaces (http-title) and prioritize auth audits.
#
# 2. Service Intelligence (scan_engine/helpers/service_intelligence.py):
#    - 'cpe': Adds high-confidence technology tags (cpe:a/p/o) and notes.
#    - 'os_guess': Adds OS-specific tags (os:linux/os:windows) with improved profiling.
#    - 'nse_findings': Increases overall service confidence and tags potential vulnerabilities.
