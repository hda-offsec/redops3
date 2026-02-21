
import re
import os

target_file = 'scan_engine/orchestrator.py'

def reorganize_pipeline():
    with open(target_file, 'r') as f:
        lines = f.readlines()

    def get_indent(line):
        return len(line) - len(line.lstrip())

    def adjust_indent(block, target_base):
        if not block: return []
        # Find current base (indent of first non-empty line)
        current_base = -1
        for line in block:
            if line.strip():
                current_base = get_indent(line)
                break
        if current_base == -1:
            return block
            
        diff = target_base - current_base
        new_block = []
        for line in block:
            stripped = line.lstrip()
            if not stripped:
                new_block.append("\n")
            else:
                line_indent = get_indent(line)
                # Calculate new indent based on shift
                new_indent = max(0, line_indent + diff)
                new_block.append(" " * new_indent + stripped)
        return new_block

    # Define the blocks based on anchors in original file
    # Note: Phase 0 and others are inside a try/if block in original
    blocks_meta = [
        ("INITIAL_RESULTS", "results = {", ["# --- PHASE 1: Port Scan ---"]),
        ("PHASE_1_2", "# --- PHASE 1: Port Scan ---", ["# --- PHASE 4: Auto-Enumeration (Web) ---"]),
        ("PHASE_4_WHATWEB", "# --- PHASE 4: Auto-Enumeration (Web) ---", ["# --- CMS SPECIFIC SCANS (WordPress) ---"]),
        ("PHASE_4_WPSCAN", "# --- CMS SPECIFIC SCANS (WordPress) ---", ["# --- KATANA CRAWLING ---"]),
        ("PHASE_4_KATANA", "# --- KATANA CRAWLING ---", ["# --- WAF DETECTION ---"]),
        ("PHASE_4_WAF", "# --- WAF DETECTION ---", ["# --- SECURITY HEADERS ANALYSIS ---"]),
        ("PHASE_4_HEADERS", "# --- SECURITY HEADERS ANALYSIS ---", ["# --- CLOUD METADATA AUDIT ---"]),
        ("PHASE_4_CLOUD_META", "# --- CLOUD METADATA AUDIT ---", ["# --- PARAMETER DISCOVERY (ARJUN) ---"]),
        ("PHASE_4_ARJUN", "# --- PARAMETER DISCOVERY (ARJUN) ---", ["# --- JS ADVANCED ANALYSIS (Deep Scan) ---"]),
        ("PHASE_4_JS", "# --- JS ADVANCED ANALYSIS (Deep Scan) ---", ["# --- OPEN REDIRECT AUDIT ---"]),
        ("PHASE_4_REDIRECT", "# --- OPEN REDIRECT AUDIT ---", ["# --- FAVICON HASHING ---"]),
        ("PHASE_4_FAVICON", "# --- FAVICON HASHING ---", ["# --- API DISCOVERY ---"]),
        ("PHASE_4_API", "# --- API DISCOVERY ---", ["# --- PHASE 0: Pre-Flight Intelligence (Geo) ---", "# --- EXPERT: SSRF Probing ---"]),
        ("PHASE_0", "# --- PHASE 0: Pre-Flight Intelligence (Geo) ---", ["# --- PHASE 0.1: Cloud Assets Audit ---"]),
        ("PHASE_0_1", "# --- PHASE 0.1: Cloud Assets Audit ---", ["# --- PHASE 0.2: GitHub Leaks & Email Discovery ---"]),
        ("PHASE_0_2", "# --- PHASE 0.2: GitHub Leaks & Email Discovery ---", ["# --- PHASE 0.3: Origin IP Discovery (The Unmasking) ---"]),
        ("PHASE_0_3", "# --- PHASE 0.3: Origin IP Discovery (The Unmasking) ---", ["# --- PHASE 0.4: Google Dorking ---"]),
        ("PHASE_0_4", "# --- PHASE 0.4: Google Dorking ---", ["# --- INITIALIZATION: Done ---", "# --- PHASE 0.5: DNS Enumeration ---"]),
        ("PHASE_0_5", "# --- PHASE 0.5: DNS Enumeration ---", ["# --- PHASE 0.7: Subdomain Fingerprinting ---"]),
        ("PHASE_0_7", "# --- PHASE 0.7: Subdomain Fingerprinting ---", ["# --- PHASE 3: Deep Analysis & Attack Vector Mapping ---"]),
        ("PHASE_3", "# --- PHASE 3: Deep Analysis & Attack Vector Mapping ---", ["# --- PHASE 3.5: Database Audit ---"]),
        ("PHASE_3_5", "# --- PHASE 3.5: Database Audit ---", ["# --- PHASE 3.7: Authentication Brute Force ---"]),
        ("PHASE_3_7", "# --- PHASE 3.7: Authentication Brute Force ---", ["# --- PHASE 3.9: Archive Intelligence (Wayback) ---"]),
        ("PHASE_3_9", "# --- PHASE 3.9: Archive Intelligence (Wayback) ---", ["# --- PHASE 5: Automated Vulnerability Scanning (Nuclei) ---"]),
        ("PHASE_5", "# --- PHASE 5: Automated Vulnerability Scanning (Nuclei) ---", ["# --- PHASE 6: Automated Dirbusting (ffuf) ---"]),
        ("PHASE_6", "# --- PHASE 6: Automated Dirbusting (ffuf) ---", ["# --- PHASE 6.1: ADVANCED ENUMERATION & DATA MINING ---"]),
        ("PHASE_6_1", "# --- PHASE 6.1: ADVANCED ENUMERATION & DATA MINING ---", ["# --- PHASE 7: VULNERABILITY ASSAULT (XSS + Injection) ---"]),
        ("PHASE_7", "# --- PHASE 7: VULNERABILITY ASSAULT (XSS + Injection) ---", ["# --- PHASE 8: Business Logic Warfare ---"]),
        ("PHASE_8", "# --- PHASE 8: Business Logic Warfare ---", ["def run_pipeline", "return results"]), # End of method
    ]

    extracted = {}
    for name, start, end in blocks_meta:
        s_idx = -1
        for i, line in enumerate(lines):
            if start in line:
                s_idx = i
                break
        if s_idx == -1: 
            print(f"FAILED TO FIND BLOCK START: {name}")
            continue
        
        e_idx = len(lines)
        for i in range(s_idx + 1, len(lines)):
            if any(p in lines[i] for p in end):
                # If we encounter another method, stop
                if any(p.strip() == "def" for p in end) and lines[i].startswith("    def "):
                    e_idx = i
                    break
                # Special case for return results
                if any(p.strip() == "return results" for p in end) and "return results" in lines[i]:
                    e_idx = i + 1
                    break
                e_idx = i
                break
        
        block = lines[s_idx:e_idx]
        # Only adjust indent if it's currently > 8 (i.e. if it was inside a try/if)
        current_base = -1
        for line in block:
            if line.strip():
                current_base = get_indent(line)
                break
        
        if current_base > 8:
            extracted[name] = adjust_indent(block, 8)
            print(f"Extracted {name} and dedented from {current_base} to 8")
        else:
            extracted[name] = block
            print(f"Extracted {name} at base {current_base}")

    header_idx = -1
    for i, line in enumerate(lines):
        if "def run_pipeline(self, profile='quick'):" in line:
            header_idx = i
            break
            
    if header_idx == -1: return

    # Identify existing run_pipeline body range to replace
    # We replace from line 90 (approx) until the beginning of the next method or end of return
    # But let's be simpler: we'll replace the whole method body
    # Find next method start
    next_method_idx = len(lines)
    for i in range(header_idx + 1, len(lines)):
        if lines[i].startswith("    def "):
            next_method_idx = i
            break
            
    new_body = [
        "        success = True\n",
        "\n"
    ]
    new_body.extend(extracted.get("INITIAL_RESULTS", []))
    new_body.append("        web_ports = []\n")
    new_body.append("        open_ports = []\n\n")
    
    # Assembly - Discovery First
    new_body.extend(extracted.get("PHASE_1_2", []))
    
    # Discovery phases (OSINT/DNS)
    new_body.extend(extracted.get("PHASE_0", []))
    new_body.extend(extracted.get("PHASE_0_1", []))
    new_body.extend(extracted.get("PHASE_0_2", []))
    new_body.extend(extracted.get("PHASE_0_3", []))
    new_body.extend(extracted.get("PHASE_0_4", []))
    new_body.extend(extracted.get("PHASE_0_5", []))
    new_body.extend(extracted.get("PHASE_0_7", []))
    new_body.extend(extracted.get("PHASE_3_9", [])) # Archive Intel
    
    # Web Recon
    new_body.extend(extracted.get("PHASE_4_WHATWEB", []))
    new_body.extend(extracted.get("PHASE_4_WAF", []))
    new_body.extend(extracted.get("PHASE_4_HEADERS", []))
    new_body.extend(extracted.get("PHASE_6_1", [])) # Advanced Tech detection
    
    # Deep Enumeration
    new_body.extend(extracted.get("PHASE_4_KATANA", []))
    new_body.extend(extracted.get("PHASE_4_CLOUD_META", []))
    new_body.extend(extracted.get("PHASE_4_ARJUN", []))
    new_body.extend(extracted.get("PHASE_4_JS", []))
    new_body.extend(extracted.get("PHASE_4_REDIRECT", []))
    new_body.extend(extracted.get("PHASE_4_FAVICON", []))
    new_body.extend(extracted.get("PHASE_4_API", []))
    
    # Audits (WPScan optimized)
    wpscan_block = extracted.get("PHASE_4_WPSCAN", [])
    optimized_wpscan = []
    for line in wpscan_block:
        if "wpscan.run_scan_json" in line and "enumerate_all" not in line:
            indent = line[:line.find("wpscan.run_scan_json")]
            optimized_wpscan.append(f"{indent}# Optimization for quick profiles\n")
            optimized_wpscan.append(f"{indent}enumerate_all = False if profile.startswith('quick') else True\n")
            optimized_wpscan.append(f"{indent}wp_json = wpscan.run_scan_json(port, proto, logger=self.log, enumerate_all=enumerate_all)\n")
        else:
            optimized_wpscan.append(line)
    new_body.extend(optimized_wpscan)
    
    new_body.extend(extracted.get("PHASE_5", []))
    new_body.extend(extracted.get("PHASE_6", []))
    
    # Analysis & Intelligence
    new_body.extend(extracted.get("PHASE_3", []))
    new_body.extend(extracted.get("PHASE_3_5", []))
    new_body.extend(extracted.get("PHASE_3_7", []))
    
    # Assault
    new_body.extend(extracted.get("PHASE_7", []))
    new_body.extend(extracted.get("PHASE_8", []))
    
    if "return results" not in "".join(new_body):
        new_body.append("\n        return results\n")

    final_lines = lines[:header_idx + 1] + new_body + lines[next_method_idx:]

    with open(target_file, 'w') as f:
        f.writelines(final_lines)
    print(f"Successfully reorganized {target_file}")

if __name__ == "__main__":
    reorganize_pipeline()
