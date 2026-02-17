
import os

FILE_PATH = "scan_engine/orchestrator.py"

def reorder_orchestrator():
    with open(FILE_PATH, 'r') as f:
        lines = f.readlines()

    # Identify markers (1-indexed in grep, 0-indexed in list)
    # We use explicit string matching for robustness
    
    markers = {}
    
    for i, line in enumerate(lines):
        if "# --- PHASE 0:" in line: markers['p0'] = i
        if "# --- PHASE 0.5:" in line: markers['p0_5'] = i # Needs verification if it exists or is inside P0 block
        if "# --- PHASE 0.7:" in line: markers['p0_7'] = i
        if "# --- PHASE 0.8:" in line: markers['p0_8'] = i
        if "# --- PHASE 1:" in line: markers['p1'] = i
        if "# --- PHASE 2:" in line: markers['p2'] = i
        if "# --- PHASE 3:" in line: markers['p3'] = i
        if "# --- PHASE 3.5:" in line: markers['p3_5'] = i
        if "# --- PHASE 3.7:" in line: markers['p3_7'] = i
        if "# --- PHASE 3.9:" in line: markers['p3_9'] = i
        if "# --- PHASE 4:" in line: markers['p4'] = i
        if "# --- PHASE 5:" in line: markers['p5'] = i
        if "# --- PHASE 6:" in line: markers['p6'] = i
        if "# --- PHASE 7:" in line: markers['p7'] = i
        if "# --- PHASE 8:" in line: markers['p8'] = i
    
    # Define Blocks
    # Header: 0 to P0
    block_header = lines[:markers['p0']]
    
    # P0 Block (OSINT): P0 to P1 (Excluding P0.8 which we want to move to end)
    # Wait, P0.8 is at 356. P1 is at 408.
    # So P0..P0.7 is markers['p0'] to markers['p0_8']
    block_osint = lines[markers['p0']:markers['p0_8']]
    
    # P0.8 Block (Takeover): P0.8 to P1
    block_takeover = lines[markers['p0_8']:markers['p1']]
    
    # P1+2 Block (Nmap+Parse): P1 to P3
    block_nmap = lines[markers['p1']:markers['p3']]
    
    # P3 Block (Deep Analysis): P3 to P4
    # This includes P3, P3.5, P3.7, P3.9
    block_deep = lines[markers['p3']:markers['p4']]
    
    # P4 Block (Web Enum): P4 to P5
    block_web = lines[markers['p4']:markers['p5']]
    
    # P5 Block (Nuclei): P5 to P6
    block_nuclei = lines[markers['p5']:markers['p6']]
    
    # Rest (P6 to End)
    block_rest = lines[markers['p6']:]
    
    # --- TRANSFORMATIONS ---
    
    # 1. Modify P3 Block to remove/comment out 'web_ports = []' and population logic
    # We iterate and comment out specific lines
    new_block_deep = []
    found_web_ports_init = False
    
    for line in block_deep:
        if "web_ports = []" in line and not found_web_ports_init:
            new_block_deep.append(line.replace("web_ports = []", "# web_ports = [] # Already populated in Phase 2.5"))
            found_web_ports_init = True
        elif "web_ports.append" in line:
             new_block_deep.append(line.replace("web_ports.append", "# web_ports.append"))
        elif "if port not in web_ports:" in line:
             new_block_deep.append(line.replace("if port not in web_ports:", "# if port not in web_ports:"))
        else:
             new_block_deep.append(line)
             
    # 2. Create Phase 2.5 Block (Web Port ID)
    # indentation should match expected (8 spaces usually inside run method)
    indent = " " * 12 # Based on previous view, it seems to be inside a method
    # Let's check indentation of 'self.log' in P1
    # P1 line 408: '        # --- PHASE 1: Port Scan ---' (8 spaces)
    # '            self.log' (12 spaces)
    
    block_web_id = [
        "\n",
        "        # --- PHASE 2.5: Host & Service Identification ---\n",
        "        web_ports = []\n",
        "        if open_ports:\n",
        "            for p in open_ports:\n",
        "                # Service-based identification\n",
        "                if 'http' in p.get('service_name', '').lower() or p['port'] in [80, 443, 8080, 8443, 8000, 8008, 3000, 5000]:\n",
        "                    if p['port'] not in web_ports:\n",
        "                        web_ports.append(p['port'])\n",
        "        self.log(f\"Identified {len(web_ports)} web ports for enumeration.\", \"INFO\")\n",
        "\n"
    ]
    
    # --- ASSEMBLY ---
    # Order: 
    # 1. Header
    # 2. Nmap (P1+2)
    # 3. Web ID (P2.5)
    # 4. Web Enum (P4) - WPScan is here
    # 5. OSINT (P0..P0.7)
    # 6. Deep Analysis (P3..P3.9) - Archive is here (3.9)
    # 7. Nuclei (P5)
    # 8. Takeover (P0.8) - User wanted Nuclei at end. Takeover is Nuclei-based.
    # 9. Rest (P6..)
    
    new_content = []
    new_content.extend(block_header)
    new_content.extend(block_nmap)
    new_content.extend(block_web_id)
    new_content.extend(block_web)
    new_content.extend(block_osint)
    new_content.extend(new_block_deep)
    new_content.extend(block_nuclei)
    new_content.extend(block_takeover)
    new_content.extend(block_rest)
    
    # Write back
    with open(FILE_PATH, 'w') as f:
        f.writelines(new_content)
    
    print("Reordering complete.")

if __name__ == "__main__":
    reorder_orchestrator()
