import logging
import sys
import os

# Adjust path to import scan_engine
sys.path.append(os.getcwd())

from scan_engine.step01_recon.nmap_scanner import NmapScanner

# Setup basic logging
logging.basicConfig(level=logging.INFO)

def test_smart_logic():
    target = "127.0.0.1" # Localhost should be fast -> -T5
    scanner = NmapScanner(target)
    
    print(f"[*] Testing Smart Scan Logic against {target}...")
    
    # 1. Test Timing Detection
    timing = scanner.detect_best_timing()
    print(f"[+] Detected Timing: {timing}")
    
    # Expect -T5 for localhost
    if timing == "-T5":
        print("[SUCCESS] Localhost timing correctly identified as -T5")
    else:
        print(f"[WARN] Expected -T5 for localhost, got {timing}. (Maybe ping failed or high load?)")

    # 2. Test Command Generation
    cmd = scanner.command_for_profile("smart")
    print(f"[+] Generated Command: {' '.join(cmd)}")
    
    expected_flags = ["-sS", "-sV", "--top-ports", "2000", "-n"]
    if all(flag in cmd for flag in expected_flags):
         print("[SUCCESS] Command contains all expected Smart Scan flags.")
    else:
         print("[FAIL] Command missing expected flags.")
         
    # 3. Test Unknown Profile Fallback (Logic is in Orchestrator, but we can check profile dict)
    if "smart" in scanner.PROFILES:
        print("[SUCCESS] 'smart' profile exists in NmapScanner.")
    else:
        print("[FAIL] 'smart' profile missing from NmapScanner.")

    # 4. Test Dynamic Script Recommendations
    print("\n[*] Testing Script Recommendations...")
    services = {
        "apache httpd": ["http-title", "http-enum"],
        "microsoft-ds": ["smb-os-discovery", "smb-vuln-ms17-010"],
        "openssh": ["ssh2-enum-algos"],
        "mysql": ["mysql-empty-password"],
        "unknown-service": ["default", "discovery", "safe"]
    }
    
    for svc, expected in services.items():
        scripts = scanner.get_recommended_scripts(svc)
        print(f"Service: '{svc}' -> Scripts: {len(scripts)}")
        
        if not expected:
            if not scripts: print(f"[SUCCESS] Correctly returned no scripts for {svc}")
            else: print(f"[FAIL] Returned scripts for unknown service: {scripts}")
            continue

        if all(e in scripts for e in expected):
            print(f"[SUCCESS] {svc} scripts include expected: {expected}")
        else:
            print(f"[FAIL] {svc} missing expected scripts. Got: {scripts}")

if __name__ == "__main__":
    test_smart_logic()
