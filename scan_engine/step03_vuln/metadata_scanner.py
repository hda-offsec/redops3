from scan_engine.helpers.http_client import get_session
import re
from urllib.parse import urljoin

class MetadataScanner:
    """
    Expert Auditor for Digital Forensics & Metadata Exfiltration.
    Targets PDF, Office (DOCX/XLSX), and Images.
    """
    def __init__(self, options=None):
        self.options = options
        self.session = get_session(self.options)
        self.session.headers.update({"User-Agent": "RedOps3-MetadataExpert/1.0"})
        self.target_extensions = [".pdf", ".docx", ".xlsx", ".pptx", ".jpg", ".png"]

    def scan_found_files(self, urls, logger=None):
        findings = []
        # Filter for relevant files
        files_to_scan = [u for u in urls if any(ext in u.lower() for ext in self.target_extensions)]
        
        if not files_to_scan:
            return []

        if logger: logger(f"Metadata Expert: Analyzing {len(files_to_scan)} documents for internal leaks...", "INFO")

        for file_url in files_to_scan[:10]: # Limit to avoid heavy downloads
            try:
                # We only need the start of the file for many metadata formats
                resp = self.session.get(file_url, stream=True, timeout=10)
                # Read first 128KB
                chunk = resp.raw.read(128 * 1024)
                
                # Simple string-based forensics (grep style)
                # Look for local paths (C:\Users\...) or internal hostnames
                leaks = []
                
                # Check for Windows-style user paths
                user_paths = re.findall(rb'[C-Z]:\\Users\\[a-zA-Z0-9.\-_ \t]+', chunk)
                if user_paths:
                    leaks.append(f"Internal Windows Path: {user_paths[0].decode('utf-8', errors='ignore')}")

                # Check for PDF creators/producers (often leaks internal software versions)
                if b"/Creator" in chunk or b"/Producer" in chunk:
                    prog = re.search(rb'/Creator\s*\((.*?)\)', chunk)
                    if prog:
                        leaks.append(f"PDF Software: {prog.group(1).decode('utf-8', errors='ignore')}")

                if leaks:
                    findings.append({
                        "title": "Digital Forensics: Sensitive Metadata Leak",
                        "description": f"Internal environment data extracted from {file_url}.\n\nLeaks:\n- " + "\n- ".join(leaks),
                        "severity": "medium",
                        "tool_source": "metadata_expert",
                        "url": file_url
                    })
                    if logger: logger(f"MEDIUM: Metadata leak confirmed in {file_url}", "WARN")

            except Exception as e:
                pass
        
        return findings
