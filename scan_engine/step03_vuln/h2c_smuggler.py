import requests
import socket

class H2CSmuggler:
    """
    Expert Auditor for H2C Smuggling (HTTP/2 Cleartext Tunneling).
    Identifies misconfigured proxies that allow upgrading to H2C to bypass
    access controls.
    """
    def __init__(self, target):
        self.target = target

    def scan_h2c_upgrade(self, port, protocol='http', logger=None):
        findings = []
        if protocol != 'http': return [] # H2C is cleartext by definition
        
        url = f"http://{self.target}:{port}"
        if logger: logger(f"H2C Expert: Testing H2C Upgrade Smuggling on {url}...", "INFO")

        try:
            # 1. Probe for H2C support in the connection/upgrade headers
            # We send an HTTP/1.1 request with Upgrade: h2c
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((self.target, port))
            
            # Request attempting to upgrade to h2c
            # Also include a second request in the buffer (smuggling attempt)
            req = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {self.target}\r\n"
                f"Connection: Upgrade, HTTP2-Settings\r\n"
                f"Upgrade: h2c\r\n"
                f"HTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n"
            )
            s.sendall(req.encode())
            
            data = s.recv(1024).decode(errors='ignore')
            s.close()
            
            # If server returns 101 Switching Protocols, it's a very strong indicator
            if "101 Switching Protocols" in data and "h2c" in data.lower():
                findings.append({
                    "title": "H2C Smuggling Potential (101 Switching Protocols)",
                    "description": f"The server accepted an H2C Upgrade request on port {port}. This often indicates a proxy misconfiguration that allows an attacker to tunnel HTTP/2 through an HTTP/1.1 proxy, bypassing security filters.",
                    "severity": "high",
                    "tool_source": "h2c_expert",
                    "url": url,
                    "raw_loot": data[:200]
                })
                if logger: logger(f"HIGH: H2C Smuggling candidate found on {url}", "SUCCESS")

        except Exception as e:
            pass
            
        return findings
