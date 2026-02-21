import socket
import ssl
import time
from urllib.parse import urlparse

class SmugglingScanner:
    """
    V6 EXPERT: HTTP Request Smuggling (CL.TE / TE.CL) Detector.
    Uses timing-based differential analysis to detect de-synchronization vulnerabilities.
    """
    def __init__(self, target, options=None):
        self.options = options
        self.target = target

    def _send_socket_request(self, host, port, protocol, raw_payload):
        """Sends a raw HTTP payload via socket to allow malformed headers."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            if protocol == 'https':
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)
            
            sock.connect((host, port))
            sock.sendall(raw_payload.encode('utf-8'))
            
            start_time = time.time()
            data = sock.recv(1024)
            duration = time.time() - start_time
            
            sock.close()
            return duration, data.decode('utf-8', errors='ignore')
        except Exception:
            return None, None

    def check_cl_te(self, host, port, protocol):
        """Probes for CL.TE smuggling via timeout."""
        # The front-end uses Content-Length (short), backend uses Transfer-Encoding (chunked)
        # We send a body that is longer than CL, the backend waits for the next chunk which never comes.
        payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Content-Length: 4\r\n"
            f"\r\n"
            f"1\r\n"
            f"Z\r\n"
            f"0\r\n"
            f"\r\n"
        )
        duration, _ = self._send_socket_request(host, port, protocol, payload)
        return duration

    def check_te_cl(self, host, port, protocol):
        """Probes for TE.CL smuggling via timeout."""
        # The front-end uses TE, backend uses CL. 
        # We send a chunked body but the front-end stops at the first chunk, 
        # while the backend waits for more data based on CL.
        payload = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"
        )
        duration, _ = self._send_socket_request(host, port, protocol, payload)
        return duration

    def scan(self, port, protocol='http', logger=None):
        findings = []
        host = self.target
        if logger: logger(f"Smuggling Expert: Probing {host}:{port} for Desync vulnerabilities...", "INFO")

        # Baseline request
        baseline_payload = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"
        baseline_dur, _ = self._send_socket_request(host, port, protocol, baseline_payload)
        
        if baseline_dur is None: return [] # Connection failed

        # Test CL.TE
        cl_te_dur = self.check_cl_te(host, port, protocol)
        if cl_te_dur and cl_te_dur > baseline_dur + 3: # 3s delay is a strong signal
             findings.append({
                "title": "🔥 CRITICAL: HTTP Request Smuggling (CL.TE) Suspected",
                "description": (
                    f"The server at `{host}:{port}` showed a significant delay ({cl_te_dur:.2f}s vs {baseline_dur:.2f}s) "
                    "when probed with a CL.TE desynchronization payload. "
                    "This suggests the front-end proxy uses `Content-Length` while the back-end uses `Transfer-Encoding`."
                ),
                "severity": "critical",
                "tool_source": "smuggling_expert",
                "type": "Desync"
            })
             if logger: logger(f"💀 SMUGGLING DETECTED: CL.TE Desync on {port}", "CRITICAL")

        # Test TE.CL
        te_cl_dur = self.check_te_cl(host, port, protocol)
        if te_cl_dur and te_cl_dur > baseline_dur + 3:
             findings.append({
                "title": "🔥 CRITICAL: HTTP Request Smuggling (TE.CL) Suspected",
                "description": (
                    f"The server at `{host}:{port}` showed a significant delay ({te_cl_dur:.2f}s vs {baseline_dur:.2f}s) "
                    "when probed with a TE.CL desynchronization payload. "
                    "This suggests the front-end proxy uses `Transfer-Encoding` while the back-end uses `Content-Length`."
                ),
                "severity": "critical",
                "tool_source": "smuggling_expert",
                "type": "Desync"
            })
             if logger: logger(f"💀 SMUGGLING DETECTED: TE.CL Desync on {port}", "CRITICAL")

        return findings
