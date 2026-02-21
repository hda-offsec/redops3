import socket
import time

class InfraExposureScanner:
    """
    Expert Auditor for Infrastructure service exposure.
    Tests for unauthenticated access to Redis, Memcached, Etcd, and Docker.
    """
    def __init__(self, target, options=None):
        self.options = options
        self.target = target
        self.ports = {
            "redis": 6379,
            "memcached": 11211,
            "etcd": 2379,
            "docker": 2375,
            "mongodb": 27017,
            "elasticsearch": 9200
        }

    def scan_common_ports(self, logger=None):
        findings = []
        for service, port in self.ports.items():
            try:
                if logger: logger(f"Infra Exposure: Testing {service} on port {port}...", "INFO")
                
                # Simple socket connection test with protocol-specific trigger
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                result = s.connect_ex((self.target, port))
                
                if result == 0:
                    # Port is open, try to send a "no-auth" command
                    if service == "redis":
                        s.sendall(b"INFO\r\n")
                        data = s.recv(1024)
                        if b"redis_version" in data:
                            findings.append(self._make_finding(service, port, "Full unauthenticated access to Redis instance."))
                    
                    elif service == "memcached":
                        s.sendall(b"stats\r\n")
                        data = s.recv(1024)
                        if b"STAT pid" in data:
                            findings.append(self._make_finding(service, port, "Unauthenticated access to Memcached stats."))
                    
                    elif service == "docker":
                        # Docker API check
                        s.sendall(b"GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n")
                        data = s.recv(1024)
                        if b"ApiVersion" in data:
                            findings.append(self._make_finding(service, port, "Docker Engine API exposed! Potential remote root takeover.", "critical"))
                            
                s.close()
            except Exception:
                pass
        return findings

    def _make_finding(self, service, port, desc, severity="high"):
        return {
            "title": f"Exposed Infrastructure Service: {service.upper()}",
            "description": f"{desc}\nTarget: {self.target}:{port}\nThis allows for sensitive data theft or remote command execution.",
            "severity": severity,
            "tool_source": "infra_expert",
            "url": f"{self.target}:{port}"
        }
