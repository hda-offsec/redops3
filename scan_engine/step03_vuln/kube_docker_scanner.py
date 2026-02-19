import socket
import requests

class KubeDockerScanner:
    def __init__(self, target):
        self.target = target

    def scan_containers(self, logger=None):
        findings = []
        
        # Specific ports for check
        ports = {
            2375: "Docker API (Unencrypted)",
            2376: "Docker API (TLS)",
            10250: "Kubelet API",
            6443: "Kubernetes API Server",
            10255: "Kubelet Read-Only Port"
        }
        
        if logger: logger(f"🐳 Container Sec: Scanning orchestration ports on {self.target}...", "INFO")

        for port, service in ports.items():
            try:
                # Quick connect check
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.target, port))
                sock.close()
                
                if result == 0:
                    # Port is open, try to get info
                    try:
                        url = f"http://{self.target}:{port}/pods" if port in [10250, 10255] else f"http://{self.target}:{port}/version"
                        if port == 6443: url = f"https://{self.target}:{port}/version"
                        
                        r = requests.get(url, timeout=3, verify=False)
                        if r.status_code == 200:
                            findings.append({
                                "title": f"CRITICAL: Exposed {service}",
                                "description": f"{service} is exposed on port {port} and accessible without auth. This allows full cluster takeover.",
                                "severity": "critical",
                                "tool_source": "kube_scanner",
                                "raw_loot": url
                            })
                            if logger: logger(f"🚨 CLUSTER BREACH: {service} on port {port}", "CRITICAL")
                        else:
                             findings.append({
                                "title": f"High: Exposed {service} Port",
                                "description": f"{service} port {port} is open but returned {r.status_code}. It should not be exposed publicly.",
                                "severity": "high",
                                "tool_source": "kube_scanner"
                            })
                    except:
                        # Just open but timeout on HTTP
                         findings.append({
                                "title": f"Medium: Exposed Container Port {port}",
                                "description": f"Port {port} ({service}) is open. Verify firewall rules.",
                                "severity": "medium",
                                "tool_source": "kube_scanner"
                            })

            except Exception:
                continue
            
        return findings

    # Alias for orchestrator compatibility
    def scan_exposure(self, port, protocol='http', logger=None):
        return self.scan_containers(logger=logger)

