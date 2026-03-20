import socket
import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session

class KubeDockerScanner:
    def __init__(self, target, options=None):
        self.options = options
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
                        
                        r = http_client.get(url, options=getattr(self, "options", None), timeout=3)
                        
                        from scan_engine.helpers.finding_normalizer import FindingNormalizer
                        
                        if r.status_code == 200:
                            findings.append(FindingNormalizer.from_response(
                                r,
                                title=f"Exposed {service}",
                                description=f"The `{service}` is exposed on port {port} and is directly accessible without authentication.\n\nThis is a critical security risk that often allows an unauthenticated attacker to execute arbitrary commands, read sensitive secrets, or achieve full cluster takeover.",
                                severity="critical",
                                confidence="certain",
                                tool_source="kube_scanner",
                                category="cloud",
                                evidence={
                                    "proof": r.text[:500]
                                },
                                repro_command=f"curl -ik {url}",
                                metadata={
                                    "validation_status": "success",
                                    "port": port,
                                    "component": "Kubernetes/Docker"
                                }
                            ))
                            if logger: logger(f"🚨 CLUSTER BREACH: {service} on port {port}", "CRITICAL")
                        else:
                             findings.append(FindingNormalizer.from_response(
                                r,
                                title=f"Exposed {service} Port",
                                description=f"The `{service}` port ({port}) is open and reachable from the internet, though it returned an HTTP `{r.status_code}` response.\n\nWhile potentially authenticated, control plane ports should never be exposed to the public internet.",
                                severity="high",
                                confidence="high",
                                tool_source="kube_scanner",
                                category="cloud",
                                repro_command=f"curl -ik {url}",
                                metadata={
                                    "validation_status": "success",
                                    "port": port,
                                    "component": "Kubernetes/Docker"
                                }
                            ))
                    except Exception as e:
                        # Just open but timeout on HTTP
                         from scan_engine.helpers.finding_normalizer import FindingNormalizer
                         findings.append(FindingNormalizer.normalize({
                                "title": f"Exposed Container Port {port}",
                                "description": f"Port {port} ({service}) is open at the network level, but did not respond to basic HTTP requests.\n\nVerify firewall rules and restrict access to trusted source IPs only.",
                                "severity": "medium",
                                "confidence": "high",
                                "tool_source": "kube_scanner",
                                "category": "cloud",
                                "endpoint": f"tcp://{self.target}:{port}",
                                "reproduction": f"nmap -p {port} -sV {self.target}",
                                "metadata": {
                                    "port": port,
                                    "component": "Kubernetes/Docker"
                                }
                            }))

            except Exception:
                continue
            
        return findings

    # Alias for orchestrator compatibility
    def scan_exposure(self, port, protocol='http', logger=None):
        return self.scan_containers(logger=logger)

