import re

def parse_nmap_open_ports(nmap_output):
    """
    Simulated parsing of Nmap stdout text.
    In a real scenario, parsing XML output (-oX) is much more reliable.
    """
    open_ports = []
    # Regex to capture lines like: "80/tcp open http nginx 1.18.0"
    regex = re.compile(r"^(\d+)/tcp\s+open\s+([\w\-\?]+)(?:\s+(.*))?")
    
    for line in nmap_output.splitlines():
        match = regex.search(line)
        if match:
            port = int(match.group(1))
            service = match.group(2)
            version = match.group(3) or ""
            open_ports.append({
                "port": port,
                "service_name": service,
                "version": version.strip()
            })
    return open_ports
