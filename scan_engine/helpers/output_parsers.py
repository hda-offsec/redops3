import re

def parse_nmap_open_ports(nmap_output):
    """
    Parses Nmap standard output for open ports.
    Splits by line first to avoid greedy regex across multiple ports.
    """
    open_ports = []
    # Regex matching: 80/tcp open  http  Apache 2.4
    port_pattern = re.compile(r"(\d+)/(tcp|udp)\s+open\s+([^\s]+)\s*(.*)")
    
    for line in nmap_output.splitlines():
        line = line.strip()
        match = port_pattern.search(line)
        if match:
            port = int(match.group(1))
            service = match.group(3)
            version = match.group(4).strip()
            
            open_ports.append({
                "port": port,
                "service_name": service,
                "version": version if version else None
            })
            
    return open_ports
