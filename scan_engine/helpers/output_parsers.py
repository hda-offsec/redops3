import re

def parse_nmap_open_ports(nmap_output):
    """
    Simulated parsing of Nmap stdout text.
    In a real scenario, parsing XML output (-oX) is much more reliable.
    """
    open_ports = []
    # Regex specifically for finding open ports lines in standard output
    # Matches: PORT/PROTO STATE SERVICE VERSION
    # Example: 80/tcp open http nginx 1.18.0
    # Improved regex to handle variable whitespace and optional version
    regex = re.compile(r"^\s*(\d+)/(\w+)\s+open\s+([\w\-\?]+)(?:\s+(.*))?", re.MULTILINE)
    
    # Also support | grep able format just in case
    # Host: 127.0.0.1 ()	Ports: 80/open/tcp//http//nginx 1.18.0/
    
    matches = regex.findall(nmap_output)
    
    for match in matches:
        port = int(match[0])
        # protocol = match[1] # e.g. tcp
        service = match[2]
        version = match[3] if len(match) > 3 else ""
        
        open_ports.append({
            "port": port,
            "service_name": service,
            "version": version.strip()
        })
        
    return open_ports
