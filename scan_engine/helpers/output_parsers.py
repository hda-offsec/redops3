import re

def parse_nmap_open_ports(nmap_output):
    """
    Simulated parsing of Nmap stdout text.
    In a real scenario, parsing XML output (-oX) is much more reliable.
    """
    open_ports = []
    # Ultra-permissive regex to capture any open port line
    # Matches: 80/tcp  open  http     Apache 2.4
    # Matches: 80/tcp  open  unknown
    regex = re.compile(r"^\s*(\d+)/(\w+)\s+open\s+(\S+)(?:\s+(.*))?", re.MULTILINE)
    
    matches = regex.findall(nmap_output)
    
    for match in matches:
        port = int(match[0])
        # protocol = match[1]
        service = match[2]
        # Clean up version (sometimes nmap puts extra spaces or pipe chars)
        version = match[3].strip() if len(match) > 3 and match[3] else ""
        
        # Fallback: if version is empty but service is huge, maybe regex split wrong?
        # Nmap -sV output is column aligned, usually reliable.
        
        open_ports.append({
            "port": port,
            "service_name": service,
            "version": version
        })
        
    return open_ports
