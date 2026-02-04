import re

PORT_LINE_RE = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)")
WHATWEB_PAIR_RE = re.compile(r"([A-Za-z0-9_-]+)\[([^\]]+)\]")
NUCLEI_SEVERITY_RE = re.compile(r"\[(critical|high|medium|low|info)\]", re.IGNORECASE)
FFUF_LINE_RE = re.compile(r"^(?P<path>\S+)\s+\[Status:\s*(?P<status>\d+),\s*Size:\s*(?P<size>\d+)")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text):
    return ANSI_RE.sub("", text or "")


def parse_nmap_open_ports(output_text):
    ports = []
    for line in output_text.splitlines():
        match = PORT_LINE_RE.search(strip_ansi(line.strip()))
        if not match:
            continue
        ports.append({"port": int(match.group(1)), "service": match.group(2)})
    return ports


def parse_whatweb_line(line):
    if not line:
        return {}
    clean_line = strip_ansi(line)
    pairs = WHATWEB_PAIR_RE.findall(clean_line)
    if not pairs:
        return {}
    result = {}
    for key, value in pairs:
        result[key] = value
    return result


def parse_nuclei_line(line):
    if not line:
        return None
    clean_line = strip_ansi(line)
    severity_match = NUCLEI_SEVERITY_RE.search(clean_line)
    if not severity_match:
        return None
    return {"severity": severity_match.group(1).lower(), "title": clean_line.strip()}


def parse_ffuf_line(line):
    if not line:
        return None
    clean_line = strip_ansi(line.strip())
    match = FFUF_LINE_RE.search(clean_line)
    if not match:
        return None
    return {
        "path": match.group("path"),
        "status": int(match.group("status")),
        "size": int(match.group("size")),
    }
