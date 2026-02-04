TOOL_MAPPING = {
    "nmap": {"phase": "recon", "type": "port_scanner", "binary": "nmap"},
    "whatweb": {"phase": "enum", "type": "fingerprinter", "binary": "whatweb"},
    "nuclei": {"phase": "vuln", "type": "vuln_scanner", "binary": "nuclei"},
    "ffuf": {"phase": "dirbusting", "type": "fuzzer", "binary": "ffuf"},
}


def get_tool_config(tool_name):
    return TOOL_MAPPING.get(tool_name, {})
