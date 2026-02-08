import socket
import ipaddress
from urllib.parse import urlparse

def normalize_target_url(target, port=None, scheme=None):
    if target.startswith("http://") or target.startswith("https://"):
        return target

    resolved_scheme = scheme
    if not resolved_scheme:
        if port in (443, 8443):
            resolved_scheme = "https"
        else:
            resolved_scheme = "http"

    if port and port not in (80, 443):
        return f"{resolved_scheme}://{target}:{port}"

    return f"{resolved_scheme}://{target}"


def validate_target(target_input):
    """
    Validates that the target is not an internal IP, loopback, or reserved address.
    Returns (True, None) if safe, or (False, reason) if unsafe.
    """
    if not target_input:
        return False, "Empty target"

    host = target_input.strip()

    # 1. Handle URL
    if "://" in host:
        try:
            parsed = urlparse(host)
            host = parsed.hostname
            if not host:
                return False, "Invalid URL"
        except ValueError:
            return False, "Invalid URL format"

    # 2. Handle host:port (if not a URL)
    elif ":" in host:
        # Logic to differentiate IPv6 from host:port
        # If it contains brackets, extract content
        if "[" in host and "]" in host:
            start = host.find("[") + 1
            end = host.find("]")
            host = host[start:end]
        # If multiple colons and no brackets, it's likely a raw IPv6
        elif host.count(":") > 1:
            pass # Keep as is, likely IPv6
        # If single colon, it's host:port
        else:
            host = host.split(":")[0]

    # Remove brackets if they remained (e.g. [::1])
    host = host.strip("[]")

    try:
        # Resolve to IP(s)
        # getaddrinfo handles both IPv4 and IPv6 and hostnames
        # We use a dummy port 80 to ensure we get a result if possible, though None works too.
        addr_info = socket.getaddrinfo(host, None)

        for res in addr_info:
            ip_str = res[4][0]
            ip = ipaddress.ip_address(ip_str)

            if ip.is_loopback:
                return False, f"Target resolves to loopback address: {ip_str}"
            if ip.is_private:
                return False, f"Target resolves to private network address: {ip_str}"
            if ip.is_link_local:
                return False, f"Target resolves to link-local address: {ip_str}"
            if ip.is_multicast:
                return False, f"Target resolves to multicast address: {ip_str}"
            if ip.is_reserved:
                return False, f"Target resolves to reserved address: {ip_str}"
            if str(ip) == "0.0.0.0" or str(ip) == "::":
                 return False, f"Target is wildcard address: {ip_str}"

        return True, None

    except socket.gaierror:
        # If we can't resolve it, we can't verify it.
        return False, f"Could not resolve hostname: {host}"
    except ValueError:
        return False, f"Invalid IP address derived from: {host}"
    except Exception as e:
        return False, f"Validation error: {str(e)}"
