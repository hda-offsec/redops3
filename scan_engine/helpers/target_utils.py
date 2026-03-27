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

def validate_target(target, allow_internal=True):
    """
    Validates the target identifier to prevent SSRF and scanning of internal/private networks.

    Args:
        target (str): The target hostname or IP address.
        allow_internal (bool): If True, permits internal scopes.

    Returns:
        bool: True if valid.

    Raises:
        ValueError: If the target is invalid or resolves to a private/loopback address.
    """
    if not target:
        raise ValueError("Target cannot be empty.")

    # 1. Handle CIDR first
    if "/" in target:
        try:
             # Check if it's a valid CIDR network (e.g. 192.168.1.0/24)
             # strict=False allows host addresses (e.g. 192.168.1.1/24)
             net = ipaddress.ip_network(target, strict=False)
             _check_network_safety(net, allow_internal)
             return True
        except ValueError:
             pass # Not a valid CIDR, proceed to hostname/IP validation

    # 2. Extract hostname for resolution
    hostname = target
    if "://" in target:
        try:
            parsed = urlparse(target)
            if parsed.hostname:
                hostname = parsed.hostname
        except ValueError:
            pass # fallback to string split if parsing fails
    elif "/" in hostname:
        # Handle cases like hove.io/admin where no scheme is present
        hostname = hostname.split("/")[0]

    # Handle simple "hostname:port" case if urlparse didn't catch it (because of no scheme)
    if ":" in hostname and not hostname.startswith("["): # Check for port but exclude IPv6 literal
         hostname = hostname.split(":")[0]
    elif hostname.startswith("[") and "]:" in hostname: # IPv6 literal with port
         hostname = hostname.split("]:")[0].strip("[")
    elif hostname.startswith("[") and hostname.endswith("]"): # IPv6 literal without port
         hostname = hostname.strip("[]")

    if not hostname:
         raise ValueError("Invalid target format.")

    # 1. Check if it's an IP address directly
    try:
        ip_obj = ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        _check_ip_safety(ip_obj, allow_internal)
        return True

    # 2. Resolve Hostname
    try:
        # Use getaddrinfo to get all IPs (IPv4 and IPv6)
        # 0, 0, 0, 0 means AF_UNSPEC, SOCK_STREAM, 0, AI_PASSIVE (default flags for getaddrinfo usually ok)
        addr_info = socket.getaddrinfo(hostname, None)
        if not addr_info:
            raise ValueError(f"Could not resolve hostname: {hostname}")

        for res in addr_info:
            # res structure: (family, socktype, proto, canonname, sockaddr)
            # sockaddr for AF_INET is (address, port)
            # sockaddr for AF_INET6 is (address, port, flow info, scope id)
            ip_str = res[4][0]
            try:
                # Remove scope ID from IPv6 address string if present (e.g. fe80::1%eth0)
                if "%" in ip_str:
                    ip_str = ip_str.split("%")[0]

                ip_obj = ipaddress.ip_address(ip_str)
                valid_ip = True
            except ValueError:
                valid_ip = False

            if valid_ip:
                _check_ip_safety(ip_obj, allow_internal)
    except socket.gaierror:
        # Fallback for domains with no A/AAAA but other records (MX, TXT).
        # We allow them but since they have no IPs, they are effectively "safe"
        # from SSRF, they will just fail naturally in scanner steps.
        import subprocess
        try:
            res = subprocess.run(["host", hostname], capture_output=True, text=True, timeout=5)
            if "not found" in res.stdout or res.returncode != 0:
                raise ValueError(f"Could not resolve hostname: {hostname}")
        except Exception:
             raise ValueError(f"Could not resolve hostname: {hostname}")

    return True

def _check_ip_safety(ip_obj, allow_internal):
    if ip_obj.is_unspecified: # 0.0.0.0
         raise ValueError(f"Target resolves to unspecified address: {ip_obj}")
         
    if not allow_internal:
        if ip_obj.is_loopback:
            raise ValueError(f"Target resolves to loopback address: {ip_obj}")
        if ip_obj.is_private:
            raise ValueError(f"Target resolves to private address: {ip_obj}")
        if ip_obj.is_reserved:
            raise ValueError(f"Target resolves to reserved address: {ip_obj}")
        if ip_obj.is_link_local:
            raise ValueError(f"Target resolves to link-local address: {ip_obj}")
        if ip_obj.is_multicast:
            raise ValueError(f"Target resolves to multicast address: {ip_obj}")

def _check_network_safety(net_obj, allow_internal):
    """Checks if the given network is safe for scanning."""
    if not allow_internal:
        if net_obj.is_loopback:
            raise ValueError(f"Target network is loopback: {net_obj}")
        if net_obj.is_private:
            raise ValueError(f"Target network is private: {net_obj}")
        if net_obj.is_reserved:
            raise ValueError(f"Target network is reserved: {net_obj}")
        if net_obj.is_link_local:
            raise ValueError(f"Target network is link-local: {net_obj}")
        if net_obj.is_multicast:
            raise ValueError(f"Target network is multicast: {net_obj}")
    if net_obj.is_unspecified: # 0.0.0.0/x
         raise ValueError(f"Target network is unspecified: {net_obj}")
