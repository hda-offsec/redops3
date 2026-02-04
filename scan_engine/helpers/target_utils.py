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
