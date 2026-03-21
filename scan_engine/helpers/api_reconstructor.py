import re
from urllib.parse import urlparse, urlunparse
from scan_engine.helpers.discovery_accumulator import DiscoveryAccumulator

class ApiReconstructor:
    """
    Utility to reconstruct the full API and web directory structure from 
    disparate discovery sources (Katana, Kiterunner, ffuf, findings).
    """

    DYNAMIC_SEGMENT_RE = re.compile(r"(\{\{[^{}]+\}\}|\{[^{}]+\}|:[A-Za-z_][\w-]*|<[^<>]+>)")

    @staticmethod
    def _coerce_status(value):
        if isinstance(value, int):
            return value if 100 <= value <= 599 else None
        if isinstance(value, str):
            match = re.search(r"\b([1-5][0-9]{2})\b", value)
            if match:
                return int(match.group(1))
        return None

    @staticmethod
    def _absolutize_url(candidate, base_url):
        if not isinstance(candidate, str):
            return ""
        url = candidate.strip()
        if not url:
            return ""
        if url.startswith("/"):
            return f"{base_url}{url}"
        if not url.startswith("http"):
            return f"{base_url}/{url.lstrip('/')}"
        return url

    @staticmethod
    def _normalize_url_key(candidate):
        try:
            parsed = urlparse(candidate)
        except Exception:
            return ""
        scheme = (parsed.scheme or "http").lower()
        netloc = (parsed.netloc or "").lower()
        path = parsed.path or "/"
        if path != "/":
            path = path.rstrip("/") or "/"
        if not netloc:
            return ""
        return urlunparse((scheme, netloc, path, "", "", ""))

    @staticmethod
    def _is_templated_path(path):
        return bool(ApiReconstructor.DYNAMIC_SEGMENT_RE.search(path or ""))

    @staticmethod
    def _status_priority(source):
        src = str(source or "").lower()
        if src.startswith("dirbusting"):
            return 30
        if src in {"api_discovery", "api_expert"}:
            return 20
        if src:
            return 10
        return 0

    @staticmethod
    def _iter_dirbusting_endpoints(results, port):
        dirb_phase = results.get("phases", {}).get("dirbusting", {})
        if not isinstance(dirb_phase, dict):
            return []

        buckets = [dirb_phase]
        per_port = dirb_phase.get(str(port))
        if isinstance(per_port, dict):
            buckets.append(per_port)

        rows = []
        for bucket in buckets:
            if not isinstance(bucket, dict):
                continue
            for tool in ("ffuf", "gobuster", "dirsearch"):
                payload = bucket.get(tool)
                if isinstance(payload, dict):
                    endpoints = payload.get("endpoints", [])
                elif isinstance(payload, list):
                    endpoints = payload
                else:
                    continue
                if isinstance(endpoints, list):
                    rows.extend(endpoints)
        return rows

    @staticmethod
    def reconstruct(results, findings=None):
        """
        Reconstructs the hierarchical tree.
        Findings (if provided) are used to enrich the tree with vulnerability markers.
        """
        target = results.get("target", "unknown")
        ports = []

        recon = results.get("phases", {}).get("recon", {})
        for p_obj in recon.get("open_ports", []):
            ports.append(p_obj.get("port"))

        if not ports:
            enum = results.get("phases", {}).get("enum", {})
            for key in enum.get("whatweb", {}).get("summary", {}).keys():
                try:
                    ports.append(int(key))
                except Exception:
                    pass

        tree = {"name": target, "type": "root", "children": []}

        for port in set(ports):
            port_node = {"name": f"Port {port}", "type": "port", "port": port, "children": []}

            proto = "https" if port == 443 else "http"
            base_url = f"{proto}://{target}:{port}"
            all_urls = DiscoveryAccumulator.gather(results, port, target, proto=proto)

            url_metadata = {}

            def register_status(url, status_value, source):
                absolute = ApiReconstructor._absolutize_url(url, base_url)
                url_key = ApiReconstructor._normalize_url_key(absolute)
                status = ApiReconstructor._coerce_status(status_value)
                if not url_key or status is None:
                    return
                current = url_metadata.get(url_key)
                payload = {"status": status, "source": source}
                if not current or ApiReconstructor._status_priority(source) >= ApiReconstructor._status_priority(current.get("source")):
                    url_metadata[url_key] = payload

            api_endpoints = results.get("phases", {}).get("enum", {}).get("api", {}).get("endpoints", [])
            for ep in api_endpoints:
                if not isinstance(ep, dict):
                    continue
                url = ep.get("url") or ep.get("endpoint")
                if url:
                    register_status(url, ep.get("status"), ep.get("source") or "api_enum")

            for ep in ApiReconstructor._iter_dirbusting_endpoints(results, port):
                if not isinstance(ep, dict):
                    continue
                url = ep.get("url") or ep.get("endpoint")
                if url:
                    register_status(url, ep.get("status"), f"dirbusting:{ep.get('source') or 'scan'}")

            findings_on_url = {}
            if findings:
                for finding in findings:
                    url = finding.get("endpoint") or finding.get("target")
                    if not isinstance(url, str):
                        continue
                    url_key = ApiReconstructor._normalize_url_key(ApiReconstructor._absolutize_url(url, base_url))
                    if not url_key:
                        continue
                    findings_on_url.setdefault(url_key, []).append({
                        "id": finding.get("id_stable") or finding.get("id"),
                        "severity": finding.get("severity", "info"),
                        "title": finding.get("title")
                    })

            port_tree = {}
            for raw_url in sorted(set(all_urls)):
                absolute_url = ApiReconstructor._absolutize_url(raw_url, base_url)
                parsed = urlparse(absolute_url)
                path = parsed.path or "/"
                url_key = ApiReconstructor._normalize_url_key(absolute_url)
                status_entry = url_metadata.get(url_key, {})
                status_code = status_entry.get("status")
                templated = ApiReconstructor._is_templated_path(path)

                parts = [p for p in path.split("/") if p]
                if not parts:
                    parts = ["/"]

                current = port_tree
                for index, part in enumerate(parts):
                    if part not in current:
                        current[part] = {"_meta": {"name": part, "type": "dir", "children": {}}}

                    if index == len(parts) - 1:
                        meta = current[part]["_meta"]
                        meta["type"] = "file" if "." in part or index > 0 else "dir"
                        meta["url"] = absolute_url
                        meta["status"] = status_code
                        meta["status_source"] = status_entry.get("source", "unverified") if status_code is not None else "unverified"
                        meta["templated"] = bool(templated)
                        meta["clickable"] = not templated
                        meta["findings"] = findings_on_url.get(url_key, [])

                    current = current[part]["_meta"]["children"]

            def dict_to_list(node_dict):
                rows = []
                for _, wrapped in node_dict.items():
                    node = wrapped["_meta"]
                    node["children"] = dict_to_list(node["children"])
                    rows.append(node)
                rows.sort(key=lambda item: (0 if item["children"] else 1, item["name"].lower()))
                return rows

            port_node["children"] = dict_to_list(port_tree)
            if port_node["children"]:
                tree["children"].append(port_node)

        return tree
