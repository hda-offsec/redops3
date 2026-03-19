import os
import json
from urllib.parse import urlparse
from scan_engine.helpers.discovery_accumulator import DiscoveryAccumulator

class ApiReconstructor:
    """
    Utility to reconstruct the full API and web directory structure from 
    disparate discovery sources (Katana, Kiterunner, ffuf, findings).
    """

    @staticmethod
    def reconstruct(results, findings=None):
        """
        Reconstructs the hierarchical tree.
        Findings (if provided) are used to enrich the tree with vulnerability markers.
        """
        scan_id = results.get('scan_id')
        target = results.get('target', 'unknown')
        ports = []
        
        # Identify scanned ports
        recon = results.get('phases', {}).get('recon', {})
        for p_obj in recon.get('open_ports', []):
            ports.append(p_obj.get('port'))
        
        # If no ports found in recon, check elsewhere
        if not ports:
            enum = results.get('phases', {}).get('enum', {})
            for key in enum.get('whatweb', {}).get('summary', {}).keys():
                try: ports.append(int(key))
                except: pass
        
        tree = {"name": target, "type": "root", "children": []}
        
        for port in set(ports):
            port_node = {"name": f"Port {port}", "type": "port", "port": port, "children": []}
            
            # Gather all URLs for this port
            # Note: We need to know which URLs belong to which port. 
            # DiscoveryAccumulator.gather(results, port, target) does exactly this.
            # But wait, DiscoveryAccumulator.gather returns absolute URLs.
            
            # Determine protocol
            proto = "https" if port == 443 else "http"
            all_urls = DiscoveryAccumulator.gather(results, port, target, proto=proto)
            
            # Map of URL -> Status/Metadata
            url_metadata = {}
            
            # Enrich with status codes from API discovery if available
            api_endpoints = results.get('phases', {}).get('enum', {}).get('api', {}).get('endpoints', [])
            for ep in api_endpoints:
                if isinstance(ep, dict) and ep.get('url'):
                    url_metadata[ep['url']] = {"status": ep.get('status', 200), "source": ep.get('source')}

            # Enrich with findings
            findings_on_url = {}
            if findings:
                for f in findings:
                    url = f.get('endpoint') or f.get('target')
                    if url and isinstance(url, str):
                        findings_on_url.setdefault(url, []).append({
                            "id": f.get('id_stable') or f.get('id'),
                            "severity": f.get('severity', 'info'),
                            "title": f.get('title')
                        })

            # Build the internal tree for this port
            port_tree = {} # path parts -> node
            
            for url in all_urls:
                parsed = urlparse(url)
                path = parsed.path
                if not path: path = "/"
                
                parts = [p for p in path.split('/') if p]
                if not parts: parts = ["/"]
                
                curr = port_tree
                for i, part in enumerate(parts):
                    if part not in curr:
                        curr[part] = {"_meta": {"name": part, "type": "dir", "children": {}}}
                    
                    # If it's the leaf node, add metadata
                    if i == len(parts) - 1:
                        meta = curr[part]["_meta"]
                        meta["type"] = "file" if "." in part or i > 0 else "dir"
                        meta["url"] = url
                        meta["status"] = url_metadata.get(url, {}).get('status', 200)
                        meta["findings"] = findings_on_url.get(url, [])
                    
                    curr = curr[part]["_meta"]["children"]
            
            # Convert port_tree (dict) to port_node['children'] (list)
            def dict_to_list(d):
                l = []
                for k, v in d.items():
                    node = v["_meta"]
                    node["children"] = dict_to_list(node["children"])
                    l.append(node)
                # Sort: dirs first, then files
                l.sort(key=lambda x: (0 if x['children'] else 1, x['name'].lower()))
                return l
            
            port_node["children"] = dict_to_list(port_tree)
            if port_node["children"]:
                tree["children"].append(port_node)
                
        return tree
