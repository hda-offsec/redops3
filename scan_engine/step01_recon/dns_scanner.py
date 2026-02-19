import json
from scan_engine.helpers.process_manager import ProcessManager

class DNSScanner:
    def __init__(self, target):
        self.target = target

    def check_tools(self):
        return ProcessManager.find_binary_path("dnsrecon") is not None

    def parse_results(self, output_file):
        """Parse DNSRecon JSON output file"""
        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        return []

    def run_dnsrecon(self, output_file=None):
        """Run dnsrecon for standard enumeration"""
        if output_file is None:
            output_file = f"data/results/dns_{self.target}.json"
        
        # --- STALE OUTPUT CLEANUP ---
        import os
        if os.path.exists(output_file):
            try:
                os.remove(output_file)
            except Exception:
                pass
                
        command = ["dnsrecon", "-d", self.target, "-t", "std", "--json", output_file]
        return ProcessManager.run_command(command)

    def run_subfinder(self):
        """Run subfinder for subdomain discovery"""
        subfinder_path = ProcessManager.find_binary_path("subfinder") or "subfinder"
        
        command = [subfinder_path, "-d", self.target, "-silent"]
        return ProcessManager.run_command(command)

    def analyze_security(self, records):
        """
        Analyze DNS records for security issues (SPF/DMARC/Takeover).
        Ported from RedOps2.
        """
        analysis = {
            "spf": {"present": False, "policy": "None", "rating": "High Risk"},
            "dmarc": {"present": False, "policy": "None", "rating": "High Risk"},
            "takeovers": [],
            "cdn": [],
            "mx_providers": []
        }
        
        # Flatten and normalize records
        txt_records = [r for r in records if r.get('type') == 'TXT']
        cname_records = [r for r in records if r.get('type') == 'CNAME']
        mx_records = [r for r in records if r.get('type') == 'MX']
        
        # SPF Analysis
        for r in txt_records:
            # dnsrecon stores TXT value in 'name' or 'strings'
            val = r.get('strings', '') 
            if isinstance(val, list): val = " ".join(val)
            if not val: val = r.get('name', '')
            
            if not isinstance(val, str): val = str(val)
            
            if "v=spf1" in val.lower():
                analysis['spf']['present'] = True
                if "-all" in val:
                    analysis['spf']['policy'] = "Strict (-all)"
                    analysis['spf']['rating'] = "Secure"
                elif "~all" in val:
                    analysis['spf']['policy'] = "SoftFail (~all)"
                    analysis['spf']['rating'] = "Medium Risk"
                elif "?all" in val:
                    analysis['spf']['policy'] = "Neutral (?all)"
                    analysis['spf']['rating'] = "High Risk"
                else:
                    analysis['spf']['policy'] = "Permissive (+all)"
                    analysis['spf']['rating'] = "Critical Risk"
                    
        # DMARC Analysis
        for r in txt_records:
            val = r.get('strings', '')
            if isinstance(val, list): val = " ".join(val)
            if not val: val = r.get('name', '')
            if not isinstance(val, str): val = str(val)

            if "v=DMARC1" in val or "v=dmarc1" in val:
                analysis['dmarc']['present'] = True
                if "p=reject" in val:
                    analysis['dmarc']['policy'] = "Reject"
                    analysis['dmarc']['rating'] = "Secure"
                elif "p=quarantine" in val:
                    analysis['dmarc']['policy'] = "Quarantine"
                    analysis['dmarc']['rating'] = "Medium Risk"
                else:
                    analysis['dmarc']['policy'] = "None"
                    analysis['dmarc']['rating'] = "High Risk"

        # CNAME Takeovers & CDN
        suspicious = ['github.io', 'herokuapp.com', "s3.amazonaws.com", "azurewebsites.net", "pantheon.io", "shopify.com"]
        cdns = ['cloudfront.net', 'akamai', 'fastly', 'cloudflare', 'incapsula', 'cdn']
        
        for r in cname_records:
            target = r.get('target', '').lower()
            if any(s in target for s in suspicious):
                analysis['takeovers'].append({'alias': r.get('name'), 'target': target})
            if any(c in target for c in cdns):
                analysis['cdn'].append(target)
                
        # MX Providers
        for r in mx_records:
             exchange = r.get('exchange', '').lower()
             if 'google' in exchange or 'googlemail' in exchange: analysis['mx_providers'].append("GSuite")
             elif 'outlook' in exchange or 'protection' in exchange: analysis['mx_providers'].append("Office365")
             elif 'zoho' in exchange: analysis['mx_providers'].append("Zoho")
             elif 'proton' in exchange: analysis['mx_providers'].append("ProtonMail")
             
        analysis['mx_providers'] = list(set(analysis['mx_providers']))
        return analysis

    def enumerate_all(self, logger=None):
        results = {
            "subdomains": [],
            "records": [],
            "security": {}
        }
        
        # Subfinder logic
        if logger: logger("Checking for subdomains via Subfinder...", "INFO")
        success, stdout, stderr, code = self.run_subfinder()
        if success:
            found = [line.strip() for line in stdout.splitlines() if line.strip()]
            
            # --- ROOT DOMAIN EXTRACTION (Hardened) ---
            try:
                import tldextract
                ext = tldextract.extract(self.target)
                root_domain = f"{ext.domain}.{ext.suffix}"
            except ImportError:
                # Fallback heuristic
                target_domain = self.target
                if "://" in target_domain:
                     from urllib.parse import urlparse
                     target_domain = urlparse(target_domain).hostname
                
                parts = target_domain.split('.')
                if len(parts) >= 2:
                    if len(parts) >= 3 and parts[-2] in ['com', 'org', 'net', 'edu', 'gov', 'co', 'ac']:
                        root_domain = ".".join(parts[-3:])
                    else:
                        root_domain = ".".join(parts[-2:])
                else:
                    root_domain = target_domain

            # Filter subdomains against the root domain
            filtered = [sub for sub in found if sub.endswith(root_domain)]
            results["subdomains"] = filtered
            
            if logger: logger(f"Subfinder finished. Found {len(filtered)} subdomains (root: {root_domain}).", "SUCCESS")
        else:
            if logger: logger("Subfinder failed or returned nothing.", "WARN")
            results["subdomains"] = [] # Explicitly clear if failed
            
        # DNSRecon
        output_file = f"data/results/dns_{self.target}.json"

        if logger: logger("Enumerating DNS records via DNSRecon...", "INFO")
        success, stdout, stderr, code = self.run_dnsrecon(output_file)
        if success:
            if logger: logger("DNSRecon enumeration complete.", "SUCCESS")

            # Parse results
            records = self.parse_results(output_file)
            if records:
                results["records"] = records
                if logger: logger(f"Parsed {len(records)} DNS records.", "SUCCESS")
                
                # NEW: Security Analysis
                results["security"] = self.analyze_security(records)
                sec = results["security"]
                if logger:
                    logger(f"DNS Security: SPF {sec['spf']['policy']} | DMARC {sec['dmarc']['policy']}", 
                           "SUCCESS" if sec['spf']['present'] and sec['dmarc']['present'] else "WARN")
            else:
                if logger: logger("No DNS records parsed from output.", "WARN")
        else:
            if logger: logger("DNSRecon enumeration skipped or failed.", "WARN")
            
        return results
