import socket
import dns.resolver

class SubdomainExpertScanner:
    def __init__(self, target):
        self.target = target
        # Fingerprints for Subdomain Takeover
        self.fingerprints = {
            "s3.amazonaws.com": "AWS S3 Bucket",
            "herokuapp.com": "Heroku App",
            "zendesk.com": "Zendesk",
            "github.io": "GitHub Pages",
            "shopify.com": "Shopify Store",
            "wpengine.com": "WPEngine",
            "bitbucket.io": "Bitbucket",
            "squarespace.com": "Squarespace",
            "unbounce.com": "Unbounce",
            "pantheonsite.io": "Pantheon",
            "tumblr.com": "Tumblr",
            "readme.io": "ReadMe.io",
            "alias.zeit.co": "Vercel",
            "azurewebsites.net": "Azure Website"
        }

    def check_takeover(self, subdomains, logger=None):
        """
        Analyzes subdomains for potential takeover vulnerabilities by checking CNAME records.
        """
        findings = []
        if not subdomains:
            return findings

        if logger: logger(f"Subdomain Expert: Analyzing {len(subdomains)} subdomains for takeover fingerprints...", "INFO")

        for sub in subdomains:
            try:
                # Resolve CNAME
                answers = dns.resolver.resolve(sub, 'CNAME')
                for rdata in answers:
                    cname = str(rdata.target).lower()
                    
                    found_provider = None
                    for fingerprint, provider in self.fingerprints.items():
                        if fingerprint in cname:
                            found_provider = provider
                            break
                    
                    if found_provider:
                        # Now check if it actually resolves to an IP (if not, it's likely a takeover)
                        try:
                            socket.gethostbyname(sub)
                            # If it resolves, it's "claimed" but still worth noting
                            findings.append({
                                "title": f"Subdomain Cloud Mapping: {sub}",
                                "description": f"The subdomain `{sub}` points to `{cname}` ({found_provider}). It currently resolves to an IP, so it is likely claimed, but could be monitored for future expiration.",
                                "severity": "info",
                                "tool_source": "subdomain_expert"
                            })
                        except socket.gaierror:
                            # Does NOT resolve -> HIGH chance of takeover
                            findings.append({
                                "title": f"CRITICAL: Potential Subdomain Takeover ({sub})",
                                "description": f"The subdomain `{sub}` points to `{cname}` ({found_provider}) but does not resolve to an IP address. This often indicates the service was deleted but the DNS record remains, allowing an attacker to claim it.",
                                "severity": "critical",
                                "tool_source": "subdomain_expert"
                            })
                            if logger: logger(f"🔥 TAKEOVER VULN: {sub} -> {cname} (Unclaimed {found_provider}?)", "CRITICAL")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, Exception):
                continue

        return findings
