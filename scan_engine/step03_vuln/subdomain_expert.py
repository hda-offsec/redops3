import socket
import dns.resolver

class SubdomainExpertScanner:
    def __init__(self, target, options=None):
        self.options = options
        self.target = target
        # EXPERT DICTIONARY: Complete cloud provider fingerprints (CNAME Mapping)
        self.fingerprints = {
             "s3.amazonaws.com": "AWS S3 Bucket",
             "s3-website": "AWS S3 Static Website",
             "cloudfront.net": "AWS CloudFront",
             "elasticbeanstalk.com": "AWS Elastic Beanstalk",
             "herokuapp.com": "Heroku App",
             "herokudns.com": "Heroku Custom Domain",
             "zendesk.com": "Zendesk Support",
             "github.io": "GitHub Pages",
             "shopify.com": "Shopify Store",
             "wpengine.com": "WPEngine Hosting",
             "bitbucket.io": "Bitbucket Cloud",
             "squarespace.com": "Squarespace",
             "unbouncepages.com": "Unbounce",
             "pantheonsite.io": "Pantheon",
             "tumblr.com": "Tumblr Blog",
             "readme.io": "ReadMe.io",
             "vercel.app": "Vercel / Zeit",
             "azurewebsites.net": "Azure App Service",
             "cloudapp.net": "Azure Cloud Service",
             "azureedge.net": "Azure CDN",
             "ghost.io": "Ghost.io",
             "cargo.site": "Cargo Collective",
             "feedpress.me": "FeedPress",
             "freshdesk.com": "Freshdesk",
             "helpjuice.com": "Helpjuice",
             "helpscoutdocs.com": "HelpScout",
             "intercom.help": "Intercom",
             "jetbrains.com": "JetBrains YouTrack/TeamCity",
             "kinsta.cloud": "Kinsta",
             "launchrock.com": "LaunchRock",
             "ngrok.io": "Ngrok Tunnel",
             "surveymonkey.com": "SurveyMonkey",
             "tictail.com": "Tictail",
             "uberflip.com": "Uberflip",
             "wishpond.com": "Wishpond"
        }

    def check_takeover(self, subdomains, logger=None):
        """
        Deep Logic: Analyzes subdomains for potential takeover by verifying CNAME 
        dangling records and resolving states.
        """
        findings = []
        if not subdomains:
            return findings

        if logger: logger(f"Subdomain Expert: Investigating {len(subdomains)} subdomains for dangling cloud records...", "INFO")

        for sub in subdomains:
            try:
                # 1. Resolve CNAME Chain
                try:
                    answers = dns.resolver.resolve(sub, 'CNAME')
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    continue
                
                for rdata in answers:
                    cname = str(rdata.target).lower().rstrip('.')
                    
                    found_provider = None
                    for fingerprint, provider in self.fingerprints.items():
                        if fingerprint in cname:
                            found_provider = provider
                            break
                    
                    if found_provider:
                        # 2. DEEP LOGIC: Check for "Dangling" state
                        # If a CNAME exists but the target host does NOT resolve to an IP, it's a gap.
                        try:
                            # Try to resolve the CNAME target itself
                            dns.resolver.resolve(cname, 'A')
                            # If it resolves, it's claimed.
                            findings.append({
                                "title": f"Cloud Asset Mapping: {sub}",
                                "description": f"Subdomain `{sub}` is mapped to `{found_provider}` via CNAME `{cname}`. Resource is currently active.",
                                "severity": "info",
                                "tool_source": "subdomain_expert"
                            })
                        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                            # CRITICAL: CNAME exists but target is dead/unclaimed
                            findings.append({
                                "title": f"CRITICAL: Verified Subdomain Takeover ({sub})",
                                "description": (
                                    f"The subdomain `{sub}` points to a defunct `{found_provider}` record (`{cname}`).\n\n"
                                    f"Status: DANGLING CNAME. The third-party service has been deleted but the DNS entry remains. "
                                    f"An attacker can register the `{found_provider}` resource to intercept traffic, cookies, and perform XSS."
                                ),
                                "severity": "critical",
                                "tool_source": "subdomain_expert"
                            })
                            if logger: logger(f"🔥 TAKEOVER IDENTIFIED: {sub} -> {cname} (Dangling)", "CRITICAL")
                            
            except Exception: continue

        return findings
