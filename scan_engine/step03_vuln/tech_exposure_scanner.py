import scan_engine.helpers.http_client as http_client
from scan_engine.helpers.http_client import get_session

class TechExposureScanner:
    def __init__(self, target, options=None):
        self.options = options
        self.target = target
        self.sensitive_files = [
            '.env', '.env.local', '.env.bak', '.env.old', '.env.save', '.env.example', '.env.prod', '.env.dev',
            'docker-compose.yml', 'Dockerfile', 'web.config', 'phpinfo.php',
            'info.php', 'config.php.bak', 'settings.py.bak', 'wp-config.php.bak',
            '.bash_history', '.ssh/id_rsa', '.ssh/id_dsa', '.aws/credentials',
            '.gitconfig', '.npmrc', '.docker/config.json', 'gc-keys.json', 
            'key.pem', 'cert.pem', 'bundle.tar.gz', 'backup.sql', 'db.sql'
        ]
        # V10: Standard web discovery files — reported as INFO detections
        self.discovery_files = {
            'robots.txt': {
                'validators': ['user-agent', 'disallow', 'allow', 'sitemap', 'crawl-delay'],
                'label': 'Robots.txt',
                'desc': 'Search engine crawling directives. May reveal hidden paths via Disallow entries.'
            },
            'sitemap.xml': {
                'validators': ['<urlset', '<sitemapindex', '<loc>', '<?xml'],
                'label': 'Sitemap XML',
                'desc': 'XML sitemap exposing site structure and all indexed URLs.'
            },
            'sitemap_index.xml': {
                'validators': ['<sitemapindex', '<sitemap>', '<loc>', '<?xml'],
                'label': 'Sitemap Index',
                'desc': 'Sitemap index file listing multiple sitemap files.'
            },
            '.well-known/security.txt': {
                'validators': ['contact:', 'expires:', 'policy:', 'encryption:'],
                'label': 'Security.txt',
                'desc': 'Security contact and vulnerability disclosure policy.'
            },
            'crossdomain.xml': {
                'validators': ['<cross-domain-policy', 'allow-access-from', '<?xml'],
                'label': 'Crossdomain XML',
                'desc': 'Flash/Silverlight cross-domain policy. May allow unauthorized cross-origin access.'
            },
            'clientaccesspolicy.xml': {
                'validators': ['<access-policy', 'allow-from', '<?xml'],
                'label': 'Client Access Policy',
                'desc': 'Silverlight cross-domain policy file.'
            },
            'humans.txt': {
                'validators': ['team', 'developer', 'designer', 'author', 'site', 'technology'],
                'label': 'Humans.txt',
                'desc': 'Human-readable site credits. May reveal team members and technology stack.'
            },
            'ads.txt': {
                'validators': ['direct', 'reseller', 'google.com', 'pub-'],
                'label': 'Ads.txt',
                'desc': 'Authorized digital sellers file for advertising transparency.'
            },
            'wp-sitemap.xml': {
                'validators': ['<sitemapindex', '<sitemap>', 'wp-sitemap', '<?xml'],
                'label': 'WordPress Sitemap',
                'desc': 'WordPress auto-generated sitemap exposing content structure.'
            },
        }

    def audit(self, port, protocol='http', logger=None):
        findings = []
        base_url = f"{protocol}://{self.target}:{port}/"
        
        if logger: logger(f"Advanced: Searching for technical exposure on {base_url}...", "INFO")
        
        # --- Phase 1: Sensitive file exposure (CRITICAL/HIGH) ---
        for file in self.sensitive_files:
            url = base_url + file
            try:
                r = http_client.get(url, options=getattr(self, "options", None), timeout=5, allow_redirects=False, headers={"User-Agent": "Mozilla/5.0"})
                
                if r.status_code == 200:
                    content_len = len(r.content)
                    if content_len > 0 and content_len < 50000:
                        is_likely = True
                        if '.env' in file:
                            if '=' not in r.text or '<html' in r.text.lower():
                                is_likely = False
                        
                        if is_likely:
                            if logger: logger(f"🔥 EXPOSURE FOUND: {url} ({content_len} bytes)", "CRITICAL")
                            from scan_engine.helpers.finding_normalizer import FindingNormalizer
                            findings.append(FindingNormalizer.from_response(
                                r,
                                title=f"Technical File Exposure: {file} ({port})",
                                description=f"A sensitive technical file was found publicly accessible: {url}\nSize: {content_len} bytes.",
                                severity="critical" if any(x in file for x in ['.env', '.ssh', 'aws', 'docker']) else "high",
                                tool_source="tech_audit",
                                category="vuln"
                            ))
            except Exception:
                continue

        # --- Phase 2: Web discovery files (INFO) ---
        for file, meta in self.discovery_files.items():
            url = base_url + file
            try:
                r = http_client.get(url, options=getattr(self, "options", None), timeout=5, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
                
                if r.status_code == 200 and len(r.content) > 10:
                    body_lower = r.text[:5000].lower()
                    
                    # Validate: at least one expected keyword must be present
                    # This prevents custom-404 pages from being reported
                    matched = any(v.lower() in body_lower for v in meta['validators'])
                    
                    # Reject HTML error pages masquerading as the file
                    if '<html' in body_lower and file.endswith('.txt'):
                        matched = False
                    
                    if matched:
                        snippet = r.text[:500].strip()
                        if logger: logger(f"📄 Discovery: {meta['label']} found at {url} ({len(r.content)} bytes)", "SUCCESS")
                        
                        # Extract interesting intel from robots.txt
                        extra_intel = ""
                        if file == 'robots.txt':
                            disallow_lines = [l.strip() for l in r.text.splitlines() 
                                            if l.strip().lower().startswith('disallow:')]
                            if disallow_lines:
                                extra_intel = "\n\n**Disallowed Paths** (potential hidden areas):\n"
                                for dl in disallow_lines[:20]:
                                    extra_intel += f"  {dl}\n"
                        
                        from scan_engine.helpers.finding_normalizer import FindingNormalizer
                        findings.append(FindingNormalizer.from_response(
                            r,
                            title=f"Web Discovery: {meta['label']} ({port})",
                            description=(
                                f"{meta['desc']}\n\n"
                                f"**URL**: {url}\n"
                                f"**Size**: {len(r.content)} bytes\n\n"
                                f"**Content Preview**:\n```\n{snippet}\n```"
                                f"{extra_intel}"
                            ),
                            severity="info",
                            tool_source="tech_audit",
                            category="discovery",
                            method="GET"
                        ))
            except Exception:
                continue
        return findings
