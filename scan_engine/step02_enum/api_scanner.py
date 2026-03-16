import os
import json
import logging
import urllib.parse
from scan_engine.helpers.process_manager import ProcessManager
import scan_engine.helpers.http_client as http_client

logger = logging.getLogger(__name__)

class APIScanner:
    def __init__(self, target, options=None):
        self.options = options or {}
        self.target = target

    def check_tools(self):
        return ProcessManager.find_binary_path("ffuf") is not None

    def get_wordlist_path(self, scan_id=None):
        """Returns a stable wordlist path. Uses scan-specific path if scan_id is provided."""
        if scan_id:
            base = os.path.join(os.getcwd(), "data", "results", f"scan_{scan_id}")
            os.makedirs(base, exist_ok=True)
            return os.path.join(base, "api_wordlist.txt")
        return os.path.join(os.getcwd(), "data", "wordlists", "api_endpoints.txt")

    def prepare_wordlist(self, quick=False, scan_id=None):
        wordlist = self.get_wordlist_path(scan_id)
        
        # Comprehensive list of common Swagger/OpenAPI and API endpoints
        endpoints = [
            'swagger-ui.html', 'openapi.json', 'v2/api-docs', 'v3/api-docs',
            'swagger.json', 'api-docs', 'docs', 'swagger-ui/', 'swagger-ui/index.html',
            'api/swagger.json', 'api/swagger-ui.html', 'swagger.yaml', 'swagger.yml',
            'api/swagger.yaml', 'api/swagger.yml', 'swagger-resources',
            'swagger-resources/configuration/ui', 'swagger-resources/configuration/security',
            'api/swagger-resources', 'api/v2/swagger.json', 'api/v3/swagger.json',
            'api/v1/documentation', 'api/v2/documentation', 'api/v3/documentation',
            'api/v1/api-docs', 'api/v2/api-docs', 'api/v3/api-docs',
            'api/swagger', 'api/docs', 'api/swagger-ui', 'api.json', 'api.yaml',
            'api.yml', 'api.html', 'documentation/swagger.json', 'documentation/swagger.yaml',
            'documentation/swagger.yml', 'documentation/swagger-ui.html',
            'documentation/swagger-ui', 'swagger/index.html', 'swagger-ui.html/v2/api-docs',
            'swagger-ui.html/v3/api-docs', 'swagger/v2/api-docs', 'swagger/v3/api-docs',
            'api/swagger/v2/api-docs', 'api/swagger/v3/api-docs', 'classicapi/doc/',
            'api-doc', 'api/package_search/v4/documentation', 'api/2/explore/', 
            'apidoc', 'apidocs', 'application', 'backoffice/v1/ui', 
            'build/reference/web-api/explore', 'core/latest/swagger-ui/index.html', 
            'csp/gateway/slc/api/swagger-ui.html', 'doc', 'internal/docs', 
            'rest/v1', 'rest/v3/doc', 'swagger', 'swaggerui', 'ui', 
            'ui/', 'v1', 'v1.0', 'v1.1', 'v2', 'v2.0', 'v3',
            'v1.x/swagger-ui.html', 'swagger/swagger-ui.html', 'swagger/index.html',
            'api/v1', 'api/v2', 'graphql', 'api/graphiql', 'api/v1/user', 'api/v1/auth', 'api/v1/config',
            'actuator', 'actuator/health', 'actuator/info', 'actuator/env', 'actuator/metrics',
            'api/v1/health', 'api/v2/health', 'health', 'info', 'version', 'status',
            'api/v1/login', 'api/v1/signup', 'api/v1/register', 'api/v1/profile',
            'api/v1/admin', 'api/v1/settings', 'api/v1/debug', 'api/v1/test',
            'api/v1/swagger', 'api/v1/docs', 'api/v1/api-docs',
            'config', 'settings', 'admin', 'manage', 'management', 'private', 'internal',
            'api/private', 'api/internal', 'api/admin', 'api/manage', 'api/management',
            'metrics', 'prometheus', 'robots.txt', 'sitemap.xml', '.env', '.git/config'
        ]
        
        if quick:
            unique_endpoints = [
                'swagger-ui.html', 'openapi.json', 'v2/api-docs', 'v3/api-docs',
                'swagger.json', 'api-docs', 'docs', 'api/v1', 'api/v2', 'graphql',
                'actuator/health', 'health', 'version', '.env'
            ]
        else:
            unique_endpoints = sorted(list(set(endpoints)))
        
        os.makedirs(os.path.dirname(wordlist), exist_ok=True)
        # Check if wordlist exists and content is identical to avoid pointless writes
        write_needed = True
        if os.path.exists(wordlist):
            with open(wordlist, "r") as f:
                existing = [l.strip() for l in f.readlines()]
                if set(existing) == set(unique_endpoints):
                    write_needed = False
        
        if write_needed:
            with open(wordlist, "w") as f:
                for ep in unique_endpoints:
                    f.write(f"{ep}\n")
        return wordlist

    def get_command(self, port, protocol='http', quick=False, scan_id=None):
        url = f"{protocol}://{self.target}:{port}/FUZZ"
        wordlist = self.prepare_wordlist(quick, scan_id)

        return [
            "ffuf", "-s", "-u", url, "-w", wordlist,
            "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "-mc", "200,201,204,301,302,401,403,405",
            "-r",
            "-ac",
            "-t", "40",
            "-timeout", "5",
            "-noninteractive",
            "-json"
        ]

    def verify_finding(self, url):
        """
        Performs strict verification of a discovered endpoint.
        Returns (confirmed, severity, evidence, repro_cmd)
        """
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            resp = http_client.get(url, options=self.options, timeout=10, allow_redirects=True, headers=headers)
            
            # 1. Check for sensitive files (Critical/High)
            filename = url.split('/')[-1].lower()
            if filename == '.env' and resp.status_code == 200:
                if any(x in resp.text for x in ['DB_', 'AWS_', 'SECRET', 'KEY']):
                    return True, "critical", resp.text[:1000], f"curl -i -s -k {url}"
            
            if '.git/config' in url and resp.status_code == 200:
                 if '[core]' in resp.text:
                     return True, "high", resp.text[:500], f"curl -i -s -k {url}"

            # 2. Check for API documentation (Info/Low)
            if any(x in url.lower() for x in ['swagger', 'openapi', 'api-docs']):
                if resp.status_code == 200 and ('swagger' in resp.text.lower() or 'openapi' in resp.text.lower()):
                    return True, "low", f"API Documentation detected. Content-Type: {resp.headers.get('Content-Type')}", f"curl -i -k {url}"

            # 3. Check for Actuator endpoints
            if 'actuator' in url.lower() and resp.status_code == 200:
                if 'application/json' in resp.headers.get('Content-Type', ''):
                    return True, "medium", resp.text[:500], f"curl -i -k {url}"

            # 4. Standard validation (is it real or a catch-all?)
            # If it's a 200 but looks generic, we might skip it or leave as low confidence
            return resp.status_code < 400, "info", f"Response Header: {resp.headers.get('Server', 'Unknown')}", f"curl -I -k {url}"

        except Exception as e:
            logger.debug(f"Verification failed for {url}: {e}")
            return False, "info", None, None

    def stream_api_discovery(self, port, protocol='http', logger=None, quick=False, scan_id=None):
        command = self.get_command(port, protocol, quick=quick, scan_id=scan_id)
        if logger: logger(f"Enrichment: Fuzzing for API Endpoints on port {port}...", "INFO")
        return ProcessManager.stream_command(command)

