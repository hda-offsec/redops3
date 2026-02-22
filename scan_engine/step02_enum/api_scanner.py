import os
from scan_engine.helpers.process_manager import ProcessManager

class APIScanner:
    def __init__(self, target, options=None):
        self.options = options
        self.target = target

    def check_tools(self):
        return ProcessManager.find_binary_path("ffuf") is not None

    def get_command(self, port, protocol='http', quick=False):
        url = f"{protocol}://{self.target}:{port}/FUZZ"
        wordlist = os.path.join(os.getcwd(), "data", "wordlists", "api_endpoints.txt")
        
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
            # Additional common API paths
            'actuator', 'actuator/health', 'actuator/info', 'actuator/env', 'actuator/metrics',
            'api/v1/health', 'api/v2/health', 'health', 'info', 'version', 'status',
            'api/v1/login', 'api/v1/signup', 'api/v1/register', 'api/v1/profile',
            'api/v1/admin', 'api/v1/settings', 'api/v1/debug', 'api/v1/test',
            'api/v1/swagger', 'api/v1/docs', 'api/v1/api-docs',
            'api/v2/login', 'api/v2/signup', 'api/v2/register', 'api/v2/profile',
            'api/v2/admin', 'api/v2/settings', 'api/v2/debug', 'api/v2/test',
            'api/v2/swagger', 'api/v2/docs', 'api/v2/api-docs',
            'config', 'settings', 'admin', 'manage', 'management', 'private', 'internal',
            'api/private', 'api/internal', 'api/admin', 'api/manage', 'api/management',
            'metrics', 'prometheus', 'robots.txt', 'sitemap.xml', '.env', '.git/config'
        ]
        
        if quick:
            # Top-tier most common API endpoints for quick discovery
            unique_endpoints = [
                'swagger-ui.html', 'openapi.json', 'v2/api-docs', 'v3/api-docs',
                'swagger.json', 'api-docs', 'docs', 'api/v1', 'api/v2', 'graphql',
                'actuator/health', 'health', 'version', '.env'
            ]
        else:
            # Deduplicate and sort for consistency
            unique_endpoints = sorted(list(set(endpoints)))
        
        # Always ensure wordlist is up-to-date with our enriched list
        os.makedirs(os.path.dirname(wordlist), exist_ok=True)
        with open(wordlist, "w") as f:
            for ep in unique_endpoints:
                f.write(f"{ep}\n")

        return [
            "ffuf", "-s", "-u", url, "-w", wordlist,
            "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "-mc", "200,201,204,301,302,401,403,405",
            "-r",
            "-ac",
            "-t", "40",
            "-timeout", "5",
            "-noninteractive",
            "-json" # Use JSON for robust parsing
        ]

    def stream_api_discovery(self, port, protocol='http', logger=None, quick=False):
        command = self.get_command(port, protocol, quick=quick)
        if logger: logger(f"Enrichment: Fuzzing for API Endpoints on port {port} (Mode: {'Quick' if quick else 'Full'})...", "INFO")
        return ProcessManager.stream_command(command)
