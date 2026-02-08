import os
from scan_engine.helpers.process_manager import ProcessManager

class APIScanner:
    def __init__(self, target):
        self.target = target

    def check_tools(self):
        return ProcessManager.find_binary_path("ffuf") is not None

    def stream_api_discovery(self, port, protocol='http', logger=None):
        """
        Runs ffuf for API discovery (Swagger, GraphQL, v1, v2, etc.)
        """
        url = f"{protocol}://{self.target}:{port}/FUZZ"
        
        # We'll use a specific small but effective API-focused wordlist
        # If the file doesn't exist, the orchestrator will handle it or we use a fallback
        wordlist = os.path.join(os.getcwd(), "data", "wordlists", "api_endpoints.txt")
        if not os.path.exists(wordlist):
            os.makedirs(os.path.dirname(wordlist), exist_ok=True)
            with open(wordlist, "w") as f:
                f.writelines([
                    "api/v1\n", "api/v2\n", "v1\n", "v2\n", "graphql\n", "swagger\n", 
                    "swagger.json\n", "swagger-ui.html\n", "api-docs\n", "api/docs\n",
                    "v1/api-docs\n", "rest\n", "api/swagger-ui\n", "api/graphiql\n",
                    "api/v1/user\n", "api/v1/auth\n", "api/v1/config\n"
                ])

        command = [
            "ffuf", "-u", url, "-w", wordlist,
            "-mc", "200,201,204,401,403,405", # 401/403/405 often indicate hidden endpoints
            "-sf", # silent
            "-ac" # autocalibrate
        ]
        
        if logger: logger(f"Enrichment: Fuzzing for API Endpoints on port {port}...", "INFO")
        return ProcessManager.stream_command(command)
