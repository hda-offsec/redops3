import requests
import json
import time

class GitHubScanner:
    def __init__(self, target):
        self.target = target
        self.base_url = "https://api.github.com/search/code"
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "RedOps3-ScanEngine"
        }

    def search_leaks(self, logger=None):
        """
        Searches GitHub for mentions of the target domain in code.
        Requires a GitHub token for better rate limits, but works (very limited) without.
        """
        query = f'"{self.target}"'
        if logger: logger(f"OSINT: Searching GitHub for mentions of {self.target}...", "INFO")
        
        leaks = []
        try:
            # Note: GitHub Search API rate limit is very strict (10 req/min for authenticated, less for unauth)
            # We'll do a simple search first.
            params = {
                'q': query,
                'sort': 'indexed',
                'order': 'desc'
            }
            
            response = requests.get(self.base_url, params=params, headers=self.headers, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                items = data.get('items', [])
                for item in items[:10]: # Limit to top 10 for performance/noise
                    leaks.append({
                        "repository": item['repository']['full_name'],
                        "path": item['path'],
                        "url": item['html_url'],
                        "owner": item['repository']['owner']['login']
                    })
                
                if logger:
                    if leaks:
                        logger(f"🚀 GitHub: Found {len(leaks)} potential code leaks/mentions!", "SUCCESS")
                    else:
                        logger(f"GitHub: No immediate code leaks detected.", "INFO")
            elif response.status_code == 403:
                if logger: logger("GitHub API: Rate limit exceeded or forbidden. (Token recommended)", "WARN")
            else:
                if logger: logger(f"GitHub API returned status {response.status_code}", "WARN")
                
        except Exception as e:
            if logger: logger(f"GitHub Search failed: {e}", "ERROR")
            
        return leaks
