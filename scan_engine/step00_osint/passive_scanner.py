import requests
import os

class OSINTTool:
    def __init__(self):
        self.shodan_key = os.getenv("SHODAN_API_KEY")

    def passive_recon(self, target):
        """
        Gathers passive intelligence about the target without direct interaction.
        For now, this is a placeholder that simulates Shodan/Censys data
        unless a key is provided.
        """
        intelligence = {
            "target": target,
            "shodan": {"status": "No API Key", "data": {}},
            "reputation": "Neutral",
            "historical_data": []
        }

        if self.shodan_key:
            try:
                # Real Shodan API Call
                res = requests.get(f"https://api.shodan.io/shodan/host/{target}?key={self.shodan_key}")
                if res.status_code == 200:
                    data = res.json()
                    intelligence["shodan"]["data"] = {
                        "organization": data.get("org", "N/A"),
                        "isp": data.get("isp", "N/A"),
                        "asn": data.get("asn", "N/A"),
                        "vulnerabilities": data.get("vulns", [])
                    }
                    intelligence["shodan"]["status"] = "Success"
                    intelligence["reputation"] = "Checked (Shodan)"
                else:
                    intelligence["shodan"]["status"] = f"API Error: {res.status_code}"
            except Exception as e:
                intelligence["shodan"]["status"] = f"Network Error: {str(e)}"
        else:
            intelligence["shodan"]["status"] = "No Shodan API Key configured in Environment."
            intelligence["shodan"]["data"] = None
        
        return intelligence
