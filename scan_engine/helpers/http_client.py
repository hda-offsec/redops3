import requests
import urllib3

# Suppress insecure request warnings if global verify is False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_session(options=None):
    """
    Returns a requests.Session configured based on scan options.
    """
    session = requests.Session()
    
    # Default behavior for pentest tools: don't verify TLS if not specified
    verify_tls = True
    if options and isinstance(options, dict):
        verify_tls = options.get("verify_tls", False) # Default to False if in pentest mode
    
    session.verify = verify_tls
    
    # Common RedOps Headers
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 RedOps3-Expert/1.0",
        "X-Scanner": "RedOps3"
    })
    
    return session
