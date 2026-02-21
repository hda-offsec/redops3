import requests
import urllib3
import logging
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- Constants & Configuration ---
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_READ_TIMEOUT = 15.0
DEFAULT_TIMEOUT = (DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT)

# Simple RedOps UA
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 RedOps3-Expert/1.0"

# --- Suppress Warnings Utility ---
# We ONLY suppress if explicitly requested or via global verify=False
_warnings_disabled = False

def _ensure_warnings_suppressed(verify):
    global _warnings_disabled
    if not verify and not _warnings_disabled:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        _warnings_disabled = True

def get_session(options=None) -> requests.Session:
    """
    Returns a hardened requests.Session configured with:
    - Custom Retries (Backoff, Force-list 429/5xx)
    - Default Headers (UA, X-Scanner)
    - Proxy configuration (if provided in options)
    - Global TLS Verification (off by default)
    
    Options support:
    - verify_tls (bool): Default False
    - proxy (str): Proxy URL
    - max_retries (int): Default 2
    """
    options = options or {}
    session = requests.Session()
    
    # 1. TLS Verification
    verify = options.get("verify_tls", False)
    session.verify = verify
    _ensure_warnings_suppressed(verify)
    
    # 2. Retries Configuration (Conservateur)
    max_retries = options.get("max_retries", 2)
    retry_strategy = Retry(
        total=max_retries,
        backoff_factor=0.4,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD", "OPTIONS"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # 3. Proxies
    proxy = options.get("proxy") or options.get("proxies")
    if proxy:
        if isinstance(proxy, str):
            session.proxies = {"http": proxy, "https": proxy}
        else:
            session.proxies = proxy
            
    # 4. Headers
    session.headers.update({
        "User-Agent": DEFAULT_UA,
        "X-Scanner": "RedOps3"
    })
    
    return session

def request(method, url, options=None, **kwargs) -> requests.Response:
    """
    One-shot request wrapper identifying as RedOps3.
    Imposes a mandatory timeout.
    
    Args:
        method (str): HTTP Method (GET, POST, etc.)
        url (str): Target URL
        options (dict): Scan options (contains timeout, verify_tls, etc.)
        **kwargs: Standard requests kwargs
        
    Returns:
        requests.Response
    """
    options = options or {}
    
    # Timeout logic: options wins, then kwargs, then default
    timeout = options.get("timeout")
    if not timeout:
        # Check for specific connect/read timeouts in options
        c_timeout = options.get("connect_timeout", DEFAULT_CONNECT_TIMEOUT)
        r_timeout = options.get("read_timeout", DEFAULT_READ_TIMEOUT)
        timeout = (c_timeout, r_timeout)
    
    # Force timeout in kwargs
    kwargs["timeout"] = timeout
    
    # verify_tls logic
    if "verify" not in kwargs:
        verify = options.get("verify_tls", False)
        kwargs["verify"] = verify
        _ensure_warnings_suppressed(verify)
        
    # Use a temporary session to benefit from retry logic if needed, 
    # or just use requests directly if no special session needed.
    # For consistency, we use get_session().
    with get_session(options) as session:
        return session.request(method, url, **kwargs)

# Alias for common methods
def get(url, options=None, **kwargs): return request("GET", url, options, **kwargs)
def post(url, options=None, **kwargs): return request("POST", url, options, **kwargs)
def head(url, options=None, **kwargs): return request("HEAD", url, options, **kwargs)
def options(url, options=None, **kwargs): return request("OPTIONS", url, options, **kwargs)
