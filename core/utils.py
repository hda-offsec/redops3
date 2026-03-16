import re
import os

def sanitize_evidence(text: str) -> str:
    """
    Scrubs sensitive information from evidence (requests/responses).
    Masks Authorization, Cookies, API Keys, and JWT tokens.
    """
    if not text or not isinstance(text, str):
        return text
    
    # 1. Mask Sensitive Headers
    sensitive_headers = [
        'Authorization', 'Cookie', 'Set-Cookie', 'X-Api-Key', 
        'Proxy-Authorization', 'X-CSRF-Token', 'X-Auth-Token',
        'X-Session-ID', 'X-Vcap-Request-Id', 'X-Amz-Security-Token'
    ]
    
    for header in sensitive_headers:
        # Match header case-insensitively and its value
        # Supports both line endings \r\n and \n
        pattern = re.compile(rf'^(\s*{header}:\s*)([^\r\n]+)', re.IGNORECASE | re.MULTILINE)
        text = pattern.sub(r'\1[MASKED]', text)

    # 2. Mask Inline Bearer/JWT patterns
    # Pattern for Bearer [token] or Authorization: Bearer [token]
    text = re.sub(r'(Bearer\s+)[a-zA-Z0-9\-\._~+/]+=*', r'\1[MASKED]', text, flags=re.IGNORECASE)
    
    # Mask JWT-like strings: eyJ... (header) . eyJ... (payload) . ... (signature)
    text = re.sub(r'ey[a-zA-Z0-9\-_]{10,}\.ey[a-zA-Z0-9\-_]{10,}\.[a-zA-Z0-9\-_]{10,}', '[JWT_MASKED]', text)

    # 3. Mask potential session IDs / common keys in JSON bodies
    json_keys = ['access_token', 'refresh_token', 'session_id', 'client_secret', 'api_key', 'password']
    for key in json_keys:
        pattern = re.compile(rf'("{key}"\s*:\s*")([^"]+)"', re.IGNORECASE)
        text = pattern.sub(r'\1[MASKED]"', text)

    return text

def cap_text(text: str, max_bytes: int = None) -> str:
    """
    Truncates text if it exceeds max_bytes.
    Default limit is 64KB unless specified.
    """
    if not text or not isinstance(text, str):
        return text
    
    if max_bytes is None:
        try:
            from flask import current_app
            max_bytes = current_app.config.get('EVIDENCE_MAX_BYTES', 65536)
        except:
            max_bytes = 65536

    if len(text.encode('utf-8', errors='ignore')) > max_bytes:
        # Truncate by character to avoid breaking UTF-8 sequences as much as possible
        # then refine by bytes
        truncated = text[:max_bytes]
        while len(truncated.encode('utf-8', errors='ignore')) > max_bytes:
            truncated = truncated[:-1]
        return truncated + "\n\n[CONTENT TRUNCATED FOR PERFORMANCE]"
    
    return text

def get_setting(key, default=None):
    """Helper to get a global setting from database or environment."""
    try:
        from core.models import GlobalSetting
        setting = GlobalSetting.query.filter_by(key=key).first()
        if setting and setting.value:
            return setting.value
        # Fallback to env
        return os.getenv(key, default)
    except Exception:
        return os.getenv(key, default)
