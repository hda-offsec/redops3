# RedOps3 Remediation Vault
# Provides actionable code blueprints for verified findings.

REMEDIATION_DATABASE = {
    "xss": """### Prevent Reflected XSS
1. **Output Encoding**: Use a context-aware encoding library (e.g., DOMPurify or OWASP Java Encoder).
2. **Content Security Policy (CSP)**: Implement a strict CSP to block inline scripts:
   `Content-Security-Policy: default-src 'self'; script-src 'self';`
3. **HTTPOnly Cookies**: Ensure session cookies cannot be accessed via JavaScript.""",

    "sqli": """### Neutralize SQL Injection
1. **Parameterized Queries**: ALWAYS use prepared statements with bind variables.
   *Example (Python):* `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`
2. **ORM Usage**: Use a secure ORM like SQLAlchemy or Django ORM.
3. **Least Privilege**: Ensure the database user has minimal required permissions.""",

    "lfi": """### Sanitize File Access
1. **Path Validation**: Use a whitelist of allowed files.
2. **Avoid User Input in Paths**: Do not concatenate user input directly into file system calls.
3. **Chroot/Containerization**: Run the application in an isolated environment to limit file system access.""",

    "ssrf": """### Mitigate SSRF
1. **Network Egress Filtering**: Block requests to internal IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254).
2. **URL Whitelisting**: Only allow requests to a predefined list of trusted domains.
3. **Disable Unused Protocols**: Disable `file://`, `gopher://`, `dict://` in the HTTP client.""",

    "jwt": """### Secure JWT Implementation
1. **Strong Signing Key**: Use a cryptographically strong secret or RSA/ECDSA keys.
2. **Algorithm Enforcement**: Explicitly check the `alg` header and do not allow `none`.
3. **Expiring Tokens**: Set a short expiration (`exp`) and implement secure refresh rotations.""",

    "secret": """### Revoke Exposed Secrets
1. **Invalidate Immediately**: Rotate the exposed API key, token, or password.
2. **Environment Variables**: Move secrets from version control to secure environment variables or a Secret Manager (AWS Secrets Manager, HashiCorp Vault).
3. **Scan History**: Purge the secret from Git history using `git-filter-repo` or BFG.""",

    "auth": """### Hardened Authentication
1. **Multi-Factor Auth (MFA)**: Require TOTP or WebAuthn for sensitive accounts.
2. **Rate Limiting**: Implement strict throttling on login endpoints.
3. **Secure Defaults**: Disable guest access and ensure password complexity requirements are met.""",
}

def get_remediation_blueprint(finding):
    """Retrieves a specific remediation blueprint based on finding category or title."""
    title = finding.get("title", "").lower()
    category = finding.get("category", "").lower()
    
    # Priority 1: Direct Category Match
    if category in REMEDIATION_DATABASE:
        return REMEDIATION_DATABASE[category]
    
    # Priority 2: Keyword Search in Title
    for key, blueprint in REMEDIATION_DATABASE.items():
        if key in title:
            return blueprint
            
    # Priority 3: Default General Blueprint
    return "### General Security Hardening\n1. Validate all user-supplied input.\n2. Apply the Principle of Least Privilege.\n3. Keep all system components and dependencies updated."
