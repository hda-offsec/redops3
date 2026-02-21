import re
import requests

class DependencyScanner:
    """
    V6 EXPERT: Dependency Confusion & Supply Chain Auditor.
    Scans for exposed dependency files and identifies potentially hijackable internal package names.
    """
    def __init__(self, target):
        self.target = target
        self.registry_checks = {
            "npm": "https://registry.npmjs.org/",
            "pypi": "https://pypi.org/pypi/"
        }

    def _is_package_public(self, name, registry_url):
        """Checks if a package exists on a public registry."""
        try:
            r = requests.get(f"{registry_url}{name}", timeout=3)
            return r.status_code == 200
        except Exception:
            return True # Assume public on error to be safe

    def audit_dependencies(self, file_content, file_type, logger=None):
        findings = []
        internal_patterns = [
            r"@[a-z0-9-]+\/[a-z0-9-]+", # Scoped NPM (often internal)
            r"corp-", r"internal-", r"private-", r"dev-", r"local-"
        ]
        
        packages = []
        if file_type == "package.json":
            # Extract names from dependencies and devDependencies
            import json
            try:
                data = json.loads(file_content)
                deps = data.get("dependencies", {})
                deps.update(data.get("devDependencies", {}))
                packages = list(deps.keys())
            except Exception: pass
        elif file_type == "requirements.txt":
            # Extract names from requirements.txt
            lines = file_content.split('\n')
            for line in lines:
                m = re.match(r"^([a-zA-Z0-9_-]+)", line.strip())
                if m: packages.append(m.group(1))

        for pkg in packages:
            is_internal_suspect = any(re.search(pat, pkg) for pat in internal_patterns)
            
            if is_internal_suspect:
                # Check if it's missing from public registry -> Potential Confusion
                reg = "npm" if file_type == "package.json" else "pypi"
                if not self._is_package_public(pkg, self.registry_checks[reg]):
                    findings.append({
                        "title": f"High: Potential Dependency Confusion ({pkg})",
                        "description": (
                            f"The internal-looking package `{pkg}` was found in `{file_type}` but does not appear "
                            f"to exist on the public {reg.upper()} registry.\n\n"
                            "An attacker could register this name on the public registry to hijack the build pipeline."
                        ),
                        "severity": "high",
                        "tool_source": "dependency_expert",
                        "package": pkg
                    })
                    if logger: logger(f"📦 DEPENDENCY CONFUSION TARGET: {pkg}", "WARN")

        return findings

    def scan_path(self, base_url, logger=None):
        findings = []
        files = [
            ("package.json", "package.json"),
            ("requirements.txt", "requirements.txt")
        ]
        
        for filename, ftype in files:
            url = f"{base_url.rstrip('/')}/{filename}"
            try:
                r = requests.get(url, timeout=3, verify=False)
                if r.status_code == 200:
                    findings.extend(self.audit_dependencies(r.text, ftype, logger))
            except Exception: pass
            
        return findings
