import re
import json
from urllib.parse import urljoin
from scan_engine.helpers.http_client import get_session

class DependencyConfusionScanner:
    """
    Scans for Supply Chain / Dependency Confusion vulnerabilities.
    Looks for internal-looking packages that don't exist in public registries.
    """
    def __init__(self, options=None):
        self.options = options
        self.session = get_session(self.options)
        self.session.headers.update({"User-Agent": "RedOps3-DependencyExpert/1.0"})
        
        # Files to target
        self.files = ["package.json", "requirements.txt", "pom.xml", "composer.json"]

    def scan(self, base_url, logger=None):
        findings = []
        if logger: logger(f"📦 Dependency Expert: Auditing supply chain on {base_url}...", "INFO")

        for f in self.files:
            target_url = urljoin(base_url, f)
            try:
                r = self.session.get(target_url, timeout=5, verify=False)
                if r.status_code == 200:
                    if f == "package.json":
                        findings.extend(self._audit_package_json(r.text, target_url, logger))
                    elif f == "requirements.txt":
                        findings.extend(self._audit_requirements_txt(r.text, target_url, logger))
            except: pass
        
        return findings

    def _audit_package_json(self, content, url, logger):
        findings = []
        try:
            data = json.loads(content)
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            
            for pkg in deps:
                # Heuristic: Scoped packages or packages containing company-like names
                if pkg.startswith("@") or "-" in pkg:
                    # check if it exists on npm
                    if not self._check_npm_exists(pkg):
                        findings.append({
                            "title": "High: Dependency Confusion Candidate",
                            "description": f"The package `{pkg}` was found in `{url}` but does not appear to exist on the public npm registry. It may be an internal package vulnerable to Dependency Confusion.",
                            "severity": "high",
                            "confidence": "medium",
                            "tool_source": "dependency_expert",
                            "url": url,
                            "metadata": {"package": pkg, "registry": "npm"}
                        })
                        if logger: logger(f"⚠️ Potential Dependency Confusion: {pkg}", "WARN")
        except: pass
        return findings

    def _audit_requirements_txt(self, content, url, logger):
        findings = []
        lines = content.splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"): continue
            # Extract package name (simple regex)
            match = re.match(r'^([a-zA-Z0-9._-]+)', line)
            if match:
                pkg = match.group(1)
                if "-" in pkg or "." in pkg:
                    if not self._check_pypi_exists(pkg):
                         findings.append({
                            "title": "High: Dependency Confusion Candidate (PyPI)",
                            "description": f"The Python package `{pkg}` found in `{url}` does not exist on PyPI. An attacker could potentially claim this name to inject malicious code.",
                            "severity": "high",
                            "tool_source": "dependency_expert",
                            "url": url,
                            "metadata": {"package": pkg, "registry": "pypi"}
                        })
        return findings

    def _check_npm_exists(self, pkg):
        """Checks if a package exists on npmjs.com"""
        try:
            r = self.session.get(f"https://registry.npmjs.org/{pkg}", timeout=3)
            return r.status_code == 200
        except: return True # Assume exists on error to be safe

    def _check_pypi_exists(self, pkg):
        """Checks if a package exists on pypi.org"""
        try:
            r = self.session.get(f"https://pypi.org/pypi/{pkg}/json", timeout=3)
            return r.status_code == 200
        except: return True
