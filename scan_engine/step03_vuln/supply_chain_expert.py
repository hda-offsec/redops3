import re
import json
import scan_engine.helpers.http_client as http_client

class SupplyChainExpert:
    """
    Scans for exposed dependency files (package.json, composer.json, etc.)
    and identifies potential supply chain risks.
    """
    
    DEPENDENCY_FILES = {
        "package.json": "npm/nodejs",
        "package-lock.json": "npm/nodejs",
        "composer.json": "php/composer",
        "composer.lock": "php/composer",
        "requirements.txt": "python/pip",
        "Gemfile": "ruby/bundler",
        "Gemfile.lock": "ruby/bundler",
        "go.mod": "go",
        "go.sum": "go",
        "pom.xml": "java/maven",
        "build.gradle": "java/gradle"
    }

    def __init__(self, target, options=None):
        self.target = target
        self.options = options or {}

    def scan(self, port, protocol='http', logger=None):
        findings = []
        base_url = f"{protocol}://{self.target}:{port}"
        if logger: logger(f"Supply Chain Expert: Checking {base_url} for exposed dependency manifests...", "INFO")

        for filename, tech in self.DEPENDENCY_FILES.items():
            url = f"{base_url}/{filename}"
            try:
                r = http_client.get(url, timeout=5, allow_redirects=False)
                if r.status_code == 200 and len(r.text) > 10:
                    content = r.text
                    
                    # V12: Validation check to avoid generic 200 error pages
                    is_valid = False
                    if filename.endswith(".json"):
                        try:
                            data = json.loads(content)
                            if any(k in data for k in ["dependencies", "devDependencies", "require", "name"]):
                                is_valid = True
                        except: pass
                    elif filename == "build.gradle":
                        if any(x in content for x in ["plugins {", "dependencies {", "repositories {", "implementation '"]):
                            is_valid = True
                    elif filename in ["requirements.txt", "Gemfile", "go.mod"]:
                        # Simple non-empty check for these, but could be improved
                        if len(content.splitlines()) > 2:
                            is_valid = True
                    
                    if not is_valid:
                        continue

                    # Potential leak discovered
                    version_info = self._parse_manifest(filename, content)
                    
                    finding = {
                        "title": f"Supply Chain: Exposed {filename} ({tech})",
                        "description": f"The dependency manifest file `{filename}` is publicly accessible at {url}.\nThis leaks internal stack information and specific dependency versions, enabling targeted supply chain attacks.",
                        "severity": "medium",
                        "tool_source": "supply_chain_expert",
                        "endpoint": url,
                        "repro_command": f"curl -ik {url}",
                        "metadata": {
                            "tech": tech,
                            "manifest_file": filename,
                            "dependencies_count": len(version_info) if version_info else 0
                        }
                    }
                    
                    # If we found known vulnerable patterns (mock correlation for now)
                    if "old" in content.lower() or "deprecated" in content.lower():
                        finding["severity"] = "high"
                        finding["description"] += "\n\n**Warning**: Potential legacy or deprecated dependencies detected in manifest."

                    findings.append(finding)
                    if logger: logger(f"🔥 Supply Chain Expert: Found exposed {filename} on {port}", "WARN")
            except Exception:
                pass

        return findings

    def _parse_manifest(self, filename, content):
        """Simplistic parsing for metrics."""
        try:
            if filename.endswith(".json"):
                data = json.loads(content)
                deps = data.get("dependencies", {})
                deps.update(data.get("devDependencies", {}))
                deps.update(data.get("require", {}))
                return deps
            else:
                # Regex for key=value or key: value
                return re.findall(r'^([^#\s:=]+)\s*[:=]\s*([^\s#]+)', content, re.M)
        except:
            return {}
