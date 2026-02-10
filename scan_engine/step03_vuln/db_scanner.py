import socket
import subprocess
from scan_engine.helpers.process_manager import ProcessManager

class DBScanner:
    def __init__(self, target):
        self.target = target

    def audit_redis(self, port=6379, logger=None):
        """Checks for unauthenticated Redis access."""
        findings = []
        try:
            if logger: logger(f"DB Audit: Testing Redis anonymous access on {self.target}:{port}", "INFO")
            s = socket.socket(socket.getaddrinfo(self.target, port)[0][0], socket.socket().type)
            s.settimeout(5)
            s.connect((self.target, port))
            s.send(b"INFO\r\n")
            response = s.recv(1024).decode('utf-8', errors='ignore')
            s.close()

            if "redis_version" in response:
                findings.append({
                    "title": "Critical: Unauthenticated Redis Access",
                    "description": f"The Redis server at {self.target}:{port} is accessible without authentication. This allows full control over the database and potentially remote code execution.\n\nServer Info Snippet:\n{response[:200]}...",
                    "severity": "critical",
                    "tool_source": "db_audit",
                    "raw_loot": f"redis://{self.target}:{port} (Unauthenticated)",
                    "loot_type": "Database Credential"
                })
                if logger: logger(f"🔥 REDIS EXPLOITABLE: Unauthenticated access on {self.target}:{port}", "CRITICAL")
        except Exception as e:
            if logger: logger(f"Redis test failed: {e}", "DEBUG")
        return findings

    def audit_mongodb(self, port=27017, logger=None):
        """Checks for unauthenticated MongoDB access."""
        findings = []
        try:
            if logger: logger(f"DB Audit: Testing MongoDB anonymous access on {self.target}:{port}", "INFO")
            # We can use a simple socket check for the greeting
            s = socket.socket(socket.getaddrinfo(self.target, port)[0][0], socket.socket().type)
            s.settimeout(5)
            s.connect((self.target, port))
            # Sending a basic isMaster command in wire protocol is complex, 
            # but unauthenticated Mongo usually allows listing dbs via nmap scripts or mongo shell.
            # Let's try a simple probe or use Nmap NSE if available.
            s.close()
            
            # Use nmap NSE for more reliable mongo check if possible
            cmd = ["nmap", "-p", str(port), "--script", "mongodb-databases,mongodb-info", self.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if "Total size" in result.stdout or "databases" in result.stdout.lower():
                findings.append({
                    "title": "Critical: Unauthenticated MongoDB Access",
                    "description": f"The MongoDB server at {self.target}:{port} allows listing databases without authentication. This is a severe data exposure risk.\n\nNmap Output:\n{result.stdout}",
                    "severity": "critical",
                    "tool_source": "db_audit",
                    "raw_loot": f"mongodb://{self.target}:{port} (Unauthenticated)",
                    "loot_type": "Database Credential"
                })
                if logger: logger(f"🔥 MONGODB EXPLOITABLE: Unauthenticated access on {self.target}:{port}", "CRITICAL")
        except Exception:
            pass
        return findings

    def audit_mysql_postgres(self, port, service_name, logger=None):
        """Common checks for MySQL/Postgres using Nmap scripts."""
        findings = []
        try:
            if logger: logger(f"DB Audit: Auditing {service_name} on {self.target}:{port}...", "INFO")
            
            scripts = "mysql-empty-password,mysql-auth-bypass,mysql-enum" if "mysql" in service_name.lower() else "pgsql-*-brute"
            if "mysql" in service_name.lower():
                scripts = "mysql-empty-password,mysql-info"
            else:
                scripts = "pgsql-brute" # Minimal for now to avoid long scans

            cmd = ["nmap", "-sV", "-p", str(port), "--script", scripts, self.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if "root has empty password" in result.stdout or "Authentication success" in result.stdout:
                findings.append({
                    "title": f"Critical: {service_name.upper()} Unauthenticated/Weak Access",
                    "description": f"A weak or missing password was detected on the {service_name} service at {self.target}:{port}.\n\nNmap Result:\n{result.stdout}",
                    "severity": "critical",
                    "tool_source": "db_audit",
                    "raw_loot": f"Service: {service_name}, Access: Unauthenticated/Weak",
                    "loot_type": "Database Credential"
                })
                if logger: logger(f"🔥 {service_name.upper()} EXPLOITABLE: Weak/No password on {self.target}:{port}", "CRITICAL")
            elif "mysql-info" in result.stdout or "pgsql" in result.stdout:
                # Information disclosure
                 findings.append({
                    "title": f"DB Info Disclosure: {service_name.upper()}",
                    "description": f"Service information extracted for {service_name} at {self.target}:{port}.\n\nNmap Result:\n{result.stdout}",
                    "severity": "info",
                    "tool_source": "db_audit"
                })
        except Exception:
            pass
        return findings

    def run_all(self, open_ports, logger=None):
        """Dispatches audits based on open ports."""
        all_findings = []
        for port_info in open_ports:
            port = int(port_info['port'])
            service = (port_info.get('service') or port_info.get('service_name') or '').lower()
            
            if port == 6379 or "redis" in service:
                all_findings.extend(self.audit_redis(port, logger))
            elif port == 27017 or "mongodb" in service:
                all_findings.extend(self.audit_mongodb(port, logger))
            elif port == 3306 or "mysql" in service:
                all_findings.extend(self.audit_mysql_postgres(port, "mysql", logger))
            elif port == 5432 or "postgresql" in service:
                all_findings.extend(self.audit_mysql_postgres(port, "postgresql", logger))
            elif port == 1433 or "ms-sql" in service:
                 all_findings.extend(self.audit_mysql_postgres(port, "mssql", logger))

        return all_findings
