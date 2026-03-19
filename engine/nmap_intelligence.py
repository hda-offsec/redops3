class NmapIntelligenceEngine:
    RULES = {
        'http': [
            'http-title', 'http-headers', 'http-enum', 'http-waf-detect', 
            'http-waf-fingerprint', 'http-robots.txt', 'http-vhosts', 
            'http-methods', 'http-security-headers', 'http-git'
        ],
        'https': [
            'ssl-cert', 'ssl-enum-ciphers', 'ssl-heartbleed', 'ssl-poodle',
            'http-title', 'http-headers', 'http-enum', 'http-methods'
        ],
        'ssl': ['ssl-cert', 'ssl-enum-ciphers', 'ssl-heartbleed', 'ssl-ccs-injection'],
        'microsoft-ds': [
            'smb-enum-shares', 'smb-os-discovery', 'smb-vuln-ms17-010', 
            'smb-protocols', 'smb-security-mode'
        ],
        'smb': [
            'smb-enum-shares', 'smb-os-discovery', 'smb-vuln-ms17-010', 
            'smb-security-mode'
        ],
        'ftp': ['ftp-anon', 'ftp-bounce', 'ftp-syst', 'ftp-vuln-cve2010-4221'],
        'ssh': ['ssh-auth-methods', 'ssh-hostkey', 'ssh2-enum-algos', 'sshv1'],
        'dns': ['dns-brute', 'dns-recursion', 'dns-cache-snoop', 'dns-zone-transfer'],
        'rdp': ['rdp-enum-encryption', 'rdp-ntlm-info', 'rdp-vuln-ms12-020'],
        'ms-wbt-server': ['rdp-enum-encryption', 'rdp-ntlm-info'],
        'vnc': ['vnc-info', 'realvnc-auth-bypass'],
        'snmp': ['snmp-interfaces', 'snmp-sysdescr', 'snmp-win32-services'],
        'mysql': ['mysql-info', 'mysql-empty-password', 'mysql-databases', 'mysql-vuln-cve2012-2122'],
        'postgresql': ['pgsql-introspection'],
        'redis': ['redis-info', 'redis-type'],
        'mongodb': ['mongodb-databases', 'mongodb-info'],
        'jenkins': ['http-jenkins-info'],
        'couchdb': ['couchdb-databases', 'couchdb-stats'],
        'ajp': ['ajp-auth', 'ajp-methods', 'ajp-headers'],
        'iis': ['http-iis-web-config', 'http-shortname'],
        'oracle': ['oracle-tns-version', 'oracle-sid-brute'],
        'rpc': ['rpcinfo', 'rpc-grind'],
        'telnet': ['telnet-encryption', 'telnet-ntlm-info'],
        'ms-sql-s': ['ms-sql-info', 'ms-sql-config', 'ms-sql-ntlm-info'],
        'memcached': ['memcached-info'],
        'docker': ['docker-version'],
    }

    @staticmethod
    def get_scripts_for_service(service_name):
        if not service_name:
            return []
            
        service_name = service_name.lower()
        scripts = []
        for key, script_list in NmapIntelligenceEngine.RULES.items():
            if key in service_name:
                scripts.extend(script_list)
        return list(set(scripts))
