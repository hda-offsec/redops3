import xml.etree.ElementTree as ET
import logging

logger = logging.getLogger(__name__)

def parse_nmap_xml(xml_content):
    """
    Parse Nmap XML output and return a structured list of hosts and ports.
    """
    if not xml_content.strip():
        return []
        
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        # Try to fix truncated XML if possible
        if "</nmaprun>" not in xml_content:
            try:
                root = ET.fromstring(xml_content + "</nmaprun>")
            except:
                logger.error(f"Error parsing Nmap XML: {e}")
                return []
        else:
            logger.error(f"Error parsing Nmap XML: {e}")
            return []

    results = []
    for host in root.findall('host'):
        host_data = {
            'ip': '',
            'hostname': '',
            'ports': [],
            'os': 'Unknown'
        }
        
        # Address
        addr = host.find('address')
        if addr is not None:
            host_data['ip'] = addr.get('addr')
            
        # Hostname
        hostnames = host.find('hostnames')
        if hostnames is not None:
            hostname = hostnames.find('hostname')
            if hostname is not None:
                host_data['hostname'] = hostname.get('name')
                
        # OS Detection
        os_elem = host.find('os')
        if os_elem is not None:
            os_match = os_elem.find('osmatch')
            if os_match is not None:
                host_data['os'] = os_match.get('name')
                
        # Ports
        ports_elem = host.find('ports')
        if ports_elem is not None:
            for port in ports_elem.findall('port'):
                port_id = port.get('portid')
                state_elem = port.find('state')
                state = state_elem.get('state') if state_elem is not None else 'unknown'
                
                service_elem = port.find('service')
                service_name = 'unknown'
                version = ''
                if service_elem is not None:
                    service_name = service_elem.get('name')
                    product = service_elem.get('product', '')
                    ver = service_elem.get('version', '')
                    ext = service_elem.get('extrainfo', '')
                    version = f"{product} {ver} {ext}".strip()
                    method = service_elem.get('method', 'table')
                    conf = service_elem.get('conf', '3')
                else:
                    method = 'table'
                    conf = '3'
                
                script_results = []
                for script in port.findall('script'):
                    script_results.append({
                        'id': script.get('id'),
                        'output': script.get('output')
                    })
                    
                host_data['ports'].append({
                    'port': port_id,
                    'state': state,
                    'service': service_name,
                    'version': version,
                    'method': method,
                    'conf': conf,
                    'scripts': script_results
                })
                
        results.append(host_data)
        
    return results
