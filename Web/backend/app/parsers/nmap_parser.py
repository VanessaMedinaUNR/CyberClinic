#Cyber clinic - nmap scan result parser
#Extracts hosts, ports, services, and vulnerabilities from nmap output

import xml.etree.ElementTree as ET
import json
import logging
import re
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class NmapParser:
    #parse nmap scan results from xml or json format
    def __init__(self):
        self.findings = []
        self.hosts = []
        self.scan_info = {}
    def parse_file(self, filepath: str) -> Dict[str, Any]:
        #parse nmap output file (xml or json)
        try:
            if filepath.endswith('.xml'):
                return self.parse_xml(filepath)
            elif filepath.endswith('.json'):
                return self.parse_json(filepath)
            else:
                #tries to detect format by reading first line
                with open(filepath, 'r') as f:
                    first_line = f.readline().strip()
                    if first_line.startswith('<?xml') or first_line.startswith('<'):
                        return self.parse_xml(filepath)
                    elif first_line.startswith('{'):
                        return self.parse_json(filepath)
                    else:
                        #fallback to text parsing
                        return self.parse_text(filepath)
        except Exception as e:
            logger.error(f"Failed to parse Nmap file {filepath}: {e}")
            return self._empty_result()
        
    def parse_xml(self, filepath: str) -> Dict[str, Any]:
        #parse nmap xml output
        try:
            #reset findings for each parse
            self.findings = []
            self.hosts = []
            tree = ET.parse(filepath)
            root = tree.getroot()
            #extract scan info
            self.scan_info = {
                'scanner': root.attrib.get('scanner', 'nmap'),
                'version': root.attrib.get('version', 'unknown'),
                'args': root.attrib.get('args', ''),
                'start_time': root.attrib.get('start', ''),
                'scan_type': 'nmap'
            }
            
            #extract hosts
            for host in root.findall('.//host'):
                host_data = self._parse_host(host)
                if host_data:
                    self.hosts.append(host_data)
                    self._extract_findings_from_host(host_data)
            return {
                'scan_info': self.scan_info,
                'hosts': self.hosts,
                'findings': self.findings,
                'total_hosts': len(self.hosts),
                'hosts_up': len([h for h in self.hosts if h['status'] == 'up']),
                'total_open_ports': sum(len(h['ports']) for h in self.hosts),
                'success': True
            }
            
        except Exception as e:
            logger.error(f"XML parsing error: {e}")
            return self._empty_result()
    
    def _parse_host(self, host_element) -> Optional[Dict[str, Any]]:
        #extract host information from xml element
        try:
            #status
            status_elem = host_element.find('status')
            status = status_elem.attrib.get('state', 'unknown') if status_elem is not None else 'unknown'
            if status != 'up':
                return None
            #addresses
            addresses = {}
            for addr in host_element.findall('address'):
                addr_type = addr.attrib.get('addrtype', 'unknown')
                addr_val = addr.attrib.get('addr', '')
                addresses[addr_type] = addr_val
            #hostnames
            hostnames = []
            for hostname in host_element.findall('.//hostname'):
                name = hostname.attrib.get('name', '')
                if name:
                    hostnames.append(name)
            #ports
            ports = []
            for port in host_element.findall('.//port'):
                port_data = self._parse_port(port)
                if port_data:
                    ports.append(port_data)
            #os detection
            os_info = self._parse_os(host_element)
            return {
                'status': status,
                'addresses': addresses,
                'ip': addresses.get('ipv4', addresses.get('ipv6', 'unknown')),
                'hostnames': hostnames,
                'ports': ports,
                'os': os_info,
                'open_ports_count': len([p for p in ports if p['state'] == 'open'])
            }
            
        except Exception as e:
            logger.error(f"Host parsing error: {e}")
            return None
        
    def _parse_port(self, port_element) -> Optional[Dict[str, Any]]:
        #extract port information
        try:
            port_id = port_element.attrib.get('portid', '')
            protocol = port_element.attrib.get('protocol', 'tcp')
            state_elem = port_element.find('state')
            state = state_elem.attrib.get('state', 'unknown') if state_elem is not None else 'unknown'
            service_elem = port_element.find('service')
            service_info = {}
            if service_elem is not None:
                service_info = {
                    'name': service_elem.attrib.get('name', 'unknown'),
                    'product': service_elem.attrib.get('product', ''),
                    'version': service_elem.attrib.get('version', ''),
                    'extrainfo': service_elem.attrib.get('extrainfo', ''),
                    'ostype': service_elem.attrib.get('ostype', ''),
                    'cpe': [cpe.text for cpe in service_elem.findall('cpe')]
                }
            
            #script results (nse)
            scripts = []
            for script in port_element.findall('script'):
                script_id = script.attrib.get('id', '')
                script_output = script.attrib.get('output', '')
                scripts.append({
                    'id': script_id,
                    'output': script_output
                })
            
            return {
                'port': port_id,
                'protocol': protocol,
                'state': state,
                'service': service_info,
                'scripts': scripts
            }
            
        except Exception as e:
            logger.error(f"Port parsing error: {e}")
            return None
    
    def _parse_os(self, host_element) -> Dict[str, Any]:
        #extract os detection info
        os_match = host_element.find('.//osmatch')
        if os_match is not None:
            return {
                'name': os_match.attrib.get('name', 'Unknown'),
                'accuracy': os_match.attrib.get('accuracy', '0'),
                'line': os_match.attrib.get('line', '')
            }
        return {'name': 'Unknown', 'accuracy': '0'}
    
    def _extract_findings_from_host(self, host_data: Dict[str, Any]):
        #extract security findings from host data
        ip = host_data['ip']
        #finding open ports
        open_ports = [p for p in host_data['ports'] if p['state'] == 'open']
        if open_ports:
            self.findings.append({
                'type': 'open_ports',
                'severity': 'info',
                'title': f"Open Ports Detected on {ip}",
                'description': f"Found {len(open_ports)} open port(s) on {ip}",
                'affected_component': ip,
                'details': {
                    'ip': ip,
                    'hostnames': host_data.get('hostnames', []),
                    'ports': [f"{p['port']}/{p['protocol']}" for p in open_ports]
                },
                'recommendation': 'Review all open ports and close unnecessary services. Ensure only required services are exposed.' })
        
        #finding unencrypted services
        for port in open_ports:
            service_name = port['service'].get('name', '').lower()
            port_num = port['port']
            
            if service_name in ['http', 'ftp', 'telnet', 'smtp', 'pop3', 'imap']:
                self.findings.append({
                    'type': 'unencrypted_service',
                    'severity': 'medium',
                    'title': f"Unencrypted {service_name.upper()} Service on {ip}:{port_num}",
                    'description': f"Service {service_name} is running without encryption on port {port_num}",
                    'affected_component': f"{ip}:{port_num}",
                    'details': {
                        'ip': ip,
                        'port': port_num,
                        'service': service_name,
                        'product': port['service'].get('product', 'unknown')
                    },
                    'recommendation': f"Enable encrypted alternatives: {self._get_secure_alternative(service_name)}"
                })
        
        #finding outdated services
        for port in open_ports:
            service_product = port['service'].get('product', '')
            service_version = port['service'].get('version', '')
            if service_version and self._is_outdated_version(service_product, service_version):
                self.findings.append({
                    'type': 'outdated_service',
                    'severity': 'high',
                    'title': f"Outdated Software: {service_product} {service_version}",
                    'description': f"Outdated version detected on {ip}:{port['port']}",
                    'affected_component': f"{ip}:{port['port']}",
                    'details': {
                        'ip': ip,
                        'port': port['port'],
                        'service': port['service'].get('name', ''),
                        'product': service_product,
                        'version': service_version
                    },
                    'recommendation': 'Update to the latest stable version. Check vendor security advisories.'
                })
        
        #finding nse script vulnerabilities
        for port in open_ports:
            for script in port.get('scripts', []):
                if 'vuln' in script['id'] or 'CVE' in script['output']:
                    self.findings.append({
                        'type': 'vulnerability',
                        'severity': 'high',
                        'title': f"Vulnerability Detected: {script['id']}",
                        'description': script['output'][:500],
                        'affected_component': f"{ip}:{port['port']}",
                        'details': {
                            'ip': ip,
                            'port': port['port'],
                            'script': script['id'],
                            'output': script['output']
                        },
                        'recommendation': 'Review script output and apply vendor patches immediately.'
                    })
    
    def _get_secure_alternative(self, service: str) -> str:
        #get secure alternative for common services
        alternatives = {
            'http': 'Use HTTPS (port 443) instead',
            'ftp': 'Use SFTP or FTPS instead',
            'telnet': 'Use SSH (port 22) instead',
            'smtp': 'Use SMTPS (port 465/587 with STARTTLS)',
            'pop3': 'Use POP3S (port 995)',
            'imap': 'Use IMAPS (port 993)'
        }
        return alternatives.get(service, 'Use encrypted version of this protocol')
    
    def _is_outdated_version(self, product: str, version: str) -> bool:
        #checks if service version is outdated 
        #this is a simplified check, in production, use cve database
        outdated_patterns = {
            'apache': ['2.2', '2.3'],
            'nginx': ['1.10', '1.11', '1.12'],
            'openssh': ['5.', '6.', '7.0', '7.1', '7.2'],
            'php': ['5.', '7.0', '7.1', '7.2'],
            'mysql': ['5.0', '5.1', '5.5'],
        }
        
        product_lower = product.lower()
        for key, outdated_versions in outdated_patterns.items():
            if key in product_lower:
                return any(version.startswith(v) for v in outdated_versions)
        
        return False
    
    def parse_json(self, filepath: str) -> Dict[str, Any]:
        #parse nmap json output
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            #convert json to our internal format
            #implementation depends on nmap json output structure
            return self._empty_result() 
        except Exception as e:
            logger.error(f"JSON parsing error: {e}")
            return self._empty_result()
    
    def parse_text(self, filepath: str) -> Dict[str, Any]:
        #parse nmap text output (fallback)
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            #basic text parsing for common patterns
            hosts = self._extract_hosts_from_text(content)
            return {
                'scan_info': {'scan_type': 'nmap', 'format': 'text'},
                'hosts': hosts,
                'findings': [],
                'total_hosts': len(hosts),
                'success': True
            }
            
        except Exception as e:
            logger.error(f"Text parsing error: {e}")
            return self._empty_result()
    
    def _extract_hosts_from_text(self, content: str) -> List[Dict[str, Any]]:
        #extract basic host info from text output
        hosts = []
        #basic regex patterns for ip addresses and open ports
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        
        for ip in re.findall(ip_pattern, content):
            hosts.append({
                'ip': ip,
                'status': 'up',
                'ports': [],
                'addresses': {'ipv4': ip}
            })
        
        return hosts
    
    def _empty_result(self) -> Dict[str, Any]:
        #return empty result structure
        return {
            'scan_info': {'scan_type': 'nmap'},
            'hosts': [],
            'findings': [],
            'total_hosts': 0,
            'hosts_up': 0,
            'total_open_ports': 0,
            'success': False,
            'error': 'Failed to parse scan results'
        }

#done by Manuel