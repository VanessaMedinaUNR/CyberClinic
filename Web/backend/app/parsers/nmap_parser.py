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
            if filepath.endswith('.json'):
                return self.parse_json(filepath)

            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                first_line = f.readline().strip()
                if first_line.startswith('<?xml') or first_line.startswith('<'):
                    return self.parse_xml(filepath)
                if first_line.startswith('{'):
                    return self.parse_json(filepath)

            return self.parse_text(filepath)
        except Exception as e:
            logger.error(f"Failed to parse Nmap file {filepath}: {e}")
            return self._empty_result()

    def parse_xml(self, filepath: str) -> Dict[str, Any]:
        #parse nmap xml output
        try:
            self.findings = []
            self.hosts = []
            tree = ET.parse(filepath)
            root = tree.getroot()

            self.scan_info = {
                'scanner': root.attrib.get('scanner', 'nmap'),
                'version': root.attrib.get('version', 'unknown'),
                'args': root.attrib.get('args', ''),
                'start_time': root.attrib.get('start', ''),
                'scan_type': 'nmap'
            }

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

    def parse_json(self, filepath: str) -> Dict[str, Any]:
        #parse nmap json output
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)

            self.scan_info = data.get('scan_info', {})
            self.hosts = data.get('hosts', [])
            self.findings = data.get('findings', [])

            return {
                'scan_info': self.scan_info,
                'hosts': self.hosts,
                'findings': self.findings,
                'total_hosts': len(self.hosts),
                'hosts_up': len([h for h in self.hosts if h['status'] == 'up']),
                'total_open_ports': sum(len(h.get('ports', [])) for h in self.hosts),
                'success': True
            }
        except Exception as e:
            logger.error(f"JSON parsing error: {e}")
            return self._empty_result()

    def parse_text(self, filepath: str) -> Dict[str, Any]:
        #parse nmap plain text output
        try:
            self.findings = []
            self.hosts = []

            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            self.scan_info = {
                'scanner': 'nmap',
                'version': 'unknown',
                'args': '',
                'start_time': '',
                'scan_type': 'nmap'
            }

            self.findings.append({
                'type': 'info',
                'severity': 'info',
                'title': 'Nmap Raw Output',
                'description': 'Nmap output was stored as text. Parsing is limited.',
                'affected_component': 'scan',
                'details': {'raw_output': content[:2000]},
                'recommendation': 'Review raw output for details.'
            })

            return {
                'scan_info': self.scan_info,
                'hosts': [],
                'findings': self.findings,
                'total_hosts': 0,
                'hosts_up': 0,
                'total_open_ports': 0,
                'success': True
            }
        except Exception as e:
            logger.error(f"Text parsing error: {e}")
            return self._empty_result()

    def _parse_host(self, host_element) -> Optional[Dict[str, Any]]:
        #extract host information from xml element
        try:
            status_elem = host_element.find('status')
            status = status_elem.attrib.get('state', 'unknown') if status_elem is not None else 'unknown'
            if status != 'up':
                return None

            addresses = {}
            for addr in host_element.findall('address'):
                addr_type = addr.attrib.get('addrtype', 'unknown')
                addr_val = addr.attrib.get('addr', '')
                addresses[addr_type] = addr_val

            hostnames = []
            for hostname in host_element.findall('.//hostname'):
                name = hostname.attrib.get('name', '')
                if name:
                    hostnames.append(name)

            ports = []
            for port in host_element.findall('.//port'):
                port_data = self._parse_port(port)
                if port_data:
                    ports.append(port_data)

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
                'references': [],
                'source': 'nmap',
                'recommendation': 'Review all open ports and close unnecessary services. Ensure only required services are exposed.'
            })

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
                    'references': [],
                    'source': 'nmap',
                    'recommendation': f"Enable encrypted alternatives: {self._get_secure_alternative(service_name)}"
                })

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
                    'references': [],
                    'source': 'nmap',
                    'recommendation': 'Update to the latest stable version. Check vendor security advisories.'
                })

        for port in open_ports:
            for script in port.get('scripts', []):
                findings = self._extract_findings_from_script(ip, port, script)
                if findings:
                    self.findings.extend(findings)

    def _extract_findings_from_script(self, ip: str, port: Dict[str, Any], script: Dict[str, Any]) -> List[Dict[str, Any]]:
        #extract findings from Nmap script output (vulners, ssl, http-* scripts)
        script_id = script.get('id', '').lower()
        output = script.get('output', '') or ''
        findings: List[Dict[str, Any]] = []

        if not output:
            return findings

        if 'vulners' in script_id:
            findings.extend(self._extract_vulners_findings(ip, port, output))
            return findings

        if 'vulnerable' in output.lower() or 'cve-' in output.lower():
            findings.append(self._build_script_finding(
                ip,
                port,
                script,
                finding_type='vulnerability',
                severity='high'
            ))
            return findings

        if script_id.startswith('ssl') or script_id.startswith('tls') or 'ssl' in script_id:
            if 'vulnerable' in output.lower() or 'weak' in output.lower():
                findings.append(self._build_script_finding(
                    ip,
                    port,
                    script,
                    finding_type='tls_issue',
                    severity='medium'
                ))
                return findings

        if script_id == 'http-methods' and 'potentially risky methods' in output.lower():
            findings.append(self._build_script_finding(
                ip,
                port,
                script,
                finding_type='http_methods',
                severity='medium'
            ))

        if script_id == 'http-enum' and '/' in output:
            findings.append(self._build_script_finding(
                ip,
                port,
                script,
                finding_type='content_discovery',
                severity='low'
            ))

        return findings

    def _extract_vulners_findings(self, ip: str, port: Dict[str, Any], output: str) -> List[Dict[str, Any]]:
        #extract CVE and exploit data from vulners script output
        findings: List[Dict[str, Any]] = []
        cve_pattern = re.compile(r'(CVE-\d{4}-\d+)\s+([0-9.]+)\s+(https?://\S+)')
        generic_pattern = re.compile(r'(\S+)\s+([0-9.]+)\s+(https?://\S+)')

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = cve_pattern.search(line) or generic_pattern.search(line)
            if not match:
                continue

            vuln_id = match.group(1)
            score = self._safe_float(match.group(2))
            reference = match.group(3)

            findings.append({
                'type': 'vulnerability',
                'severity': 'info',
                'title': f"{vuln_id} on {ip}:{port['port']}",
                'description': f"{vuln_id} reported by Nmap vulners script.",
                'affected_component': f"{ip}:{port['port']}",
                'details': {
                    'script_id': 'vulners',
                    'reference': reference,
                    'raw_line': line
                },
                'references': [reference],
                'cves': [vuln_id] if vuln_id.startswith('CVE-') else [],
                'cvss_score': score,
                'source': 'nmap'
            })

        return findings

    def _build_script_finding(self, ip: str, port: Dict[str, Any], script: Dict[str, Any],
                              finding_type: str, severity: str) -> Dict[str, Any]:
        output = script.get('output', '') or ''
        references = self._extract_references(output)
        cves = re.findall(r'(CVE-\d{4}-\d+)', output, flags=re.IGNORECASE)

        return {
            'type': finding_type,
            'severity': severity,
            'title': f"{script.get('id', 'script')} finding on {ip}:{port['port']}",
            'description': output[:600],
            'affected_component': f"{ip}:{port['port']}",
            'details': {
                'script_id': script.get('id', ''),
                'output': output
            },
            'references': references,
            'cves': list({cve.upper() for cve in cves}),
            'source': 'nmap'
        }

    def _extract_references(self, text: str) -> List[str]:
        if not text:
            return []
        return list({match.group(0) for match in re.finditer(r'https?://\S+', text)})

    def _safe_float(self, value: str) -> Optional[float]:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _get_secure_alternative(self, service_name: str) -> str:
        secure_map = {
            'http': 'HTTPS',
            'ftp': 'SFTP/FTPS',
            'telnet': 'SSH',
            'smtp': 'SMTPS/STARTTLS',
            'pop3': 'POP3S/STARTTLS',
            'imap': 'IMAPS/STARTTLS'
        }
        return secure_map.get(service_name, 'encrypted protocols')

    def _is_outdated_version(self, product: str, version: str) -> bool:
        #basic heuristic for outdated software
        if not product or not version:
            return False
        if re.match(r'^\d+\.\d+\.\d+$', version):
            major = int(version.split('.')[0])
            return major < 2
        return False

    def _empty_result(self) -> Dict[str, Any]:
        return {
            'scan_info': {},
            'hosts': [],
            'findings': [],
            'total_hosts': 0,
            'hosts_up': 0,
            'total_open_ports': 0,
            'success': False
        }

# Done by Manuel Morales-Marroquin
