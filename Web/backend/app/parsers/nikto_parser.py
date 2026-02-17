#Cyber clinic - nikto scan result parser
#Extracts web vulnerabilities from nikto output

import json
import re
import logging
from typing import Dict, List, Any
import csv
import io

logger = logging.getLogger(__name__)

class NiktoParser:
    #parse nikto web vulnerability scan results
    def __init__(self):
        self.findings = []
        self.scan_info = {}

    def parse_file(self, filepath: str) -> Dict[str, Any]:
        #parse Nikto output file (JSON, CSV, or text)
        try:
            if filepath.endswith('.json'):
                return self.parse_json(filepath)
            if filepath.endswith('.csv'):
                return self.parse_csv(filepath)
            return self.parse_text(filepath)
        except Exception as e:
            logger.error(f"Failed to parse Nikto file {filepath}: {e}")
            return self._empty_result()

    def parse_json(self, filepath: str) -> Dict[str, Any]:
        #parse Nikto JSON output
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)

            data = self._normalize_json(data)
            if not isinstance(data, dict):
                raise ValueError("Unexpected Nikto JSON format")

            #extract common scan info including possible version fields
            if 'host' in data:
                version = data.get('version') or data.get('nikto_version') or data.get('nikto', {}).get('version')
                self.scan_info = {
                    'target': data.get('host', 'unknown'),
                    'port': data.get('port', '80'),
                    'ip': data.get('ip', 'unknown'),
                    'scan_type': 'nikto',
                }
                if version:
                    self.scan_info['version'] = version

            vulnerabilities = data.get('vulnerabilities', [])
            for vuln in vulnerabilities:
                finding = self._parse_vulnerability(vuln)
                if finding:
                    self.findings.append(finding)

            return {
                'scan_info': self.scan_info,
                'findings': self.findings,
                'total_findings': len(self.findings),
                'critical_count': len([f for f in self.findings if f['severity'] == 'critical']),
                'high_count': len([f for f in self.findings if f['severity'] == 'high']),
                'medium_count': len([f for f in self.findings if f['severity'] == 'medium']),
                'low_count': len([f for f in self.findings if f['severity'] == 'low']),
                'success': True
            }
        except Exception as e:
            logger.error(f"JSON parsing error: {e}")
            return self._empty_result()

    def _normalize_json(self, data: Any) -> Any:
        #normalize Nikto JSON output to a single dict
        if isinstance(data, list):
            if not data:
                return {}
            if isinstance(data[0], dict):
                return data[0]
        return data

    def parse_csv(self, filepath: str) -> Dict[str, Any]:
        #parse Nikto CSV output
        try:
            #read full content so we can search for a version string in text headers or comments
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()

            #attempt to locate a Nikto version string in the CSV content
            version_match = re.search(r'Nikto(?: v|/)?\s*([0-9]+(?:\.[0-9]+)+)', text, re.IGNORECASE)
            if version_match:
                self.scan_info = {'scan_type': 'nikto', 'version': version_match.group(1)}

            #parse CSV from text
            reader = csv.DictReader(io.StringIO(text))
            for row in reader:
                finding = self._parse_csv_row(row)
                if finding:
                    self.findings.append(finding)

            if self.findings and not self.scan_info:
                first = self.findings[0]
                self.scan_info = {
                    'target': first['details'].get('host', 'unknown'),
                    'scan_type': 'nikto'
                }

            return {
                'scan_info': self.scan_info,
                'findings': self.findings,
                'total_findings': len(self.findings),
                'success': True
            }
        except Exception as e:
            logger.error(f"CSV parsing error: {e}")
            return self._empty_result()

    def parse_text(self, filepath: str) -> Dict[str, Any]:
        #parse Nikto text output
        try:
            self.findings = []

            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            #tries to find Nikto version string in the content
            version_match = re.search(r'Nikto(?: v|/)?\s*([0-9]+(?:\.[0-9]+)+)', content, re.IGNORECASE)

            target_match = re.search(r'Target:\s+([^\s]+)', content)
            ip_match = re.search(r'Target IP:\s+([^\s]+)', content)
            port_match = re.search(r'Target Port:\s+(\d+)', content)

            self.scan_info = {
                'target': target_match.group(1) if target_match else 'unknown',
                'ip': ip_match.group(1) if ip_match else 'unknown',
                'port': port_match.group(1) if port_match else '80',
                'scan_type': 'nikto'
            }

            if version_match:
                self.scan_info['version'] = version_match.group(1)

            self._extract_findings_from_text(content)

            unique_findings = []
            seen_descriptions = set()
            for finding in self.findings:
                desc = finding.get('description', '')
                if desc not in seen_descriptions:
                    seen_descriptions.add(desc)
                    unique_findings.append(finding)
            self.findings = unique_findings

            return {
                'scan_info': self.scan_info,
                'findings': self.findings,
                'total_findings': len(self.findings),
                'success': True
            }
        except Exception as e:
            logger.error(f"Text parsing error: {e}")
            return self._empty_result()

    def _parse_vulnerability(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        #parse a single vulnerability from JSON
        try:
            vuln_id = vuln.get('id', 'unknown')
            method = vuln.get('method', 'GET')
            url = vuln.get('url', '')
            msg = vuln.get('msg', '')
            title, finding_type, severity = self._classify_message(vuln_id, msg)

            raw_refs = vuln.get('refs', []) or vuln.get('references', [])

            return {
                'type': finding_type,
                'severity': severity,
                'title': title,
                'description': msg,
                'affected_component': url,
                'details': {
                    'id': vuln_id,
                    'method': method,
                    'url': url,
                    'osvdb': vuln.get('OSVDB', ''),
                    'refs': raw_refs
                },
                'references': self._extract_references(msg, raw_refs),
                'source': 'nikto',
                'recommendation': self._generate_recommendation(vuln_id, msg)
            }
        except Exception as e:
            logger.error(f"Vulnerability parsing error: {e}")
            return None

    def _parse_csv_row(self, row: Dict[str, str]) -> Dict[str, Any]:
        #parse CSV row into finding
        try:
            host = row.get('host', 'unknown')
            port = row.get('port', '80')
            osvdb = row.get('OSVDB', '')
            method = row.get('HTTP Method', 'GET')
            uri = row.get('URI', '')
            msg = row.get('Msg', '')
            title, finding_type, severity = self._classify_message(osvdb, msg)

            return {
                'type': finding_type,
                'severity': severity,
                'title': title,
                'description': msg,
                'affected_component': f"{host}:{port}{uri}",
                'details': {
                    'host': host,
                    'port': port,
                    'osvdb': osvdb,
                    'method': method,
                    'uri': uri
                },
                'references': self._extract_references(msg, row.get('references', '')),
                'source': 'nikto',
                'recommendation': self._generate_recommendation(osvdb, msg)
            }
        except Exception as e:
            logger.error(f"CSV row parsing error: {e}")
            return None

    def _extract_findings_from_text(self, content: str):
        #extract findings from text format
        lines = content.split('\n')

        for line in lines:
            line = line.strip()

            if not line.startswith('+'):
                continue

            line = line[1:].strip()
            if not line or line.startswith('-'):
                continue

            osvdb_match = re.search(r'OSVDB-(\d+)', line)
            osvdb = osvdb_match.group(1) if osvdb_match else ''
            severity = self._determine_severity(osvdb, line)

            if severity == 'info' and not self._is_important_info(line):
                continue

            endpoint = ''
            if line.startswith(('GET ', 'POST ', 'HEAD ', 'OPTIONS ')):
                parts = line.split(':')
                if parts:
                    endpoint = parts[0].strip()

            target = self.scan_info.get('target', 'unknown')
            port = self.scan_info.get('port', '80')
            affected_component = f"{target}:{port}"
            if endpoint and not endpoint.startswith(target):
                affected_component = f"{target}:{port}/{endpoint}"

            title, finding_type, severity = self._classify_message(osvdb, line)

            self.findings.append({
                'type': finding_type,
                'severity': severity,
                'title': title,
                'description': line,
                'affected_component': affected_component,
                'details': {
                    'osvdb': osvdb,
                    'endpoint': endpoint,
                    'target': target,
                    'port': port
                },
                'references': self._extract_references(line),
                'source': 'nikto',
                'recommendation': self._generate_recommendation(osvdb, line)
            })

    def _determine_severity(self, vuln_id: str, message: str) -> str:
        #determine severity based on known keywords
        message_lower = message.lower()

        if any(term in message_lower for term in ['remote code', 'rce', 'sql injection', 'directory traversal']):
            return 'critical'
        if any(term in message_lower for term in ['xss', 'csrf', 'xxe', 'overflow']):
            return 'high'
        if any(term in message_lower for term in ['outdated', 'obsolete', 'deprecated', 'admin', 'backup', 'insecure']):
            return 'medium'
        if any(term in message_lower for term in ['missing header', 'x-frame-options', 'x-content-type-options', 'uncommon header', 'banner']):
            return 'low'
        if any(term in message_lower for term in ['exposed', 'disclosure', 'misconfiguration']):
            return 'medium'

        if any(term in message_lower for term in ['cookie', 'info']):
            return 'low'

        if vuln_id and vuln_id.isdigit():
            osvdb_id = int(vuln_id)
            if osvdb_id < 1000:
                return 'high'
            if osvdb_id < 5000:
                return 'medium'

        return 'info'

    def _classify_message(self, vuln_id: str, message: str) -> tuple:
        message_lower = message.lower()
        severity = self._determine_severity(vuln_id, message)

        if 'x-frame-options' in message_lower or 'x-content-type-options' in message_lower:
            return 'Missing Security Headers', 'security_headers', severity
        if 'crossdomain.xml' in message_lower or 'clientaccesspolicy.xml' in message_lower:
            return 'Cross-Domain Policy Exposure', 'policy_exposure', severity
        if 'backup' in message_lower or '.zip' in message_lower or '.tar' in message_lower:
            return 'Backup or Archive File Found', 'sensitive_file', severity
        if 'robots.txt' in message_lower:
            return 'Robots.txt Disclosure', 'content_discovery', severity
        if 'admin' in message_lower:
            return 'Admin Surface Exposure', 'admin_surface', severity
        if 'outdated' in message_lower:
            return 'Outdated Software Detected', 'outdated_software', severity

        return self._generate_title(vuln_id, message), 'web_vulnerability', severity

    def _generate_title(self, vuln_id: str, msg: str) -> str:
        #generate a readable title
        if vuln_id:
            #remove leading zeros for numeric IDs for cleaner titles
            try:
                if isinstance(vuln_id, str) and vuln_id.isdigit():
                    return f"Finding {int(vuln_id)}"
            except Exception:
                pass
            return f"Finding {vuln_id}"
        return msg[:60] + ('...' if len(msg) > 60 else '')

    def _generate_recommendation(self, vuln_id: str, msg: str) -> str:
        #generate simple recommendation
        if 'xss' in msg.lower():
            return 'Implement output encoding and validate user input.'
        if 'sql injection' in msg.lower():
            return 'Use parameterized queries and input validation.'
        if 'directory traversal' in msg.lower():
            return 'Sanitize file paths and enforce access controls.'
        if 'outdated' in msg.lower():
            return 'Update the software to the latest stable version.'
        if 'x-frame-options' in msg.lower():
            return 'Set X-Frame-Options or CSP frame-ancestors to prevent clickjacking.'
        if 'x-content-type-options' in msg.lower():
            return 'Set X-Content-Type-Options to nosniff.'
        if 'robots.txt' in msg.lower():
            return 'Review robots.txt entries and remove sensitive paths.'
        if 'backup' in msg.lower() or '.zip' in msg.lower() or '.tar' in msg.lower():
            return 'Remove exposed backup/archive files from the web root.'
        return 'Review the finding and apply appropriate remediation.'

    def _is_important_info(self, message: str) -> bool:
        #filter low value info lines
        return any(term in message.lower() for term in ['admin', 'password', 'login', 'header', 'robots', 'backup'])

    def _extract_references(self, message: str, refs: Any = None) -> List[str]:
        references = []
        if refs:
            if isinstance(refs, list):
                references.extend(refs)
            elif isinstance(refs, str):
                references.extend([r.strip() for r in refs.split(',') if r.strip()])
        if message:
            references.extend(re.findall(r'https?://\S+', message))
        return list(dict.fromkeys(references))

    def _empty_result(self) -> Dict[str, Any]:
        return {
            'scan_info': {},
            'findings': [],
            'total_findings': 0,
            'success': False
        }

# Done by Manuel Morales-Marroquin
