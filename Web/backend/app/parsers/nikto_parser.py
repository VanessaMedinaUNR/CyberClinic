#Cyber clinic - nikto scan result parser
#Extracts web vulnerabilities from nikto output

import json
import re
import logging
from typing import Dict, List, Any
import csv

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
            elif filepath.endswith('.csv'):
                return self.parse_csv(filepath)
            else:
                return self.parse_text(filepath)
        except Exception as e:
            logger.error(f"Failed to parse Nikto file {filepath}: {e}")
            return self._empty_result()
    
    def parse_json(self, filepath: str) -> Dict[str, Any]:
        #parse Nikto JSON output
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            #extracts scan info
            if 'host' in data:
                self.scan_info = {
                    'target': data.get('host', 'unknown'),
                    'port': data.get('port', '80'),
                    'ip': data.get('ip', 'unknown'),
                    'scan_type': 'nikto',
                    'start_time': data.get('starttime', '') }
            
            #extracts vulnerabilities
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
    
    def parse_csv(self, filepath: str) -> Dict[str, Any]:
        #parse Nikto CSV output
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                
                for row in reader:
                    finding = self._parse_csv_row(row)
                    if finding:
                        self.findings.append(finding)
            
            #extracts basic scan info from first finding
            if self.findings:
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
            #resets findings for each parse
            self.findings = []
            
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            #extracts target info
            target_match = re.search(r'Target:\s+([^\s]+)', content)
            ip_match = re.search(r'Target IP:\s+([^\s]+)', content)
            port_match = re.search(r'Target Port:\s+(\d+)', content)
            
            self.scan_info = {
                'target': target_match.group(1) if target_match else 'unknown',
                'ip': ip_match.group(1) if ip_match else 'unknown',
                'port': port_match.group(1) if port_match else '80',
                'scan_type': 'nikto'
            }
            
            #parses findings from text
            self._extract_findings_from_text(content)
            
            #deduplicate findings by description to handle repeated nikto output
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
            
            #determines severity based on OSVDB ID or message content
            severity = self._determine_severity(vuln_id, msg)
            
            return {
                'type': 'web_vulnerability',
                'severity': severity,
                'title': self._generate_title(vuln_id, msg),
                'description': msg,
                'affected_component': url,
                'details': {
                    'id': vuln_id,
                    'method': method,
                    'url': url,
                    'osvdb': vuln.get('OSVDB', ''),
                    'refs': vuln.get('refs', [])
                },
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
            
            severity = self._determine_severity(osvdb, msg)
            
            return {
                'type': 'web_vulnerability',
                'severity': severity,
                'title': self._generate_title(osvdb, msg),
                'description': msg,
                'affected_component': f"{host}:{port}{uri}",
                'details': {
                    'host': host,
                    'port': port,
                    'osvdb': osvdb,
                    'method': method,
                    'uri': uri
                },
                'recommendation': self._generate_recommendation(osvdb, msg)
            }
            
        except Exception as e:
            logger.error(f"CSV row parsing error: {e}")
            return None
    
    def _extract_findings_from_text(self, content: str):
        #extract findings from text format
        #nikto text format typically has + prefixed lines for findings
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            #skip non finding lines
            if not line.startswith('+'):
                continue
            
            #remove the + prefix
            line = line[1:].strip()
            #skip empty or info lines
            if not line or line.startswith('-'):
                continue
            #extract OSVDB if present
            osvdb_match = re.search(r'OSVDB-(\d+)', line)
            osvdb = osvdb_match.group(1) if osvdb_match else ''
            #determine severity
            severity = self._determine_severity(osvdb, line)
            #skip info level findings unless they're important
            if severity == 'info' and not self._is_important_info(line):
                continue
            #extract path/endpoint if present in finding
            endpoint = ''
            if line.startswith('GET ') or line.startswith('POST ') or line.startswith('HEAD ') or line.startswith('OPTIONS '):
                parts = line.split(':')
                if parts:
                    endpoint = parts[0].strip()
            #build affected component (host:port or host:port/endpoint)
            target = self.scan_info.get('target', 'unknown')
            port = self.scan_info.get('port', '80')
            affected_component = f"{target}:{port}"
            if endpoint and not endpoint.startswith(target):
                affected_component = f"{target}:{port} {endpoint}"
            
            finding = {
                'type': 'web_vulnerability',
                'severity': severity,
                'title': self._generate_title(osvdb, line),
                'description': line,
                'affected_component': affected_component,
                'details': {
                    'osvdb': osvdb,
                    'raw': line
                },
                'recommendation': self._generate_recommendation(osvdb, line)
            }
            
            self.findings.append(finding)
    
    def _determine_severity(self, osvdb: str, message: str) -> str:
        #determine severity level from OSVDB or message content
        msg_lower = message.lower()
        
        #critical indicators
        if any(word in msg_lower for word in ['sql injection', 'remote code execution', 'rce', 'file upload', 'command injection']):
            return 'critical'
        #high indicators
        if any(word in msg_lower for word in ['xss', 'cross-site scripting', 'authentication bypass', 'directory traversal', 
                                                'lfi', 'rfi', 'xxe', 'ssrf', 'csrf']):
            return 'high'
        #medium indicators
        if any(word in msg_lower for word in ['disclosure', 'exposed', 'misconfiguration', 'weak', 'insecure', 
                                                'unencrypted', 'default credentials', 'backup file']):
            return 'medium'
        #low indicators
        if any(word in msg_lower for word in ['deprecated', 'outdated', 'missing header', 'cookie', 'clickjacking']):
            return 'low'
        #default to info
        return 'info'
    
    def _generate_title(self, osvdb: str, message: str) -> str:
        #generate a concise title for the finding
        #extract first meaningful sentence
        title = message.split('.')[0].strip()
        #limit length
        if len(title) > 100:
            title = title[:97] + '...'
        
        if osvdb:
            return f"[OSVDB-{osvdb}] {title}"
        
        return title
    
    def _generate_recommendation(self, osvdb: str, message: str) -> str:
        #generate remediation recommendation
        msg_lower = message.lower()
        
        #specific recommendations based on finding type
        if 'sql injection' in msg_lower:
            return 'Use parameterized queries or prepared statements. Implement input validation and sanitization. Apply principle of least privilege to database accounts.'
        
        if 'xss' in msg_lower or 'cross-site scripting' in msg_lower:
            return 'Implement output encoding for all user input. Use Content Security Policy (CSP) headers. Validate and sanitize all input data.'
        
        if 'directory traversal' in msg_lower or 'path traversal' in msg_lower:
            return 'Implement strict input validation. Use whitelisting for allowed paths. Avoid direct file system access from user input.'
        
        if 'default credentials' in msg_lower or 'default password' in msg_lower:
            return 'Change all default credentials immediately. Implement strong password policy. Use multi-factor authentication.'
        
        if 'disclosure' in msg_lower or 'exposed' in msg_lower:
            return 'Remove or restrict access to sensitive information. Implement proper access controls. Review error handling to prevent information leakage.'
        
        if 'backup' in msg_lower:
            return 'Remove backup files from web-accessible directories. Implement proper backup procedures with secure storage.'
        
        if 'missing header' in msg_lower:
            return 'Implement security headers (X-Frame-Options, X-Content-Type-Options, HSTS, CSP). Review web server configuration.'
        
        if 'outdated' in msg_lower or 'deprecated' in msg_lower:
            return 'Update software to the latest stable version. Subscribe to security mailing lists for vendor advisories.'
        
        #generic recommendation
        return 'Review the finding details and apply vendor-recommended patches. Implement defense-in-depth security controls.'
    
    def _is_important_info(self, message: str) -> bool:
        #dtermine if an info level finding is important enough to include
        msg_lower = message.lower()
        
        #include these info findings
        important_keywords = [
            'allowed http methods',
            'server version',
            'robots.txt',
            'sitemap.xml',
            'admin',
            'login',
            'panel'
        ]
        
        return any(keyword in msg_lower for keyword in important_keywords)
    
    def _empty_result(self) -> Dict[str, Any]:
        #return empty result structure
        return {
            'scan_info': {'scan_type': 'nikto'},
            'findings': [],
            'total_findings': 0,
            'success': False,
            'error': 'Failed to parse scan results'
        }

#done by Manuel
