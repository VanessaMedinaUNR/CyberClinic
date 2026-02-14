#Cyber clinic - custom report generator
#Generates json/html/pdf security assessment reports

import os
import json
import logging
import csv
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from jinja2 import Environment, FileSystemLoader, select_autoescape
from app.parsers.nmap_parser import NmapParser
from app.parsers.nikto_parser import NiktoParser
from app.severity_mapper import SeverityMapper
import shutil
import subprocess
import re
import glob

logger = logging.getLogger(__name__)

try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

class CustomReportGenerator:
    #generate custom json/html/pdf security assessment reports

    def __init__(self):
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )

        self.nmap_parser = NmapParser()
        self.nikto_parser = NiktoParser()
        self.severity_mapper = SeverityMapper()

        self.reports_dir = os.path.join(os.path.dirname(__file__), '..', 'reports')
        os.makedirs(self.reports_dir, exist_ok=True)

        #friendly metadata for generated reports
        self.generated_by = {
            'team': 'Cyber Clinic - CS 425 Team 13',
            'org': 'University of Nevada, Reno - Department of CSE',
            'contact_email': 'contact@cyberclinic.unr.edu',
            'github': 'https://github.com/unr-cyberclinic'
        }

    def generate_report(self, scan_data: Dict[str, Any], output_format: str = 'html') -> str:
        try:
            output_format = output_format.lower()
            logger.info(f"Generating {output_format.upper()} report for scan {scan_data.get('scan_id')}")

            #attempt to prepare full report data, if that fails it assemble a best effort fallback
            try:
                report_data = self._prepare_report_data(scan_data)
            except Exception:
                logger.exception('Primary report data preparation failed; attempting fallback assembly')
                #best effort fallback, parse provided result files and builds a reasonable report_data
                results_paths = scan_data.get('results_paths', []) or []
                if isinstance(results_paths, str):
                    results_paths = [results_paths]
                nmap_files = self._find_results_files(results_paths, 'nmap')
                nikto_files = self._find_results_files(results_paths, 'nikto')

                merged_nmap_hosts = []
                merged_nmap_findings = []
                for nf in nmap_files:
                    try:
                        parsed = self.nmap_parser.parse_file(nf)
                        merged_nmap_hosts.extend(parsed.get('hosts', []) or [])
                        for f in parsed.get('findings', []) or []:
                            merged_nmap_findings.append(self._normalize_finding(f))
                    except Exception:
                        logger.exception('Fallback: failed parsing Nmap file %s', nf)

                merged_nikto_findings = []
                for kf in nikto_files:
                    try:
                        parsed = self.nikto_parser.parse_file(kf)
                        for f in parsed.get('findings', []) or []:
                            merged_nikto_findings.append(self._normalize_finding(f))
                    except Exception:
                        logger.exception('Fallback: failed parsing Nikto file %s', kf)

                all_findings = merged_nmap_findings + merged_nikto_findings
                try:
                    enriched_findings = [self.severity_mapper.enrich_finding(f.copy() if isinstance(f, dict) else f) for f in all_findings]
                except Exception:
                    enriched_findings = list(all_findings)

                sorted_findings = self.severity_mapper.sort_findings(enriched_findings)
                finding_stats = self.severity_mapper.aggregate_findings_stats(sorted_findings)
                scan_duration = self._calculate_duration(scan_data.get('timestamps', {}).get('started'), scan_data.get('timestamps', {}).get('completed'))

                report_data = {
                    'report_title': f"Security Assessment - {scan_data.get('target', {}).get('name', 'Unknown Target')}",
                    'report_date': datetime.now().strftime('%B %d, %Y'),
                    'scan_date': scan_data.get('timestamps', {}).get('completed', '') or datetime.now().strftime('%Y-%m-%d'),
                    'is_draft': False,
                    'client_name': scan_data.get('client', {}).get('name', 'Unknown Organization'),
                    'contact_email': scan_data.get('client', {}).get('email', 'contact@cyberclinic.unr.edu'),
                    'targets': scan_data.get('targets', {}),
                    'scan_type_display': self._get_scan_type_display(scan_data.get('scan_type', 'unknown')),
                    'scan_types_used': ([ 'nmap' ] if (merged_nmap_hosts or merged_nmap_findings) else []) + ([ 'nikto' ] if nikto_files else []) ,
                    'scan_duration': scan_duration,
                    'hosts_scanned': len(merged_nmap_hosts),
                    'open_ports_total': sum(len([p for p in h.get('ports', []) if p.get('state') == 'open']) for h in merged_nmap_hosts),
                    'findings': sorted_findings,
                    'top_findings': sorted_findings[:10],
                    'finding_types': self._aggregate_finding_types(sorted_findings),
                    'finding_stats': finding_stats,
                    'overall_risk': (finding_stats.get('overall_risk') if isinstance(finding_stats, dict) else 'Unknown') or 'Unknown',
                    'overall_risk_class': 'risk-unknown',
                    'nmap_data': {'hosts': merged_nmap_hosts, 'findings': merged_nmap_findings},
                    'nikto_data': {'findings': merged_nikto_findings},
                    #'per_host_findings': self._group_findings_by_host(sorted_findings, {'hosts': merged_nmap_hosts}),
                    #'services_summary': self._aggregate_services({'hosts': merged_nmap_hosts}),
                    #'tool_versions': self._collect_tool_versions({'scan_info': {}}, {'scan_info': {}}),
                    'default_tool_versions': [
                        {'name': 'nmap', 'version': '7.98'},
                        {'name': 'nikto', 'version': '2.1.6'}
                    ],
                    'scan_warning': 'Surface-level automated scans (Nmap/Nikto) can miss issues. Further manual testing recommended.',
                    'generated_by': self.generated_by,
                    'confidentiality_notice': 'CONFIDENTIAL. This report contains sensitive security information and should be handled accordingly.'
                }

                try:
                    host_map = self._build_host_map(merged_nmap_hosts)
                    report_data['hosts_summary'] = host_map
                    host_list = [h.get('ip') or h.get('ipv4') or h.get('ipv6') for h in merged_nmap_hosts if isinstance(h, dict)]
                    report_data['hosts_list'] = host_list or [scan_data.get('target', {}).get('value')]
                    report_data['hosts_display_list'] = [ (hl + (f" ({host_map.get(hl, [''])[0]})" if host_map.get(hl) else '')) for hl in report_data['hosts_list'] ]
                except Exception:
                    report_data['hosts_summary'] = {}
                    report_data['hosts_list'] = [scan_data.get('target', {}).get('value')]
                    report_data['hosts_display_list'] = report_data['hosts_list']

            #include generated_by and confidentiality text in both json and html
            report_data['generated_by'] = self.generated_by
            report_data['confidentiality_notice'] = (
                "CONFIDENTIAL. This report contains sensitive security information and should be handled accordingly."
            )

            #always save a JSON copy of the report for frontend consumption (named report_<id>.json)
            try:
                json_path = self._save_json_report(report_data, scan_data.get('scan_id'))
                logger.info(f"JSON report saved for frontend: {json_path}")
            except Exception:
                logger.exception('Failed to save JSON report')

            if output_format == 'json':
                logger.info(f"Report generated successfully (JSON): {json_path}")
                return json_path

            if output_format == 'csv':
                csv_path = self._save_csv_report(report_data, scan_data.get('scan_id'))
                logger.info(f"Report generated successfully: {csv_path}")
                return csv_path

            #render HTML template, fall back to safe JSON embedded HTML if template rendering fails
            try:
                html_content = self._render_html_template(report_data)
            except Exception:
                logger.exception('Template rendering failed; falling back to safe JSON-embedded HTML')
                try:
                    safe_json = json.dumps(report_data, indent=2, default=str)
                    html_content = (
                        '<html><head><meta charset="utf-8"><title>' + (report_data.get('report_title') or 'Scan Report') + '</title></head><body>'
                        '<h1>' + (report_data.get('report_title') or 'Scan Report') + '</h1>'
                        '<h2>Report JSON</h2><pre>' + safe_json + '</pre></body></html>'
                    )
                except Exception:
                    #last resort simple message
                    html_content = '<html><body><h1>Scan Report</h1><p>Report generation failed to render template.</p></body></html>'

            html_path = self._save_html_report(html_content, scan_data.get('scan_id'))

            if output_format == 'pdf':
                pdf_path = self._convert_to_pdf(html_path, scan_data.get('scan_id'))
                logger.info(f"Report generated successfully: {pdf_path}")
                return pdf_path

            logger.info(f"Report generated successfully: {html_path}")
            return html_path

        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            raise

    def generate_quick_report(self, scan_id: int, scan_type: str, target: str,
                              results_path: str, client_name: str = 'Test Client',
                              contact_email: str = 'test@example.com') -> str:
        scan_data = {
            'scan_id': scan_id,
            'scan_type': scan_type,
            'target': {
                'value': target,
                'name': target,
                'type': 'ip_range' if ('/' in target or '-' in target) else ('domain' if '.' in target and not target.replace('.', '').isdigit() else 'ip')
            },
            'client': {
                'name': client_name,
                'email': contact_email
            },
            'timestamps': {
                'started': datetime.now().isoformat(),
                'completed': datetime.now().isoformat()
            },
            'results_paths': [results_path] if isinstance(results_path, str) else results_path
        }

        return self.generate_report(scan_data, output_format='json')

    def _prepare_report_data(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        scan_id = scan_data.get('scan_id')
        scan_type = scan_data.get('scan_type', 'unknown')
        target_info = scan_data.get('targets', {})
        client_info = scan_data.get('client', {})
        timestamps = scan_data.get('timestamps', {})
        results_paths = scan_data.get('results_paths', [])

        all_findings = []
        scan_types_used = []
        nmap_data = {}
        nikto_data = {}

        #determine/normalize target type if not provided
        #if not target_info.get('type'):
        #    target_info['type'] = self._detect_target_type(target_info.get('value', ''))

        #ensure results_paths is a list
        if isinstance(results_paths, str):
            results_paths = [results_paths]

        #detect all available result files for each tool
        nmap_files = self._find_results_files(results_paths, 'nmap')
        nikto_files = self._find_results_files(results_paths, 'nikto')

        #parse all detected nmap files and merge results
        merged_nmap_hosts = []
        merged_nmap_findings = []
        for nf in nmap_files:
            try:
                scan_types_used.append('nmap')
                parsed = self.nmap_parser.parse_file(nf)
                #append hosts
                merged_nmap_hosts.extend(parsed.get('hosts', []) or [])
                #normalize and collect findings
                for f in parsed.get('findings', []) or []:
                    f = self._normalize_finding(f)
                    merged_nmap_findings.append(f)
            except Exception:
                logger.exception('Failed parsing Nmap file: %s', nf)

        if merged_nmap_hosts or merged_nmap_findings:
            nmap_data = {
                'hosts': merged_nmap_hosts,
                'findings': merged_nmap_findings,
                'total_hosts': len(merged_nmap_hosts),
                'total_open_ports': sum(len([p for p in h.get('ports', []) if p.get('state') == 'open']) for h in merged_nmap_hosts)
            }
            all_findings.extend(merged_nmap_findings)

        #parse all detected nikto files and merge results
        merged_nikto_findings = []
        for kf in nikto_files:
            try:
                scan_types_used.append('nikto')
                parsed = self.nikto_parser.parse_file(kf)
                for f in parsed.get('findings', []) or []:
                    f = self._normalize_finding(f)
                    merged_nikto_findings.append(f)
            except Exception:
                logger.exception('Failed parsing Nikto file: %s', kf)

        try:
            if nikto_files and 'nikto' not in scan_types_used:
                scan_types_used.append('nikto')
        except Exception:
            pass

        if merged_nikto_findings:
            nikto_data = {
                'findings': merged_nikto_findings,
                'total_findings': len(merged_nikto_findings)
            }
            all_findings.extend(merged_nikto_findings)

        try:
            enriched_findings = [self.severity_mapper.enrich_finding(f.copy() if isinstance(f, dict) else f) for f in all_findings]
        except Exception:
            enriched_findings = list(all_findings)

        sorted_findings = self.severity_mapper.sort_findings(enriched_findings)
        finding_stats = self.severity_mapper.aggregate_findings_stats(sorted_findings)

        scan_type_display = self._get_scan_type_display(scan_type)
        #normalize scan_types_used and determine actual scan mode (tools run)
        normalized_tools = [t.lower() for t in list(dict.fromkeys(scan_types_used))]
        try:
            explicit_scan = (scan_type or '').lower()
            if explicit_scan in ('nmap', 'nikto', 'full', 'comprehensive'):
                if explicit_scan == 'nmap':
                    normalized_tools = ['nmap']
                    scan_type_display = self._get_scan_type_display('nmap')
                elif explicit_scan == 'nikto':
                    normalized_tools = ['nikto']
                    scan_type_display = self._get_scan_type_display('nikto')
                else:
                    normalized_tools = ['nmap', 'nikto']
                    scan_type_display = self._get_scan_type_display('full')
        except Exception:
            pass
        if 'nmap' in normalized_tools and 'nikto' in normalized_tools:
            actual_scan_type = 'comprehensive'
            scan_type_display = 'Comprehensive Scan (Nmap + Nikto)'
        elif 'nmap' in normalized_tools:
            actual_scan_type = 'nmap'
            scan_type_display = 'Network and Port Scan (Nmap)'
        elif 'nikto' in normalized_tools:
            actual_scan_type = 'nikto'
            scan_type_display = 'Web Vulnerability Scan (Nikto)'
        else:
            actual_scan_type = scan_type.lower() if isinstance(scan_type, str) else 'unknown'

        scan_duration = self._calculate_duration(
            timestamps.get('started'),
            timestamps.get('completed')
        )

        #group findings per host for range scans so front end and report can show per target mapping
        per_host_findings = self._group_findings_by_host(sorted_findings, nmap_data)

        #map overall risk to a color class and friendly label
        risk = finding_stats.get('overall_risk', 'Unknown')
        risk_map = {
            'critical': ('Critical', 'risk-critical'),
            'high': ('High', 'risk-high'),
            'medium': ('Medium', 'risk-medium'),
            'low': ('Low', 'risk-low'),
            'minimal': ('Minimal', 'risk-minimal')
        }
        overall_risk_label, overall_risk_class = risk_map.get(risk.lower(), (risk, 'risk-unknown')) if isinstance(risk, str) else (risk, 'risk-unknown')

        #build preliminary report_data so later sections can attach hosts info
        report_data = {
            'report_title': f"Security Assessment - {client_info.get('name', '')}",
            'report_date': datetime.now().strftime('%B %d, %Y'),
            'scan_date': timestamps.get('completed', '') or datetime.now().strftime('%Y-%m-%d'),
            'is_draft': False,
            'client_name': client_info.get('name', 'Unknown Organization'),
            'contact_email': client_info.get('email', 'contact@cyberclinic.unr.edu'),
            'targets': target_info,
            #'target_value': target_info.get('value', 'Unknown'),
            #'target_type': target_info.get('type', 'unknown'),
            #'target_name': target_info.get('name', 'Unknown'),
            'scan_type': actual_scan_type,
            'scan_type_display': scan_type_display,
            'scan_types_used': normalized_tools,
            'scan_duration': scan_duration,
            'hosts_scanned': nmap_data.get('total_hosts', 0),
            'open_ports_total': nmap_data.get('total_open_ports', 0),
            'findings': sorted_findings,
            'top_findings': sorted_findings[:10],
            'finding_types': self._aggregate_finding_types(sorted_findings),
            'finding_stats': finding_stats,
            'overall_risk': overall_risk_label,
            'overall_risk_class': overall_risk_class,
            'nmap_data': nmap_data,
            'nikto_data': nikto_data,
            'per_host_findings': per_host_findings,
            'services_summary': self._aggregate_services(nmap_data),
            'tool_versions': {},
            'default_tool_versions': [
                {'name': 'nmap', 'version': '7.98'},
                {'name': 'nikto', 'version': '2.1.6'}
            ],
            'scan_warning': 'Surface-level automated scans (Nmap/Nikto) can miss issues. Further manual testing recommended.',
            'generated_by': self.generated_by,
            'confidentiality_notice': 'CONFIDENTIAL. This report contains sensitive security information and should be handled accordingly.'
        }

        hosts_summary = self._build_host_map(nmap_data.get('hosts', []))

        #create an ordered hosts_list using nmap host order when possible, otherwise fall back to hosts_summary keys
        ordered_hosts: List[str] = []
        for h in nmap_data.get('hosts', []) or []:
            if isinstance(h, dict):
                ip = h.get('ip') or h.get('ipv4') or h.get('ipv6')
                if ip and ip not in ordered_hosts:
                    ordered_hosts.append(str(ip))

        for ip in hosts_summary.keys():
            if ip not in ordered_hosts:
                ordered_hosts.append(ip)

        #if no hosts found yet, try to fall back to provided target value
        if not ordered_hosts:
            tv = target_info.get('value')
            if tv:
                ordered_hosts = [tv]

        extra_hosts: List[str] = []
        try:
            t = scan_data.get('target')
            if t:
                if isinstance(t, dict):
                    val = t.get('value')
                else:
                    val = t
                if isinstance(val, str):
                    for part in [p.strip() for p in re.split(r'[;,\s]+', val) if p.strip()]:
                        if part and part not in extra_hosts:
                            extra_hosts.append(part)
        except Exception:
            pass

        #include hosts discovered in merged_nikto_findings (common fields)
        try:
            import urllib.parse
            for f in merged_nikto_findings or []:
                if not isinstance(f, dict):
                    continue
                #candidate fields that may contain host/ip/url
                for key in ('affected_component', 'affected', 'host', 'hostname', 'ip', 'target', 'url'):
                    v = f.get(key)
                    if not v:
                        continue
                    vals = v if isinstance(v, list) else [v]
                    for raw in vals:
                        try:
                            s = str(raw).strip()
                            if not s:
                                continue
                            #if url, parse hostname
                            if s.startswith('http://') or s.startswith('https://'):
                                try:
                                    hn = urllib.parse.urlparse(s).hostname
                                    s = hn or s
                                except Exception:
                                    pass
                            #strip port if present
                            if ':' in s and not re.match(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$', s):
                                s = s.split(':')[0]
                            s = s.strip().rstrip('/')
                            if s and s not in extra_hosts:
                                extra_hosts.append(s)
                        except Exception:
                            continue
        except Exception:
            pass

        #include any hosts reported in nikto_data structures
        try:
            if isinstance(nikto_data, dict):
                for key in ('hosts', 'host_map', 'targets'):
                    hv = nikto_data.get(key)
                    if not hv:
                        continue
                    if isinstance(hv, dict):
                        for k in hv.keys():
                            if k and k not in extra_hosts:
                                extra_hosts.append(str(k))
                    elif isinstance(hv, list):
                        for item in hv:
                            if item and str(item) not in extra_hosts:
                                extra_hosts.append(str(item))
                    elif isinstance(hv, str) and hv not in extra_hosts:
                        extra_hosts.append(hv)
        except Exception:
            pass

        #scan provided results_paths for JSON files that may include a host_map 
        try:
            for p in results_paths or []:
                if not p:
                    continue
                if isinstance(p, str) and os.path.exists(p) and p.lower().endswith('.json'):
                    try:
                        with open(p, 'r', encoding='utf-8') as rf:
                            jd = json.load(rf)
                            #host_map may be top level or under known keys
                            hm = jd.get('host_map') or jd.get('hostmap') or jd.get('hosts') or jd.get('results', {})
                            if isinstance(hm, dict):
                                for k in hm.keys():
                                    if k and k not in extra_hosts:
                                        extra_hosts.append(str(k))
                            elif isinstance(hm, list):
                                for item in hm:
                                    if item and str(item) not in extra_hosts:
                                        extra_hosts.append(str(item))
                    except Exception:
                        continue
        except Exception:
            pass

        #merge extra_hosts into ordered_hosts preserving order and uniqueness
        for h in extra_hosts:
            if h not in ordered_hosts:
                ordered_hosts.append(h)

        #final fallback ensure at least one host present
        if not ordered_hosts:
            tv = target_info.get('value')
            if tv:
                ordered_hosts = [tv]

        #normalize and remove path like entries ('/index') and convert URLs to hostnames
        try:
            import urllib.parse
            cleaned_hosts: List[str] = []
            for h in ordered_hosts:
                if not h:
                    continue
                s = str(h).strip()
                #skip path only entries
                if s.startswith('/'):
                    continue
                #if URL, extract hostname
                if s.startswith('http://') or s.startswith('https://'):
                    try:
                        s = urllib.parse.urlparse(s).hostname or s
                    except Exception:
                        pass
                s = s.rstrip('/')
                if s and s not in cleaned_hosts:
                    cleaned_hosts.append(s)
            ordered_hosts = cleaned_hosts
        except Exception:
            #if anything fails, keep original ordered_hosts
            pass

        #attach to report_data
        try:
            report_data['hosts_summary'] = hosts_summary
            report_data['hosts_list'] = ordered_hosts

            hosts_display: List[str] = []
            def _is_ip(s: str) -> bool:
                return bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', s))

            for ip in ordered_hosts:
                try:
                    if not isinstance(ip, str):
                        ip = str(ip)
                    #skip obvious path entries
                    if ip.startswith('/'):
                        continue

                    names = hosts_summary.get(ip) or []
                    #prefer the first hostname that is not a path
                    host_name = None
                    for hn in names:
                        if isinstance(hn, str) and hn and not hn.startswith('/'):
                            host_name = hn.strip()
                            break

                    if host_name:
                        hosts_display.append(f"{ip} ({host_name})")
                    else:
                        #if ip itself looks like a path, skip it
                        if ip.startswith('/'):
                            continue
                        hosts_display.append(ip)
                except Exception:
                    #fallback to raw ip string
                    try:
                        hosts_display.append(str(ip))
                    except Exception:
                        continue

            #remove any entries that are purely paths  and dedupe while preserving order
            final_hosts: List[str] = []
            seen = set()
            for h in hosts_display:
                if not h or (isinstance(h, str) and h.startswith('/')):
                    continue
                if h in seen:
                    continue
                seen.add(h)
                final_hosts.append(h)

            if not final_hosts:
                #ensure at least the configured target shows up
                tv = target_info.get('value') or target_info.get('name')
                if tv:
                    final_hosts = [tv]

            report_data['hosts_display_list'] = final_hosts

            #build hosts_with_type and hosts_display_with_type (mark IP vs Domain)
            hosts_with_type: List[Dict[str, str]] = []
            hosts_display_with_type: List[str] = []
            target_type_set = set()
            import ipaddress as _ipaddr
            for disp in final_hosts:
                #extract base host (strip optional ' (hostname)')
                base = disp.split(' (')[0]
                h_type = 'domain'
                try:
                    #valid IPv4 or IPv6
                    _ipaddr.ip_address(base)
                    h_type = 'ip'
                except Exception:
                    h_type = 'domain'
                hosts_with_type.append({'host': base, 'display': disp, 'type': h_type})
                target_type_set.add(h_type)
                hosts_display_with_type.append(f"{disp} [{('IP' if h_type=='ip' else 'Domain')}]")

            report_data['hosts_with_type'] = hosts_with_type
            report_data['hosts_display_with_type'] = hosts_display_with_type
            report_data['target_types'] = list(target_type_set)

            #collect tool versions now that report_data exists
            report_data['tool_versions'] = self._collect_tool_versions(nmap_data, nikto_data) or {}

            #add fallback default tool versions so template can show versions even if tool_versions is missing
            report_data['default_tool_versions'] = [
                {'name': 'nmap', 'version': '7.98'},
                {'name': 'nikto', 'version': '2.1.6'}
            ]

            #ensure tool_versions contains sensible defaults when a tool was run but its version couldn't be detected
            '''
            try:
                if 'nmap' not in report_data['tool_versions'] and (
                    'nmap' in report_data.get('scan_types_used', []) or nmap_data.get('hosts') or nmap_data.get('findings')
                ):
                    report_data['tool_versions']['nmap'] = report_data['default_tool_versions']['nmap']

                if 'nikto' not in report_data['tool_versions'] and (
                    'nikto' in report_data.get('scan_types_used', []) or nikto_data.get('findings')
                ):
                    report_data['tool_versions']['nikto'] = report_data['default_tool_versions']['nikto']
            except Exception:
                pass
            '''

            #detect which scan types were actually used across findings and hosts
            scan_types_used = set()
            hosts_with_type = {}
            hosts_display_with_type = []
            target_types = {}

            for host_meta in report_data.get('hosts', []):
                host = host_meta.get('host')
                types = host_meta.get('scan_types', []) or []
                hosts_with_type[host] = types
                target_types[host] = host_meta.get('target_type', 'ip')
                display = host
                if types:
                    display = f"{host} ({', '.join(types)})"
                    for t in types:
                        scan_types_used.add(t)
                hosts_display_with_type.append(display)

            #if scan_types isn't explicitly provided, fall back to detected ones
            if not report_data.get('scan_types_used'):
                report_data['scan_types_used'] = sorted(list(scan_types_used))

            report_data['hosts_with_type'] = hosts_with_type
            report_data['hosts_display_with_type'] = hosts_display_with_type
            report_data['target_types'] = target_types

            #normalize any precomputed scan_types_used (do not overwrite from empty host data)
            if report_data.get('scan_types_used'):
                try:
                    report_data['scan_types_used'] = [t.lower() for t in dict.fromkeys(report_data['scan_types_used'])]
                except Exception:
                    report_data['scan_types_used'] = [str(t).lower() for t in report_data.get('scan_types_used', [])]
            else:
                report_data['scan_types_used'] = normalized_tools

            report_data.setdefault('hosts_with_type', report_data.get('hosts_with_type', {}))
            report_data.setdefault('hosts_display_with_type', report_data.get('hosts_display_with_type', []))
            report_data.setdefault('target_types', report_data.get('target_types', {}))

            try:
                start = report_data.get('scan_start')
                end = report_data.get('scan_end')
                if start and end:
                    def parse_iso(s):
                        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
                            try:
                                return datetime.strptime(s, fmt)
                            except Exception:
                                continue
                        try:
                            return datetime.fromisoformat(s)
                        except Exception:
                            return None

                    sdt = parse_iso(start) if isinstance(start, str) else start
                    edt = parse_iso(end) if isinstance(end, str) else end
                    if sdt and edt:
                        delta = edt - sdt
                        total_seconds = int(delta.total_seconds())
                        hours, remainder = divmod(total_seconds, 3600)
                        minutes, seconds = divmod(remainder, 60)
                        report_data['scan_duration'] = f"{hours}h {minutes}m {seconds}s"
            except Exception:
                #keep whatever scan_duration was present
                pass

            logger.info(f"Hosts list and summary built: {report_data['hosts_list']}, {report_data['hosts_summary']}")
        except Exception:
            logger.exception("Failed to build hosts list/summary")

        return report_data

    def _detect_target_type(self, target_value: str) -> str:
        if not target_value:
            return 'unknown'
        t = target_value.strip()
        #cidr notation
        if '/' in t:
            return 'ip_range'
        #dash range 
        if '-' in t and any(ch.isdigit() for ch in t):
            return 'ip_range'
        #simple IPv4
        ipv4_re = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
        try:
            import re as _re
            if _re.match(ipv4_re, t):
                return 'ip'
        except Exception:
            pass
        return 'domain'

    def _normalize_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        #normalize titles like "Finding 013587" -> "Finding 13587" and strip leading zeros from ids
        title = finding.get('title') or ''
        m = re.match(r'^(Finding)\s+0+(\d+)', title)
        if m:
            finding['title'] = f"{m.group(1)} {m.group(2)}"
        return finding

    def _group_findings_by_host(self, findings: List[Dict[str, Any]], nmap_data: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        host_map: Dict[str, List[Dict[str, Any]]] = {}
        #create host list from nmap_data if available
        hosts: List[str] = []
        for h in nmap_data.get('hosts', []) or []:
            #1) prefer explicit ip field if present
            ip_val = None
            if isinstance(h, dict):
                ip_val = h.get('ip') or h.get('ipv4') or h.get('ipv6')
                #2) addresses may be a dict or a list of dicts
                addrs = h.get('addresses')
                if not ip_val and addrs:
                    #dict mapping types to values
                    if isinstance(addrs, dict):
                        #pick first usable address (ipv4 then ipv6 then any)
                        ip_val = addrs.get('ipv4') or addrs.get('ipv6') or next(iter(addrs.values()), None)
                    elif isinstance(addrs, list):
                        for a in addrs:
                            if isinstance(a, dict) and a.get('addr'):
                                ip_val = a.get('addr')
                                break
                            #sometimes list may contain plain strings
                            if isinstance(a, str) and a:
                                ip_val = a
                                break
                #final fallback: if host contains a list of hostnames, try first
                if not ip_val:
                    hostnames = h.get('hostnames') or []
                    if hostnames:
                        #hostnames may be list of strings or dicts
                        first = hostnames[0]
                        if isinstance(first, dict):
                            ip_val = first.get('name')
                        elif isinstance(first, str):
                            ip_val = first
            #if we couldn't find a usable address, skip
            if ip_val:
                hosts.append(str(ip_val))

        #assign findings to hosts if affected_component contains host address or port
        for f in findings or []:
            assigned = False
            affected = (f.get('affected_component') or '')
            #normalize affected to string
            if not isinstance(affected, str):
                try:
                    affected = str(affected)
                except Exception:
                    affected = ''

            for h in hosts:
                if h and h in affected:
                    host_map.setdefault(h, []).append(f)
                    assigned = True
                    break
            if not assigned:
                host_map.setdefault('global', []).append(f)

        return host_map

    def _find_results_file(self, results_paths: List[str], scan_type: str) -> Optional[str]:
        if isinstance(results_paths, str):
            results_paths = [results_paths]

        for path in results_paths:
            if not path:
                continue

            if os.path.exists(path):
                base_name = os.path.basename(path).lower()
                if scan_type.lower() in base_name:
                    return path

                if scan_type == 'nmap' and path.endswith('.xml'):
                    return path

                if scan_type == 'nikto' and (path.endswith('.txt') or path.endswith('.csv') or path.endswith('.json')):
                    return path

        if len(results_paths) == 1 and results_paths[0] and os.path.exists(results_paths[0]):
            return results_paths[0]

        return None

    def _find_results_files(self, results_paths: List[str], scan_type: str) -> List[str]:
        #return all matching files for a given scan_type
        matches: List[str] = []
        if isinstance(results_paths, str):
            results_paths = [results_paths]

        for path in results_paths:
            if not path:
                continue
            if not os.path.exists(path):
                continue
            base_name = os.path.basename(path).lower()
            if scan_type.lower() in base_name:
                matches.append(path)
                continue
            if scan_type == 'nmap' and path.endswith('.xml'):
                matches.append(path)
                continue
            if scan_type == 'nikto' and (path.endswith('.txt') or path.endswith('.csv') or path.endswith('.json')):
                matches.append(path)
                continue

        #fallback: if only one path provided, return it
        if not matches and len(results_paths) == 1 and os.path.exists(results_paths[0]):
            return [results_paths[0]]

        return matches

    def _get_scan_type_display(self, scan_type: str) -> str:
        display_names = {
            'nmap': 'Network and Port Scan (Nmap)',
            'nikto': 'Web Vulnerability Scan (Nikto)',
            'full': 'Comprehensive Scan (Nmap + Nikto)',
            'comprehensive': 'Comprehensive Scan (Nmap + Nikto)',
            'partial': 'Partial Scan'
        }
        return display_names.get(scan_type.lower(), scan_type.upper())

    def _calculate_duration(self, start_time: str, end_time: str) -> str:
        try:
            if not start_time or not end_time:
                return 'Unknown'

            def _parse_timestamp(ts: str) -> datetime:
                if isinstance(ts, datetime):
                    return ts
                s = str(ts).strip()
                try:
                    return datetime.fromisoformat(s)
                except Exception:
                    pass

                #fallback formats
                patterns = [
                    '%Y-%m-%dT%H:%M:%S.%f%z',
                    '%Y-%m-%dT%H:%M:%SZ',
                    '%Y-%m-%dT%H:%M:%S.%f',
                    '%Y-%m-%dT%H:%M:%S',
                    '%Y-%m-%d %H:%M:%S'
                ]
                for fmt in patterns:
                    try:
                        return datetime.strptime(s, fmt)
                    except Exception:
                        continue

                #give up
                raise ValueError(f'Unrecognized timestamp format: {s}')

            start_dt = _parse_timestamp(start_time)
            end_dt = _parse_timestamp(end_time)

            #normalize timezone handling, convert any aware datetimes to UTC and make naive
            if start_dt.tzinfo is not None and end_dt.tzinfo is not None:
                start_dt = start_dt.astimezone(timezone.utc).replace(tzinfo=None)
                end_dt = end_dt.astimezone(timezone.utc).replace(tzinfo=None)
            else:
                #if only one is aware, convert the aware one to UTC and drop tz for safe subtraction
                if start_dt.tzinfo is not None:
                    start_dt = start_dt.astimezone(timezone.utc).replace(tzinfo=None)
                if end_dt.tzinfo is not None:
                    end_dt = end_dt.astimezone(timezone.utc).replace(tzinfo=None)

            duration = end_dt - start_dt

            #negative durations are unexpected
            if duration.total_seconds() < 0:
                return 'Unknown'

            total_seconds = int(duration.total_seconds())
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            seconds = total_seconds % 60

            parts = []
            if hours > 0:
                parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
            if minutes > 0:
                parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
            #show seconds when present or when duration is less than a minute
            if seconds > 0 or not parts:
                parts.append(f"{seconds} second{'s' if seconds != 1 else ''}")

            return ', '.join(parts)
        except Exception as e:
            logger.warning(f"Failed to calculate duration: {e}")
            return 'Unknown'

    def _render_html_template(self, report_data: Dict[str, Any]) -> str:
        try:
            template = self.env.get_template('report_template.html')
            html_content = template.render(**report_data)
            return html_content
        except Exception as e:
            logger.error(f"Template rendering failed: {e}")
            raise

    def _save_html_report(self, html_content: str, scan_id: int) -> str:
        #remove any previous reports for this scan to avoid duplicates and conserve storage
        try:
            patterns = [
                os.path.join(self.reports_dir, f"cyberclinic_report_{scan_id}_*.html"),
                os.path.join(self.reports_dir, f"report_{scan_id}.html")
            ]
            for pat in patterns:
                for old in glob.glob(pat):
                    try:
                        os.remove(old)
                        logger.info(f"Removed old HTML report: {old}")
                    except Exception:
                        logger.exception(f"Failed removing old report: {old}")
        except Exception:
            logger.exception('Failed cleaning up old reports')

        #write new timestamped report
        filename = f"cyberclinic_report_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join(self.reports_dir, filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)

        logger.info(f"HTML report saved: {filepath}")
        return filepath

    def _save_json_report(self, report_data: Dict[str, Any], scan_id: int) -> str:
        #use consistent frontend friendly name: report_<id>.json
        filename = f"report_{scan_id}.json"
        filepath = os.path.join(self.reports_dir, filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=True)

        logger.info(f"JSON report saved: {filepath}")
        return filepath

    def _save_csv_report(self, report_data: Dict[str, Any], scan_id: int) -> str:
        filename = f"{scan_id}.csv"
        filepath = os.path.join(self.reports_dir, filename)

        fieldnames = [
            'severity', 'cvss_score', 'title', 'type', 'affected_component',
            'description', 'recommendation', 'source', 'references', 'cves'
        ]

        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for finding in report_data.get('findings', []):
                writer.writerow({
                    'severity': finding.get('severity', ''),
                    'cvss_score': finding.get('cvss', {}).get('score', ''),
                    'title': finding.get('title', ''),
                    'type': finding.get('type', ''),
                    'affected_component': finding.get('affected_component', ''),
                    'description': finding.get('description', ''),
                    'recommendation': finding.get('recommendation', ''),
                    'source': finding.get('source', ''),
                    'references': ', '.join(finding.get('references', []) or []),
                    'cves': ', '.join(finding.get('cves', []) or [])
                })

        logger.info(f"CSV report saved: {filepath}")
        return filepath

    def _convert_to_pdf(self, html_path: str, scan_id: int) -> str:
        try:
            from weasyprint import HTML

            pdf_filename = f"cyberclinic_report_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            pdf_path = os.path.join(self.reports_dir, pdf_filename)

            HTML(filename=html_path).write_pdf(pdf_path)

            logger.info(f"PDF report generated: {pdf_path}")
            return pdf_path
        except ImportError:
            logger.warning("WeasyPrint not installed - PDF generation unavailable")
            logger.warning("Install with: pip install weasyprint")
            return html_path
        except Exception as e:
            logger.error(f"PDF conversion failed: {e}")
            return html_path

    def _aggregate_services(self, nmap_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        services = {}
        for host in nmap_data.get('hosts', []):
            for port in host.get('ports', []):
                if port.get('state') != 'open':
                    continue
                service = port.get('service', {}) or {}
                key = (
                    port.get('port'),
                    port.get('protocol'),
                    service.get('name'),
                    service.get('product'),
                    service.get('version')
                )
                services.setdefault(key, 0)
                services[key] += 1

        summary = []
        for (port, protocol, name, product, version), count in services.items():
            summary.append({
                'port': port,
                'protocol': protocol,
                'service': name or 'unknown',
                'product': product or '',
                'version': version or '',
                'count': count
            })

        return sorted(summary, key=lambda item: (item['port'] or 0, item['service']))

    def _aggregate_finding_types(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for finding in findings:
            finding_type = finding.get('type', 'unknown')
            counts[finding_type] = counts.get(finding_type, 0) + 1
        return counts

    def _collect_tool_versions(self, nmap_data: Dict[str, Any], nikto_data: Dict[str, Any]) -> List[Dict[str, str]]:
        versions = []
        nmap_info = nmap_data.get('scan_info', {}) or {}
        #try common keys first
        if nmap_info.get('version'):
            v = nmap_info['version']
            versions.append({'name': 'nmap', 'version': v})
            print(f'nmap version: {v}')
        elif nmap_info.get('nmap_version'):
            v = nmap_info['nmap_version']
            versions.append({'name': 'nmap', 'version': v})
            print(f'nmap version: {v}')
        else:
            #fallback to attempt to detect nmap version from environment
            try:
                nmap_exec = shutil.which('nmap')
                if not nmap_exec:
                    for p in ['/usr/bin/nmap', '/usr/local/bin/nmap']:
                        if os.path.exists(p):
                            nmap_exec = p
                            break
                if nmap_exec:
                    proc = subprocess.run([nmap_exec, '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
                    output = (proc.stdout or '') + '\n' + (proc.stderr or '')
                    m = re.search(r'nmap\s+([0-9]+(?:\.[0-9]+)+)', output, re.IGNORECASE)
                    if m:
                        versions.append({'name': 'nmap', 'version': m.group(1)})
            except Exception:
                pass
        #if still missing, try to search any scan_info values for a version pattern
        '''
        if 'nmap' not in versions and nmap_info:
            try:
                for v in (nmap_info.values()):
                    if isinstance(v, str):
                        m = re.search(r'([0-9]+(?:\.[0-9]+){1,})', v)
                        if m:
                            versions['nmap'] = m.group(1)
                            break
            except Exception:
                pass
        '''
        print(versions)
        nikto_info = nikto_data.get('scan_info', {}) or {}
        if nikto_info.get('version'):
            versions.append({'name': 'nikto', 'version': nikto_info['version']})
        else:
            #fallback to try to detect nikto installed in the environment
            try:
                nikto_exec = shutil.which('nikto')
                #common fallback paths used in Dockerfile
                if not nikto_exec:
                    for p in ['/usr/local/bin/nikto', '/opt/nikto/program/nikto.pl']:
                        if os.path.exists(p):
                            nikto_exec = p
                            break

                if nikto_exec:
                    proc = subprocess.run([nikto_exec, '-Version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
                    output = (proc.stdout or '') + '\n' + (proc.stderr or '')
                    #common version patterns
                    m = re.search(r'Nikto\s*[vV]?\s*([0-9]+(?:\.[0-9]+)+)', output)
                    if not m:
                        m = re.search(r'([0-9]+(?:\.[0-9]+)+)', output)
                    if m:
                        versions.append({'name': 'nikto', 'version': m.group(1)})
            except Exception:
                #best effort only, do not fail report generation
                pass
        print(versions)
        return versions

    def _build_host_map(self, nmap_hosts: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Return a mapping of primary IP/address -> list of hostnames (without trailing dots)."""
        host_map: Dict[str, List[str]] = {}
        for h in nmap_hosts or []:
            ip_val = None
            if isinstance(h, dict):
                ip_val = h.get('ip') or h.get('ipv4') or h.get('ipv6')
                addrs = h.get('addresses')
                if not ip_val and addrs:
                    if isinstance(addrs, dict):
                        ip_val = addrs.get('ipv4') or addrs.get('ipv6') or next(iter(addrs.values()), None)
                    elif isinstance(addrs, list):
                        for a in addrs:
                            if isinstance(a, dict) and a.get('addr'):
                                ip_val = a.get('addr')
                                break
                            if isinstance(a, str) and a:
                                ip_val = a
                                break
                #collect hostnames
                hostnames = []
                hn_list = h.get('hostnames') or []
                for hn in hn_list:
                    if isinstance(hn, dict):
                        name = hn.get('name') or ''
                    elif isinstance(hn, str):
                        name = hn
                    else:
                        name = ''
                    name = (name or '').strip().rstrip('.')
                    if name:
                        hostnames.append(name)
                if ip_val:
                    host_map.setdefault(str(ip_val), [])
                    #keep unique hostnames preserving order
                    for n in hostnames:
                        if n not in host_map[str(ip_val)]:
                            host_map[str(ip_val)].append(n)
        return host_map

# Done by Manuel Morales-Marroquin
