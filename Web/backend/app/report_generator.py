#Cyber clinic - custom report generator
#Generates professional html/pdf security assessment reports

import os
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from jinja2 import Environment, FileSystemLoader, select_autoescape
from app.parsers.nmap_parser import NmapParser
from app.parsers.nikto_parser import NiktoParser
from app.severity_mapper import SeverityMapper

logger = logging.getLogger(__name__)

class CustomReportGenerator:
    #generate custom html/pdf security assessment reports
    
    def __init__(self):
        #setup jinja2 template environment
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )
        #initialize parsers and mappers
        self.nmap_parser = NmapParser()
        self.nikto_parser = NiktoParser()
        self.severity_mapper = SeverityMapper()
        #reports output directory
        self.reports_dir = os.path.join(os.path.dirname(__file__), '..', 'reports')
        os.makedirs(self.reports_dir, exist_ok=True)
    
    def generate_report(self, scan_data: Dict[str, Any], output_format: str = 'html') -> str:
        try:
            logger.info(f"Generating {output_format.upper()} report for scan {scan_data.get('scan_id')}")
            #extract and parse scan results
            report_data = self._prepare_report_data(scan_data)
            #generate HTML from template
            html_content = self._render_html_template(report_data)
            #save HTML report
            html_path = self._save_html_report(html_content, scan_data.get('scan_id'))
            
            if output_format == 'pdf':
                #convert to PDF if requested
                pdf_path = self._convert_to_pdf(html_path, scan_data.get('scan_id'))
                logger.info(f"Report generated successfully: {pdf_path}")
                return pdf_path
            
            logger.info(f"Report generated successfully: {html_path}")
            return html_path
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            raise
    
    def _prepare_report_data(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        #prepare all data needed for report template
        #extract basic scan info
        scan_id = scan_data.get('scan_id')
        scan_type = scan_data.get('scan_type', 'unknown')
        target_info = scan_data.get('target', {})
        client_info = scan_data.get('client', {})
        timestamps = scan_data.get('timestamps', {})
        results_paths = scan_data.get('results_paths', [])
        #parse scan results based on type
        all_findings = []
        scan_types_used = []
        nmap_data = {}
        nikto_data = {}
        
        if scan_type.lower() in ['nmap', 'full']:
            nmap_results = self._find_results_file(results_paths, 'nmap')
            if nmap_results:
                scan_types_used.append('nmap')
                nmap_data = self.nmap_parser.parse_file(nmap_results)
                all_findings.extend(nmap_data.get('findings', []))
        
        if scan_type.lower() in ['nikto', 'full']:
            nikto_results = self._find_results_file(results_paths, 'nikto')
            if nikto_results:
                scan_types_used.append('nikto')
                nikto_data = self.nikto_parser.parse_file(nikto_results)
                all_findings.extend(nikto_data.get('findings', []))
        
        #enrich findings with CVSS scores and severity data
        enriched_findings = []
        for finding in all_findings:
            enriched = self.severity_mapper.enrich_finding(finding)
            enriched_findings.append(enriched)
        
        #sort findings by priority 
        sorted_findings = self.severity_mapper.sort_findings(enriched_findings)
        
        #calculate statistics
        finding_stats = self.severity_mapper.aggregate_findings_stats(sorted_findings)
        
        #determine scan type display name
        scan_type_display = self._get_scan_type_display(scan_type)
        
        #calculate scan duration
        scan_duration = self._calculate_duration(
            timestamps.get('started'),
            timestamps.get('completed')
        )
        
        #prepare report data
        report_data = {
            #report metadata
            'report_title': f"Security Assessment - {target_info.get('name', 'Unknown Target')}",
            'report_date': datetime.now().strftime('%B %d, %Y'),
            'scan_date': timestamps.get('completed', datetime.now().strftime('%Y-%m-%d')),
            'is_draft': False,
            #client information
            'client_name': client_info.get('name', 'Unknown Organization'),
            'contact_email': client_info.get('email', 'contact@cyberclinic.unr.edu'),
            #target information
            'target_value': target_info.get('value', 'Unknown'),
            'target_type': target_info.get('type', 'unknown'),
            'target_name': target_info.get('name', 'Unknown'),
            #scan information
            'scan_type': scan_type,
            'scan_type_display': scan_type_display,
            'scan_types_used': scan_types_used,
            'scan_duration': scan_duration,
            'hosts_scanned': nmap_data.get('total_hosts', 1),
            #findings
            'findings': sorted_findings,
            'finding_stats': finding_stats,
            'overall_risk': finding_stats.get('overall_risk', 'Unknown'),
            #additional data
            'nmap_data': nmap_data,
            'nikto_data': nikto_data
        }
        
        return report_data
    
    def _find_results_file(self, results_paths: List[str], scan_type: str) -> Optional[str]:
        #find results file for a specific scan type
        if isinstance(results_paths, str):
            results_paths = [results_paths]
        
        for path in results_paths:
            if not path:
                continue
            
            #check if file exists
            if os.path.exists(path):
                #check if filename contains scan type
                if scan_type.lower() in os.path.basename(path).lower():
                    return path
                
                #for nmap, check for .xml extension
                if scan_type == 'nmap' and path.endswith('.xml'):
                    return path
                
                #for nikto, check for .txt or .csv
                if scan_type == 'nikto' and (path.endswith('.txt') or path.endswith('.csv')):
                    return path
        
        #if single path provided, assume it's the right one
        if len(results_paths) == 1 and results_paths[0] and os.path.exists(results_paths[0]):
            return results_paths[0]
        
        return None
    
    def _get_scan_type_display(self, scan_type: str) -> str:
        #get display friendly scan type name
        display_names = {
            'nmap': 'Network and Port Scan (Nmap)',
            'nikto': 'Web Vulnerability Scan (Nikto)',
            'full': 'Comprehensive Scan (Nmap + Nikto)'
        }
        return display_names.get(scan_type.lower(), scan_type.upper())
    
    def _calculate_duration(self, start_time: str, end_time: str) -> str:
        #calculate and format scan duration
        try:
            if not start_time or not end_time:
                return 'Unknown'
            
            #parse timestamps 
            for fmt in ['%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S.%f']:
                try:
                    start_dt = datetime.strptime(start_time.split('.')[0], fmt)
                    end_dt = datetime.strptime(end_time.split('.')[0], fmt)
                    break
                except ValueError:
                    continue
            else:
                return 'Unknown'
            
            duration = end_dt - start_dt
            
            #format duration nicely
            total_seconds = int(duration.total_seconds())
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            seconds = total_seconds % 60
            
            parts = []
            if hours > 0:
                parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
            if minutes > 0:
                parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
            if seconds > 0 or not parts:
                parts.append(f"{seconds} second{'s' if seconds != 1 else ''}")
            
            return ', '.join(parts)
            
        except Exception as e:
            logger.warning(f"Failed to calculate duration: {e}")
            return 'Unknown'
    
    def _render_html_template(self, report_data: Dict[str, Any]) -> str:
        #render html report from template
        try:
            template = self.env.get_template('report_template.html')
            html_content = template.render(**report_data)
            return html_content
        except Exception as e:
            logger.error(f"Template rendering failed: {e}")
            raise
    
    def _save_html_report(self, html_content: str, scan_id: int) -> str:
        #save html report to file
        filename = f"cyberclinic_report_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join(self.reports_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report saved: {filepath}")
        return filepath
    
    def _convert_to_pdf(self, html_path: str, scan_id: int) -> str:
        #convert html report to pdf using weasyprint
        try:
            from weasyprint import HTML
            
            pdf_filename = f"cyberclinic_report_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            pdf_path = os.path.join(self.reports_dir, pdf_filename)
            
            #convert HTML to PDF
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
    
    def generate_quick_report(self, scan_id: int, scan_type: str, target: str, 
                            results_path: str, client_name: str = 'Test Client',
                            contact_email: str = 'test@example.com') -> str:
        #quick report generation helper for testing
        scan_data = {
            'scan_id': scan_id,
            'scan_type': scan_type,
            'target': {
                'value': target,
                'name': target,
                'type': 'domain' if '.' in target and not target.replace('.', '').isdigit() else 'ip'
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
        
        return self.generate_report(scan_data, output_format='html')

#done by Morales-Marroquin
