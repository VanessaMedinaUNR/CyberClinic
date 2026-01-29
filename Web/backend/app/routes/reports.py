#Cyber Clinic backend - Report generation with custom HTML/PDF generator

from flask import Blueprint, request, jsonify, send_file, render_template
import os
import json
from datetime import datetime
import logging
import ipaddress

#import custom report generator
from app.report_generator import CustomReportGenerator

#import reptor client for backward compatibility (optional)
try:
    from reptor import Reptor
    REPTOR_AVAILABLE = True
except ImportError:
    REPTOR_AVAILABLE = False
    logging.warning("Reptor not available - using custom report generator only")

#import our database manager for data operations
from app.database import get_db
#create blueprint for report-related endpoints
reports_bp = Blueprint('reports', __name__, url_prefix='/api/reports')
#setup logging for report operations
logger = logging.getLogger(__name__)

#initialize custom report generator
custom_generator = CustomReportGenerator()

class ReportGenerator:
    #handles report generation using SysReptor integration
    #creates professional cybersecurity reports from scan results
    def __init__(self):
        self.reptor_client = None
        # Use relative path that works both locally and in docker
        self.reports_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'reports')
        
        #ensure reports directory exists
        os.makedirs(self.reports_dir, exist_ok=True)
        
        if REPTOR_AVAILABLE:
            self._initialize_reptor()
    
    def _initialize_reptor(self):
        #initialize connection to SysReptor server
        #uses environment variables for configuration
        try:
            server_url = os.environ.get('REPTOR_SERVER_URL')
            token = os.environ.get('REPTOR_API_TOKEN')
            
            logger.info(f"Initializing SysReptor with server: {server_url}")
            
            self.reptor_client = Reptor(server=server_url, token=token)
            logger.info("SysReptor client initialized with 'server' parameter")
            
        except Exception as e:
            logger.error(f"Failed to initialize SysReptor with all methods: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            self.reptor_client = None
    
    def generate_report(self, scan_id, report_format='pdf'):
        #generate a professional report from scan results
        #supports PDF and HTML formats
        try:
            db = get_db()
            
            #get scan details and results
            scan_data = db.execute_single(
                """SELECT sj.*, nt.subnet_name, nt.subnet_netmask, nt.subnet_ip, c.client_name, c.client_id
                   FROM scan_jobs sj 
                   JOIN network nt ON sj.client_id = nt.client_id AND sj.subnet_name = nt.subnet_name
                   JOIN client c ON sj.client_id = c.client_id
                   WHERE sj.id = %s AND sj.status = 'completed'""",
                (scan_id,)
            )
            
            if not scan_data:
                raise Exception(f"Completed scan job {scan_id} not found")
            
            admin_email = db.execute_single(
                """SELECT u.email
                FROM users u
                JOIN client_users cu ON cu.client_id = %s
                WHERE u.client_admin = TRUE LIMIT 1""",
                (scan_data['client_id'])
            )

            target_value = None
            target_type = None
            #determine target value and type
            domain = db.execute_single(
                """SELECT domain
                FROM network_domains
                WHERE client_id = %s, subnet_name = %s""",
                (scan_data['client_id'], scan_data['subnet_name'])
                )
            if domain:
                target_type = "domain"
                target_value = domain
            else:
                if scan_data["subnet_netmask"] == "255.255.255.255":
                    target_type = "ip"
                    target_value = scan_data["subnet_ip"]
                else:
                    target_type = "range"
                    subnet_ip = scan_data['subnet_ip']
                    subnet_netmask = scan_data['subnet_netmask']
                    target_value = ipaddress.IPv4Network(f'{subnet_ip}/{subnet_netmask}').compressed

            #prepare report data structure
            report_data = {
                'scan_info': {
                    'scan_id': scan_data['id'],
                    'scan_type': scan_data['scan_type'],
                    'target': {
                        'name': scan_data['subnet_name'],
                        'type': target_type,
                        'value': target_value
                    },
                    'user': {
                        'client_name': scan_data['client_name'],
                        'email': admin_email
                    },
                    'timestamps': {
                        'created': scan_data['created_at'].isoformat(),
                        'started': scan_data['started_at'].isoformat() if scan_data['started_at'] else None,
                        'completed': scan_data['completed_at'].isoformat() if scan_data['completed_at'] else None
                    }
                },
                'results': self._load_scan_results(scan_data['results_path']),
                'metadata': {
                    'report_generated': datetime.now().isoformat(),
                    'generator': 'Cyber Clinic v1.0',
                    'team': 'CS425-Team13'
                }
            }
            
            if self.reptor_client:
                #use SysReptor for professional report generation
                return self._generate_with_reptor(report_data, report_format)
            else:
                #fallback to basic report generation
                return self._generate_basic_report(report_data, report_format)
                
        except Exception as e:
            logger.error(f"Report generation failed for scan {scan_id}: {e}")
            raise
    
    def _load_scan_results(self, results_path):
        #load scan results from file system
        #handles different result formats (JSON, XML, text)
        if not results_path or not os.path.exists(results_path):
            return {
                'status': 'no_results',
                'message': 'Scan results file not found'
            }
        
        try:
            #try to load as JSON first
            with open(results_path, 'r') as f:
                if results_path.endswith('.json'):
                    return json.load(f)
                else:
                    #for other formats, return as text for now
                    return {
                        'raw_output': f.read(),
                        'format': 'text'
                    }
        except Exception as e:
            logger.error(f"Failed to load scan results from {results_path}: {e}")
            return {
                'status': 'load_error',
                'message': str(e)
            }
    
    def _generate_with_reptor(self, report_data, report_format):
        #generate professional report using SysReptor
        #creates structured cybersecurity reports
        try:
            #create reptor report project
            report_project = {
                'name': f"Cyber Clinic Scan - {report_data['scan_info']['target']['name']}",
                'scope': f"{report_data['scan_info']['target']['type']}: {report_data['scan_info']['target']['value']}",
                'tags': ['cyberclinic', report_data['scan_info']['scan_type']],
                'report_template': 'cybersecurity_assessment'
            }
            
            #upload scan data to reptor
            reptor_report = self.reptor_client.create_report(report_project)
            
            #add findings from scan results
            self._add_findings_to_reptor(reptor_report, report_data['results'])
            
            #generate final report
            report_filename = f"cyberclinic_scan_{report_data['scan_info']['scan_id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{report_format}"
            report_path = os.path.join(self.reports_dir, report_filename)
            
            reptor_report.export(report_path, format=report_format)
            
            logger.info(f"Generated report with SysReptor: {report_path}")
            return report_path
            
        except Exception as e:
            logger.error(f"SysReptor report generation failed: {e}")
            #fallback to basic report
            return self._generate_basic_report(report_data, report_format)
    
    def _generate_basic_report(self, report_data, report_format):
        #generate basic report when SysReptor is not available
        #creates simple HTML or JSON report
        try:
            scan_id = report_data['scan_info']['scan_id']
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            if report_format.lower() == 'json':
                #generate JSON report
                report_filename = f"cyberclinic_scan_{scan_id}_{timestamp}.json"
                report_path = os.path.join(self.reports_dir, report_filename)
                
                with open(report_path, 'w') as f:
                    json.dump(report_data, f, indent=2, default=str)
                    
            else:
                #generate HTML report
                report_filename = f"cyberclinic_scan_{scan_id}_{timestamp}.html"
                report_path = os.path.join(self.reports_dir, report_filename)
                
                html_content = self._generate_html_report(report_data)
                
                with open(report_path, 'w') as f:
                    f.write(html_content)
            
            logger.info(f"Generated basic report: {report_path}")
            return report_path
            
        except Exception as e:
            logger.error(f"Basic report generation failed: {e}")
            raise
    
    def _generate_html_report(self, report_data):
        #generate HTML report content
        #creates a basic but readable cybersecurity report
        scan_info = report_data['scan_info']
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Cyber Clinic Security Assessment Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; }}
                .section {{ margin: 20px 0; }}
                .finding {{ background: #f8f9fa; padding: 10px; border-left: 4px solid #007bff; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Cyber Clinic Security Assessment Report</h1>
                <p>CS 425 Team 13 - University of Nevada, Reno</p>
            </div>
            
            <div class="section">
                <h2>Scan Summary</h2>
                <table>
                    <tr><td><strong>Scan ID:</strong></td><td>{scan_info['scan_id']}</td></tr>
                    <tr><td><strong>Target:</strong></td><td>{scan_info['target']['name']} ({scan_info['target']['value']})</td></tr>
                    <tr><td><strong>Scan Type:</strong></td><td>{scan_info['scan_type']}</td></tr>
                    <tr><td><strong>User:</strong></td><td>{scan_info['user']['username']}</td></tr>
                    <tr><td><strong>Completed:</strong></td><td>{scan_info['timestamps']['completed']}</td></tr>
                </table>
            </div>
            
            <div class="section">
                <h2>Results</h2>
                <div class="finding">
                    <p><strong>Status:</strong> Report generated successfully</p>
                    <p><strong>Note:</strong> This is a basic report generated without SysReptor integration.</p>
                    <p>For detailed vulnerability analysis and professional reporting, ensure SysReptor is properly configured.</p>
                </div>
            </div>
            
            <div class="section">
                <h2>Generated By</h2>
                <p>Cyber Clinic Web Application<br>
                CS 425 - Software Engineering Project<br>
                University of Nevada, Reno<br>
                Team 13</p>
            </div>
        </body>
        </html>
        """
        
        return html_content

#create global report generator instance
report_generator = ReportGenerator()

@reports_bp.route('/viewer', methods=['GET'])
def view_reports():
    #serve the reports viewer page
    try:
        return render_template('reports_viewer.html')
    except Exception as e:
        logger.error(f"Failed to load reports viewer: {e}")
        return jsonify({'error': 'Failed to load viewer'}), 500

@reports_bp.route('/generate/<int:scan_id>', methods=['POST'])
def generate_report(scan_id):
    #generate a report for a completed scan job
    #accepts format parameter (pdf, html, json)
    try:
        data = request.get_json() or {}
        report_format = data.get('format', 'html').lower()
        
        #validate format
        valid_formats = ['pdf', 'html', 'json']
        if report_format not in valid_formats:
            return jsonify({'error': f'Invalid format. Must be one of: {", ".join(valid_formats)}'}), 400
        
        #generate report
        report_path = report_generator.generate_report(scan_id, report_format)
        
        #update database with report path
        db = get_db()
        db.execute_command(
            "UPDATE scan_jobs SET results_path = %s WHERE id = %s",
            (report_path, scan_id)
        )
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'report_path': report_path,
            'format': report_format,
            'generated_at': datetime.now().isoformat(),
            'download_url': f'/api/reports/download/{scan_id}'
        }), 201
        
    except Exception as e:
        logger.error(f"Report generation failed for scan {scan_id}: {e}")
        return jsonify({'error': 'Report generation failed'}), 500

@reports_bp.route('/download/<int:scan_id>', methods=['GET'])
def download_report(scan_id):
    #download the generated report file for a scan
    try:
        db = get_db()
        
        scan_data = db.execute_single(
            "SELECT results_path, subnet_name FROM scan_jobs sj JOIN network nt ON sj.client_id = nt.client_id WHERE sj.id = %s",
            (scan_id,)
        )
        
        if not scan_data or not scan_data['results_path']:
            return jsonify({'error': 'Report not found'}), 404
        
        report_path = scan_data['results_path']
        
        if not os.path.exists(report_path):
            return jsonify({'error': 'Report file not found'}), 404
        
        #determine appropriate filename for download
        filename = f"cyberclinic_report_{scan_data['subnet_name']}_{scan_id}.{os.path.splitext(report_path)[1][1:]}"
        
        return send_file(report_path, as_attachment=True, download_name=filename)
        
    except Exception as e:
        logger.error(f"Report download failed for scan {scan_id}: {e}")
        return jsonify({'error': 'Report download failed'}), 500

@reports_bp.route('/list', methods=['GET'])
def list_reports():
    #list all available reports
    #shows completed scans that have generated reports
    try:
        user_filter = request.args.get('user_id')
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
        
        db = get_db()
        
        #build query for completed scans with reports
        where_conditions = ["sj.status = 'completed'", "sj.results_path IS NOT NULL"]
        params = []
        
        if user_filter:
            where_conditions.append("sj.user_id = %s")
            params.append(int(user_filter))
        
        where_clause = "WHERE " + " AND ".join(where_conditions)
        params.extend([limit, offset])
        
        query = f"""
            SELECT sj.id, sj.scan_type, sj.completed_at, sj.results_path,
                   nt.subnet_name, nt.subnet_ip, nt.subnet_netmask, c.client_id c.client_name
            FROM scan_jobs sj 
            JOIN network nt ON sj.subnet_name = nt.subnet_name AND sj.client_id = nt.client_id
            JOIN users u ON sj.user_id = u.id
            {where_clause}
            ORDER BY sj.completed_at DESC
            LIMIT %s OFFSET %s
        """
        
        reports = db.execute_query(query, params)
        
        target_value = None
        target_type = None
        #determine target value and type
        domain = db.execute_single(
            """SELECT domain
            FROM network_domains
            WHERE client_id = %s, subnet_name = %s""",
            (reports['client_id'], reports['subnet_name'])
            )
        if domain:
            target_type = "domain"
            target_value = domain
        else:
            if reports["subnet_netmask"] == "255.255.255.255":
                target_type = "ip"
                target_value = reports["subnet_ip"]
            else:
                target_type = "range"
                subnet_ip = reports['subnet_ip']
                subnet_netmask = reports['subnet_netmask']
                target_value = ipaddress.IPv4Network(f'{subnet_ip}/{subnet_netmask}').compressed

        #format report list
        report_list = []
        for report in reports:
            report_list.append({
                'scan_id': report['id'],
                'scan_type': report['scan_type'],
                'target': {
                    'name': report['target_name'],
                    'type': target_type,
                    'value': target_value
                },
                'client_name': report['client_name'],
                'completed_at': report['completed_at'].isoformat(),
                'has_report': bool(report['results_path']),
                'download_url': f'/api/reports/download/{report["id"]}'
            })
        
        return jsonify({
            'reports': report_list,
            'total': len(report_list),
            'offset': offset,
            'limit': limit
        })
        
    except Exception as e:
        logger.error(f"Report listing failed: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@reports_bp.route('/debug/reptor', methods=['GET'])
def debug_reptor():
    #debug endpoint to test SysReptor initialization and connection
    try:
        # Test if reptor module is available
        if not REPTOR_AVAILABLE:
            return jsonify({
                'status': 'error',
                'message': 'Reptor module not available',
                'reptor_available': False
            })
        
        # Test initialization
        server_url = os.environ.get('REPTOR_SERVER_URL', 'http://reptor:8000')
        token = os.environ.get('REPTOR_API_TOKEN', 'dev-token')
        
        debug_info = {
            'reptor_available': REPTOR_AVAILABLE,
            'server_url': server_url,
            'token_set': bool(token and token != 'dev-token'),
            'initialization_attempts': []
        }
        
        # Try different initialization methods
        methods = [
            ('server_token', lambda: Reptor(server=server_url, token=token)),
            ('serverurl_token', lambda: Reptor(serverurl=server_url, token=token)),
            ('config_dict', lambda: Reptor(config={'server': server_url, 'token': token})),
            ('config_dict_serverurl', lambda: Reptor(config={'serverurl': server_url, 'token': token}))
        ]
        
        for method_name, init_func in methods:
            try:
                client = init_func()
                debug_info['initialization_attempts'].append({
                    'method': method_name,
                    'status': 'success',
                    'client_type': str(type(client))
                })
                # Test connection if possible
                try:
                    # Try to call a simple method if available
                    if hasattr(client, 'get_projects'):
                        projects = client.get_projects()
                        debug_info['initialization_attempts'][-1]['connection_test'] = 'success'
                    else:
                        debug_info['initialization_attempts'][-1]['connection_test'] = 'no_test_method'
                except Exception as conn_e:
                    debug_info['initialization_attempts'][-1]['connection_test'] = f'failed: {str(conn_e)}'
                break  # Use first successful method
            except Exception as e:
                debug_info['initialization_attempts'].append({
                    'method': method_name,
                    'status': 'failed',
                    'error': str(e),
                    'error_type': type(e).__name__
                })
        
        return jsonify(debug_info)
        
    except Exception as e:
        logger.error(f"Debug reptor failed: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e),
            'error_type': type(e).__name__
        }), 500

    """
    Generate a custom HTML/PDF report from scan results
    Uses the new CustomReportGenerator with Cyber Clinic branding
    
    POST /api/reports/generate/123
    {
        "format": "html"  // or "pdf"
    }
    """
    try:
        db = get_db()
        
        #get report format preference
        data = request.get_json() or {}
        report_format = data.get('format', 'html').lower()
        
        if report_format not in ['html', 'pdf']:
            return jsonify({'error': 'Invalid format. Use "html" or "pdf"'}), 400
        
        #get scan data from database
        scan_data = db.execute_single(
            """SELECT sj.*, nt.subnet_name, nt.subnet_netmask, nt.subnet_ip, c.client_name, c.client_id
               FROM scan_jobs sj 
               JOIN network nt ON sj.client_id = nt.client_id AND sj.subnet_name = nt.subnet_name
               JOIN client c ON sj.client_id = c.client_id
               WHERE sj.id = %s AND sj.status = 'completed'""",
            (scan_id,)
        )
        
        if not scan_data:
            return jsonify({'error': f'Completed scan {scan_id} not found'}), 404
        
        #get admin email
        admin_email = db.execute_single(
            """SELECT u.email
            FROM users u
            JOIN client_users cu ON cu.user_id = u.user_id
            WHERE cu.client_id = %s AND u.client_admin = TRUE 
            LIMIT 1""",
            (scan_data['client_id'],)
        )
        
        #determine target value and type
        domain_result = db.execute_single(
            """SELECT domain
            FROM network_domains
            WHERE client_id = %s AND subnet_name = %s""",
            (scan_data['client_id'], scan_data['subnet_name'])
        )
        
        if domain_result:
            target_type = "domain"
            target_value = domain_result['domain']
        else:
            if scan_data["subnet_netmask"] == "255.255.255.255":
                target_type = "ip"
                target_value = scan_data["subnet_ip"]
            else:
                target_type = "range"
                subnet_ip = scan_data['subnet_ip']
                subnet_netmask = scan_data['subnet_netmask']
                target_value = str(ipaddress.IPv4Network(f'{subnet_ip}/{subnet_netmask}'))
        
        #prepare data for custom report generator
        report_data = {
            'scan_id': scan_data['id'],
            'scan_type': scan_data['scan_type'],
            'target': {
                'value': target_value,
                'name': scan_data['subnet_name'],
                'type': target_type
            },
            'client': {
                'name': scan_data['client_name'],
                'email': admin_email['email'] if admin_email else 'contact@cyberclinic.unr.edu'
            },
            'timestamps': {
                'started': scan_data['started_at'].isoformat() if scan_data['started_at'] else None,
                'completed': scan_data['completed_at'].isoformat() if scan_data['completed_at'] else None
            },
            'results_paths': [scan_data['results_path']] if scan_data['results_path'] else []
        }
        
        #generate report using custom generator
        logger.info(f"Generating custom {report_format} report for scan {scan_id}")
        report_path = custom_generator.generate_report(report_data, output_format=report_format)
        
        #update database with report path
        db.execute_command(
            "UPDATE scan_jobs SET results_path = %s WHERE id = %s",
            (report_path, scan_id)
        )
        
        return jsonify({
            'message': 'Report generated successfully',
            'scan_id': scan_id,
            'format': report_format,
            'report_path': report_path,
            'download_url': f'/api/reports/download/{scan_id}'
        }), 201
        
    except Exception as e:
        logger.error(f"Custom report generation failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({
            'error': 'Report generation failed',
            'details': str(e)
        }), 500
@reports_bp.route('/available', methods=['GET'])
def list_available_reports():
    #list all available reports in the reports folder
    #allows users to view and download generated reports
    try:
        reports_dir = os.path.join(os.path.dirname(__file__), '..', 'reports')
        
        if not os.path.exists(reports_dir):
            return jsonify({
                'message': 'Reports directory not found',
                'reports': []
            }), 200
        
        reports = []
        
        #scan reports folder for HTML and PDF files
        for filename in os.listdir(reports_dir):
            if filename.endswith(('.html', '.pdf')):
                filepath = os.path.join(reports_dir, filename)
                
                #get file info
                file_stat = os.stat(filepath)
                file_size_mb = file_stat.st_size / (1024 * 1024)  #convert to MB
                
                #extract report info from filename
                #format: cyberclinic_report_<scan_id>_<timestamp>.<ext>
                parts = filename.replace('cyberclinic_report_', '').replace('.html', '').replace('.pdf', '').split('_')
                
                report_info = {
                    'filename': filename,
                    'file_type': filename.split('.')[-1].upper(),
                    'size_mb': round(file_size_mb, 2),
                    'created': datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                    'download_url': f'/api/reports/download-file/{filename}'
                }
                
                #try to extract scan ID if available
                if len(parts) > 0:
                    try:
                        report_info['scan_id'] = parts[0]
                    except:
                        pass
                
                reports.append(report_info)
        
        #sort by creation date descending
        reports.sort(key=lambda x: x['created'], reverse=True)
        
        return jsonify({
            'message': f'Found {len(reports)} reports',
            'count': len(reports),
            'reports': reports
        }), 200
        
    except Exception as e:
        logger.error(f"Failed to list available reports: {e}")
        return jsonify({
            'error': 'Failed to list reports',
            'details': str(e)
        }), 500

@reports_bp.route('/download-file/<filename>', methods=['GET'])
def download_report_file(filename):
    #download a specific report file from the reports folder
    try:
        reports_dir = os.path.join(os.path.dirname(__file__), '..', 'reports')
        filepath = os.path.join(reports_dir, filename)
        
        #security check: ensure file is in reports directory
        if not os.path.abspath(filepath).startswith(os.path.abspath(reports_dir)):
            return jsonify({'error': 'Invalid file path'}), 400
        
        if not os.path.exists(filepath):
            return jsonify({'error': 'Report file not found'}), 404
        
        return send_file(filepath, as_attachment=True, download_name=filename)
        
    except Exception as e:
        logger.error(f"Report file download failed for {filename}: {e}")
        return jsonify({
            'error': 'File download failed',
            'details': str(e)
        }), 500
        
        # Done by Morales-Marroquin and Austin Finch
