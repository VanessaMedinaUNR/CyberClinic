#Cyber Clinic backend - Report generation and SysReptor integration

from flask import Blueprint, request, jsonify, send_file
import os
import json
from datetime import datetime
import logging

#import reptor client for report generation
try:
    from reptor import Reptor
    REPTOR_AVAILABLE = True
except ImportError:
    REPTOR_AVAILABLE = False
    logging.warning("Reptor not available - report generation will use placeholders")

#import our database manager for data operations
from app.database import get_db

#create blueprint for report-related endpoints
reports_bp = Blueprint('reports', __name__, url_prefix='/api/reports')

#setup logging for report operations
logger = logging.getLogger(__name__)

class ReportGenerator:
    #handles report generation using SysReptor integration
    #creates professional cybersecurity reports from scan results
    
    def __init__(self):
        self.reptor_client = None
        self.reports_dir = '/app/reports'  #docker volume mount path
        
        #ensure reports directory exists
        os.makedirs(self.reports_dir, exist_ok=True)
        
        if REPTOR_AVAILABLE:
            self._initialize_reptor()
    
    def _initialize_reptor(self):
        #initialize connection to SysReptor server
        #uses environment variables for configuration
        try:
            reptor_config = {
                'server_url': os.environ.get('REPTOR_SERVER_URL', 'http://reptor:8000'),
                'api_token': os.environ.get('REPTOR_API_TOKEN', 'dev-token'),
                'project_id': os.environ.get('REPTOR_PROJECT_ID', 'cyberclinic')
            }
            
            self.reptor_client = Reptor(**reptor_config)
            logger.info("SysReptor client initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize SysReptor: {e}")
            self.reptor_client = None
    
    def generate_report(self, scan_id, report_format='pdf'):
        #generate a professional report from scan results
        #supports PDF and HTML formats
        try:
            db = get_db()
            
            #get scan details and results
            scan_data = db.execute_single(
                """SELECT sj.*, nt.target_name, nt.target_type, nt.target_value, u.username, u.email
                   FROM scan_jobs sj 
                   JOIN network_targets nt ON sj.target_id = nt.id
                   JOIN users u ON sj.user_id = u.id
                   WHERE sj.id = %s AND sj.status = 'completed'""",
                (scan_id,)
            )
            
            if not scan_data:
                raise Exception(f"Completed scan job {scan_id} not found")
            
            #prepare report data structure
            report_data = {
                'scan_info': {
                    'scan_id': scan_data['id'],
                    'scan_type': scan_data['scan_type'],
                    'target': {
                        'name': scan_data['target_name'],
                        'type': scan_data['target_type'],
                        'value': scan_data['target_value']
                    },
                    'user': {
                        'username': scan_data['username'],
                        'email': scan_data['email']
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
            "SELECT results_path, target_name FROM scan_jobs sj JOIN network_targets nt ON sj.target_id = nt.id WHERE sj.id = %s",
            (scan_id,)
        )
        
        if not scan_data or not scan_data['results_path']:
            return jsonify({'error': 'Report not found'}), 404
        
        report_path = scan_data['results_path']
        
        if not os.path.exists(report_path):
            return jsonify({'error': 'Report file not found'}), 404
        
        #determine appropriate filename for download
        filename = f"cyberclinic_report_{scan_data['target_name']}_{scan_id}.{os.path.splitext(report_path)[1][1:]}"
        
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
                   nt.target_name, nt.target_type, nt.target_value, u.username
            FROM scan_jobs sj 
            JOIN network_targets nt ON sj.target_id = nt.id
            JOIN users u ON sj.user_id = u.id
            {where_clause}
            ORDER BY sj.completed_at DESC
            LIMIT %s OFFSET %s
        """
        
        reports = db.execute_query(query, params)
        
        #format report list
        report_list = []
        for report in reports:
            report_list.append({
                'scan_id': report['id'],
                'scan_type': report['scan_type'],
                'target': {
                    'name': report['target_name'],
                    'type': report['target_type'],
                    'value': report['target_value']
                },
                'user': report['username'],
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
