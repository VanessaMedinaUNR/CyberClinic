#Cyber Clinic backend - Standalone application integration handler

from flask import Blueprint, request, jsonify
import subprocess
import json
import os
import logging
from datetime import datetime

#import our database manager for updating scan status
from app.database import get_db

#create blueprint for standalone app integration
standalone_bp = Blueprint('standalone', __name__, url_prefix='/api/standalone')

#setup logging for standalone operations
logger = logging.getLogger(__name__)

class StandaloneAppHandler:
    #handles integration with the standalone cybersecurity scanning application
    #manages communication between web backend and standalone app
    
    def __init__(self):
        self.standalone_app_path = os.environ.get('STANDALONE_APP_PATH', '/src/standalone')
        # Use relative path that works both locally and in docker
        default_path = os.path.join(os.path.dirname(__file__), '..', '..', 'results')
        self.scan_results_path = os.environ.get('SCAN_RESULTS_PATH', default_path)
        
        #ensure directories exist
        os.makedirs(self.scan_results_path, exist_ok=True)
    
    def execute_scan(self, scan_job_id, target_info, scan_config):
        #execute a scan using the standalone application
        #this is a placeholder until the standalone app is complete
        try:
            logger.info(f"Starting scan execution for job {scan_job_id}")
            
            #update scan status to running
            db = get_db()
            db.execute_command(
                "UPDATE scan_jobs SET status = 'running', started_at = CURRENT_TIMESTAMP WHERE id = %s",
                (scan_job_id,)
            )
            
            #prepare scan configuration file
            scan_config_file = os.path.join(self.scan_results_path, f"config_{scan_job_id}.json")
            
            config_data = {
                'scan_id': scan_job_id,
                'target': target_info,
                'scan_type': scan_config.get('scan_type', 'nmap'),
                'options': scan_config.get('scan_options', {}),
                'output_path': os.path.join(self.scan_results_path, f"results_{scan_job_id}.json")
            }
            
            with open(scan_config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            #check if standalone app exists
            if not os.path.exists(self.standalone_app_path):
                #placeholder execution for development
                return self._placeholder_scan_execution(scan_job_id, config_data)
            
            #execute standalone application
            command = [
                'python3', 
                os.path.join(self.standalone_app_path, 'main.py'),
                '--config', scan_config_file
            ]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=3600
            )
            
            if result.returncode == 0:
                #scan completed successfully
                results_path = config_data['output_path']
                
                db.execute_command(
                    """UPDATE scan_jobs 
                       SET status = 'completed', completed_at = CURRENT_TIMESTAMP, results_path = %s 
                       WHERE id = %s""",
                    (results_path, scan_job_id)
                )
                
                logger.info(f"Scan {scan_job_id} completed successfully")
                return {'success': True, 'results_path': results_path}
            
            else:
                #scan failed
                error_message = result.stderr or 'Unknown error during scan execution'
                
                db.execute_command(
                    """UPDATE scan_jobs 
                       SET status = 'failed', completed_at = CURRENT_TIMESTAMP, error_message = %s 
                       WHERE id = %s""",
                    (error_message, scan_job_id)
                )
                
                logger.error(f"Scan {scan_job_id} failed: {error_message}")
                return {'success': False, 'error': error_message}
        
        except subprocess.TimeoutExpired:
            #scan timed out
            error_message = 'Scan execution timed out (1 hour limit)'
            
            db.execute_command(
                """UPDATE scan_jobs 
                   SET status = 'failed', completed_at = CURRENT_TIMESTAMP, error_message = %s 
                   WHERE id = %s""",
                (error_message, scan_job_id)
            )
            
            logger.error(f"Scan {scan_job_id} timed out")
            return {'success': False, 'error': error_message}
        
        except Exception as e:
            #general error
            error_message = f'Scan execution error: {str(e)}'
            
            db.execute_command(
                """UPDATE scan_jobs 
                   SET status = 'failed', completed_at = CURRENT_TIMESTAMP, error_message = %s 
                   WHERE id = %s""",
                (error_message, scan_job_id)
            )
            
            logger.error(f"Scan {scan_job_id} error: {e}")
            return {'success': False, 'error': error_message}
    
    def _placeholder_scan_execution(self, scan_job_id, config_data):
        #placeholder scan execution for development when standalone app is not available
        #creates mock results for testing the web interface
        logger.info(f"Running placeholder scan for job {scan_job_id}")
        
        #create placeholder results
        placeholder_results = {
            'scan_id': scan_job_id,
            'target': config_data['target'],
            'scan_type': config_data['scan_type'],
            'timestamp': datetime.now().isoformat(),
            'status': 'completed',
            'results': {
                'summary': {
                    'total_hosts_scanned': 1,
                    'open_ports_found': 3,
                    'services_identified': 3,
                    'vulnerabilities_found': 0
                },
                'hosts': [
                    {
                        'host': config_data['target']['target_value'],
                        'status': 'up',
                        'open_ports': [
                            {'port': 22, 'service': 'ssh', 'version': 'OpenSSH 8.9'},
                            {'port': 80, 'service': 'http', 'version': 'nginx 1.18.0'},
                            {'port': 443, 'service': 'https', 'version': 'nginx 1.18.0'}
                        ]
                    }
                ],
                'notes': 'This is a placeholder result generated for development testing. No actual scanning was performed.',
                'generator': 'Cyber Clinic Web Backend - Placeholder Mode'
            }
        }
        
        #save placeholder results
        results_path = config_data['output_path']
        with open(results_path, 'w') as f:
            json.dump(placeholder_results, f, indent=2)
        
        #update database
        db = get_db()
        db.execute_command(
            """UPDATE scan_jobs 
               SET status = 'completed', completed_at = CURRENT_TIMESTAMP, results_path = %s 
               WHERE id = %s""",
            (results_path, scan_job_id)
        )
        
        logger.info(f"Placeholder scan {scan_job_id} completed")
        return {'success': True, 'results_path': results_path}

#create global standalone app handler
standalone_handler = StandaloneAppHandler()

@standalone_bp.route('/execute/<int:scan_id>', methods=['POST'])
def execute_scan(scan_id):
    #execute a scan using the standalone application
    #this endpoint is called internally when a scan is ready to run
    try:
        db = get_db()
        
        #get scan details
        scan_data = db.execute_single(
            """SELECT sj.*, nt.target_name, nt.target_type, nt.target_value
               FROM scan_jobs sj 
               JOIN network_targets nt ON sj.target_id = nt.id
               WHERE sj.id = %s AND sj.status = 'pending'""",
            (scan_id,)
        )
        
        if not scan_data:
            return jsonify({'error': 'Scan job not found or not in pending status'}), 404
        
        #prepare target info and scan config
        target_info = {
            'target_name': scan_data['target_name'],
            'target_type': scan_data['target_type'],
            'target_value': scan_data['target_value']
        }
        
        scan_config = {
            'scan_type': scan_data['scan_type'],
            'scan_options': json.loads(scan_data['scan_config']) if scan_data['scan_config'] else {}
        }
        
        #execute scan
        result = standalone_handler.execute_scan(scan_id, target_info, scan_config)
        
        if result['success']:
            return jsonify({
                'success': True,
                'scan_id': scan_id,
                'status': 'completed',
                'results_path': result['results_path']
            })
        else:
            return jsonify({
                'success': False,
                'scan_id': scan_id,
                'status': 'failed',
                'error': result['error']
            }), 500
        
    except Exception as e:
        logger.error(f"Scan execution request failed for scan {scan_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@standalone_bp.route('/status', methods=['GET'])
def standalone_status():
    #get status of standalone application integration
    #checks if standalone app is available and configured
    try:
        app_exists = os.path.exists(standalone_handler.standalone_app_path)
        results_dir_exists = os.path.exists(standalone_handler.scan_results_path)
        
        #get recent scan statistics
        db = get_db()
        stats = db.execute_single("""
            SELECT 
                COUNT(*) as total_scans,
                COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_scans,
                COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_scans,
                COUNT(CASE WHEN status = 'running' THEN 1 END) as running_scans
            FROM scan_jobs 
            WHERE created_at >= CURRENT_DATE - INTERVAL '7 days'
        """)
        
        return jsonify({
            'standalone_app': {
                'available': app_exists,
                'path': standalone_handler.standalone_app_path,
                'mode': 'production' if app_exists else 'placeholder'
            },
            'results_directory': {
                'available': results_dir_exists,
                'path': standalone_handler.scan_results_path
            },
            'scan_statistics': {
                'total_scans_7_days': stats['total_scans'],
                'completed_scans_7_days': stats['completed_scans'],
                'failed_scans_7_days': stats['failed_scans'],
                'currently_running': stats['running_scans']
            }
        })
        
    except Exception as e:
        logger.error(f"Standalone status check failed: {e}")
        return jsonify({'error': 'Status check failed'}), 500
