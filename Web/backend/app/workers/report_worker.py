from datetime import datetime
import json
import os
from app.report_generator import CustomReportGenerator
from app.database import get_db
from threading import Thread
import logging
import time

logger = logging.getLogger(__name__)

class ReportWorker:
    #background worker that processes pending reports
    def __init__(self, report_dir, poll_interval=50):
        self.poll_interval = poll_interval
        self.running = False
        self.report_generator = CustomReportGenerator(report_dir)
        self.worker_thread = None
    
    def start(self):
        if not self.running:
            self.running = True
            self.worker_thread = Thread(target=self._worker_loop, daemon=True)
            self.worker_thread.start()
            logger.info("Report worker started")

    def _worker_loop(self):
        #main worker loop, polls for pending reports and processes them
        logger.info("Report worker loop started")
        
        while self.running:
            try:
                self._process_pending_reports()
            except Exception as e:
                logger.error(f"Error in report worker loop: {e}")
            
            #wait before next poll
            time.sleep(self.poll_interval)

    def _process_pending_reports(self):
        #check for pending scans and process them
        db = get_db()
        
        #get pending scan jobs
        pending_reports = db.execute_query(
            """ SELECT report_id, creation_time FROM report 
                WHERE status = 'pending'
                ORDER BY creation_time ASC
                LIMIT 5 """,
            ()
        )
        
        for report in pending_reports:
            try:
                compiled = self._compile_report(report['report_id'], report['creation_time'])
            except Exception as e:
                self._mark_report_failed(report['report_id'], e)

    def _compile_report(self, report_id, start_time):
        logger.info(f'compiling {report_id}...')

        db = get_db()
        report_scans = db.execute_query(
            """ SELECT sj.*, nt.subnet_name, nt.subnet_ip, nt.subnet_netmask
                FROM scan_jobs sj
                LEFT JOIN network nt ON sj.subnet_name = nt.subnet_name AND sj.client_id = nt.client_id
                WHERE sj.report_id = %s 
                ORDER BY sj.created_at ASC
                """,
            (report_id,)
        )

        complete_scans = []
        for scan in report_scans:
            scan_id = scan['id']
            status = scan['status']
            logger.info(f'{scan_id} - {status}')
            match status:
                case 'failed':
                    self._mark_report_failed(report_id, f'Scan job {scan_id} failed')
                    break
                case 'completed':
                    complete_scans.append(scan)
                case _:
                    pass
        if len(complete_scans) == len(report_scans):
            client_id = complete_scans[0]['client_id']
            SCAN_ID = complete_scans[0]['id']
            MODE = complete_scans[0]['scan_type']
            completed_time = datetime.now()
            
            targets = []
            results_paths = []
            scan_type = complete_scans[0]['scan_type']
            for scan in complete_scans:
                if scan['scan_type'] != scan_type:
                    scan_type = 'full'
                subnet_name = scan['subnet_name']
                network = db.execute_single(
                    """SELECT * FROM network WHERE client_id = %s AND subnet_name = %s""",
                    (client_id, subnet_name,)
                )
                domain = db.execute_single(
                    """SELECT * FROM network_domains WHERE client_id = %s AND subnet_name = %s""",
                    (client_id, subnet_name,)
                )
                if network:
                    target_value = network['subnet_ip']
                    target_type = "range"
                    if domain:
                        target_type = "domain"
                        target_value = domain['domain']
                    elif network['subnet_netmask'] == '255.255.255.255':
                        target_type = 'ip'
                    target = {
                        'target_name': subnet_name,
                        'target_value': target_value,
                        'target_type': target_type
                    }
                    if not target in targets:
                        targets.append(target)
                results_file: dict = json.loads(scan['results_path'])
                logger.info(results_file)
                path = results_file.get('json')
                if results_file.get('json') and os.path.exists(f'{path}.json'):
                    results_paths.append(f'{path}.json')
                elif results_file.get('xml') and os.path.exists(results_file.get('xml')):
                    results_paths.append(results_file.get('xml'))

            logger.info(results_paths)
            report_data = {
                'report_id': report_id,
                'scan_id': SCAN_ID,
                'scan_type': scan_type,
                'targets': targets,
                'client': {
                    'name': 'Cyber Clinic',
                    'email': 'example@unr.edu'
                },
                'timestamps': {
                    'started': start_time,
                    'completed': completed_time
                },
                'results_paths': results_paths
            }
            try:
                self.report_generator.generate_report(report_data, output_format='json')
                self._mark_report_completed(report_id)
            except Exception as e:
                raise e
        else:
            in_progress = len(report_scans) - len(complete_scans) 
            logger.info(f'Still waiting on {in_progress}/{len(report_scans)} scans - Skipping...')


    def _mark_report_completed(self, report_id):
        #mark scan as completed and store results
        db = get_db()
        
        db.execute_command(
            """UPDATE report SET 
               status = 'completed',
               completion_time = CURRENT_TIMESTAMP
               WHERE report_id = %s""",
            (report_id,)
        )
        
        logger.info(f"Report {report_id} compiled successfully")

    def _mark_report_failed(self, report_id, error_message):
        #mark scan as failed with error message
        db = get_db()
        
        db.execute_command(
            """UPDATE report SET 
               status = 'failed',
               completion_time = CURRENT_TIMESTAMP
               WHERE report_id = %s""",
            (report_id,)
        )
        logger.error(f"Failed to compile report {report_id}: {error_message}")
    
    def stop(self):
        #stop the background worker
        self.running = False
        if self.worker_thread:
            self.worker_thread.join()
        logger.info("Report worker stopped")

#global report worker instance
report_worker = None

def start_report_worker(report_dir):
    #start the global scan worker
    global report_worker
    if report_worker is None:
        report_worker = ReportWorker(report_dir)
        report_worker.start()
        return report_worker
    return report_worker

def stop_report_worker():
    #stop the global scan worker
    global report_worker
    if report_worker:
        report_worker.stop()
        report_worker = None

# Done By Austin Finch