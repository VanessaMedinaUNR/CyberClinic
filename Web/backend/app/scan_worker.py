#Cyber Clinic - Scan worker
#Background worker that processes scan jobs from the database

import time
import logging
import threading
import json
import ipaddress
from datetime import datetime
from app.database import get_db
from app.scan_executor import ScanExecutor

logger = logging.getLogger(__name__)

class ScanWorker:
    #background worker that processes pending scan jobs
    def __init__(self, poll_interval=30):
        self.poll_interval = poll_interval
        self.running = False
        self.executor = ScanExecutor()
        self.worker_thread = None
    
    def start(self):
        #start the background worker
        if not self.running:
            self.running = True
            self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
            self.worker_thread.start()
            logger.info("Scan worker started")
    
    def stop(self):
        #stop the background worker
        self.running = False
        if self.worker_thread:
            self.worker_thread.join()
        logger.info("Scan worker stopped")
    
    def _worker_loop(self):
        #main worker loop, polls for pending scans and processes them
        logger.info("Scan worker loop started")
        
        while self.running:
            try:
                self._process_pending_scans()
            except Exception as e:
                logger.error(f"Error in scan worker loop: {e}")
            
            #wait before next poll
            time.sleep(self.poll_interval)
    
    def _process_pending_scans(self):
        #check for pending scans and process them
        db = get_db()
        
        # Get pending scan jobs
        pending_scans = db.execute_query(
            """SELECT sj.*, nt.subnet_name, nt.subnet_ip, nt.subnet_netmask
               FROM scan_jobs sj
               LEFT JOIN network nt ON sj.subnet_name = nt.subnet_name AND sj.client_id = nt.client_id
               WHERE sj.status = 'pending'
               ORDER BY sj.created_at ASC
               LIMIT 5""",
            ()
        )
        
        for scan in pending_scans:
            try:
                self._execute_scan_job(scan)
            except Exception as e:
                logger.error(f"Failed to process scan job {scan['id']}: {e}")
                self._mark_scan_failed(scan['id'], str(e))
    
    def _execute_scan_job(self, scan_job):
        #execute a single scan job
        scan_id = scan_job['id']
        logger.info(f"Processing scan job {scan_id}")
        
        try:
            #mark scan as running
            db = get_db()
            db.execute_command(
                "UPDATE scan_jobs SET status = 'running', started_at = CURRENT_TIMESTAMP WHERE id = %s",
                (scan_id,)
            )

            target_value = None
            target_type = None
            #determine target value and type
            domain = db.execute_single(
                """SELECT domain
                FROM network_domains
                WHERE client_id = %s AND subnet_name = %s""",
                (scan_job['client_id'], scan_job['subnet_name'])
                )
            if domain:
                target_type = "domain"
                target_value = domain
            else:
                if scan_job["subnet_netmask"] == "255.255.255.255":
                    target_type = "ip"
                    target_value = scan_job["subnet_ip"]
                else:
                    target_type = "range"
                    subnet_ip = scan_job['subnet_ip']
                    subnet_netmask = scan_job['subnet_netmask']
                    target_value = ipaddress.IPv4Network(f'{subnet_ip}/{subnet_netmask}').compressed

            
            #parse scan configuration
            scan_config = {}
            if scan_job['scan_config']:
                try:
                    scan_config = json.loads(scan_job['scan_config']) if isinstance(scan_job['scan_config'], str) else scan_job['scan_config']
                except json.JSONDecodeError:
                    logger.warning(f"Invalid scan_config for job {scan_id}, using defaults")
            
            #execute the scan
            scan_result = self.executor.execute_scan(
                scan_job_id=scan_id,
                scan_type=scan_job['scan_type'],
                target_value=target_value,
                target_type=target_type,
                scan_options=scan_config.get('scan_options', {})
            )
            
            #update database with results
            if scan_result['success']:
                self._mark_scan_completed(scan_id, scan_result)
            else:
                self._mark_scan_failed(scan_id, scan_result.get('error', 'Unknown error'))
                
        except Exception as e:
            logger.error(f"Error executing scan job {scan_id}: {e}")
            self._mark_scan_failed(scan_id, str(e))
    
    def _mark_scan_completed(self, scan_id, scan_result):
        #mark scan as completed and store results
        db = get_db()
        
        #store results in the database
        results_json = json.dumps(scan_result)
        output_files = scan_result.get('output_files', {})
        
        db.execute_command(
            """UPDATE scan_jobs SET 
               status = 'completed',
               completed_at = CURRENT_TIMESTAMP,
               results = %s,
               results_path = %s
               WHERE id = %s""",
            (results_json, json.dumps(output_files), scan_id)
        )
        
        logger.info(f"Scan job {scan_id} completed successfully")
    
    def _mark_scan_failed(self, scan_id, error_message):
        #mark scan as failed with error message
        db = get_db()
        
        db.execute_command(
            """UPDATE scan_jobs SET 
               status = 'failed',
               completed_at = CURRENT_TIMESTAMP,
               error_message = %s
               WHERE id = %s""",
            (error_message, scan_id)
        )
        
        logger.error(f"Scan job {scan_id} failed: {error_message}")

#global scan worker instance
scan_worker = None

def start_scan_worker():
    #start the global scan worker
    global scan_worker
    if scan_worker is None:
        scan_worker = ScanWorker()
        scan_worker.start()
        return scan_worker
    return scan_worker

def stop_scan_worker():
    #stop the global scan worker
    global scan_worker
    if scan_worker:
        scan_worker.stop()
        scan_worker = None
