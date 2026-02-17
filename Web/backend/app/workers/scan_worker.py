#Cyber Clinic - Scan worker
#Background worker that processes scan jobs from the database

import os
import time
import logging
import threading
import json
import ipaddress
import socket
from datetime import datetime
from app.database import get_db
from app.scan_executor import ScanExecutor

logger = logging.getLogger(__name__)

class ScanWorker:
    #background worker that processes pending scan jobs
    def __init__(self, scan_dir, poll_interval=30):
        self.poll_interval = poll_interval
        self.running = False
        self.executor = ScanExecutor()
        self.scan_dir = scan_dir
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
        
        #get pending scan jobs
        pending_scans = db.execute_query(
            """ SELECT sj.*, nt.subnet_name, nt.subnet_ip, nt.subnet_netmask
                FROM scan_jobs sj
                LEFT JOIN network nt ON sj.subnet_name = nt.subnet_name AND sj.client_id = nt.client_id
                WHERE sj.status = 'pending'
                ORDER BY sj.created_at ASC
                LIMIT 5 """,
            ()
        )
        
        for scan in pending_scans:
            try:
                self._execute_scan_job(scan)
            except Exception as e:
                logger.error(f"Failed to process scan job {scan['id']}: {e}")
                self._mark_scan_failed(scan['id'], str(e))
    
    def _dedupe_tools(self, tools_list):
        #preserve order, remove duplicates, normalize lower case names
        seen = set()
        out = []
        if not tools_list:
            return []
        for t in tools_list:
            if not t:
                continue
            key = str(t).strip().lower()
            if key and key not in seen:
                seen.add(key)
                out.append(str(t).strip())
        return out

    def _dedupe_findings(self, findings):
        #remove duplicate findings by key fields
        if not findings:
            return []
        seen = set()
        out = []
        for f in findings:
            try:
                title = (f.get('title') or '').strip()
                affected = (f.get('affected_component') or f.get('affected') or '').strip()
                src = (f.get('source') or f.get('tool') or '').strip()
                fid = (title + '|' + affected + '|' + src).lower()
            except Exception:
                fid = str(f).lower()
            if fid in seen:
                continue
            seen.add(fid)
            out.append(f)
        return out

    def _unique_output_files(self, output_files):
        #output_files might be dict or list, return a normalized dict with unique paths
        if not output_files:
            return {}
        result = {}
        if isinstance(output_files, dict):
            for k, v in output_files.items():
                if isinstance(v, list):
                    uniq = []
                    seen = set()
                    for p in v:
                        pstr = str(p)
                        if pstr not in seen:
                            seen.add(pstr)
                            uniq.append(pstr)
                    result[k] = uniq
                else:
                    result[k] = v
        elif isinstance(output_files, list):
            seen = set(); uniq = []
            for p in output_files:
                pstr = str(p)
                if pstr not in seen:
                    seen.add(pstr); uniq.append(pstr)
            result['files'] = uniq
        else:
            result['files'] = [str(output_files)]
        return result

    def _build_host_map(self, scan_result, target_value=None):
        #build mapping domain/ip -> ip and hostnames
        host_map = {}
        #prefer nmap parsed data if present
        nmap_data = scan_result.get('nmap') if isinstance(scan_result, dict) else None
        if nmap_data and isinstance(nmap_data, dict):
            hosts = nmap_data.get('hosts') or []
            for h in hosts:
                ip = None
                if isinstance(h, dict):
                    ip = h.get('ip') or h.get('address') or (h.get('addresses') or [{}])[0].get('addr') if h.get('addresses') else None
                    names = []
                    if h.get('hostnames'):
                        try:
                            if isinstance(h.get('hostnames'), list):
                                names = [str(x) for x in h.get('hostnames') if x]
                            else:
                                names = [str(h.get('hostnames'))]
                        except Exception:
                            names = []
                    if ip:
                        host_map[ip] = {'hostnames': names}
        #if nothing from nmap, try to resolve provided domain
        if not host_map and target_value:
            try:
                resolved = socket.gethostbyname_ex(target_value)
                #resolved -> (name, aliaslist, ipaddrlist)
                if resolved and len(resolved) >= 3:
                    ips = resolved[2]
                    for ip in ips:
                        host_map[ip] = {'hostnames': [resolved[0]]}
            except Exception:
                #ignore resolve errors
                pass
        return host_map
    
    def _execute_scan_job(self, scan_job):
        #execute a single scan job
        scan_id = scan_job['id']
        report_id = scan_job['report_id']
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
                target_value = domain['domain']
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
            self.executor.results_dir = os.path.join(self.scan_dir, report_id)
            scan_result = self.executor.execute_scan(
                scan_job_id=scan_id,
                scan_type=scan_job['scan_type'],
                target_value=target_value,
                target_type=target_type,
                scan_options=scan_config.get('scan_options', {})
            )
            
            if isinstance(scan_result, dict):
                #normalize tools/scan_tools
                tools_candidates = scan_result.get('scan_tools') or scan_result.get('tools_used') or scan_result.get('tools') or []
                scan_result['scan_tools'] = self._dedupe_tools(tools_candidates)

                #dedupe findings at top level
                if 'findings' in scan_result and isinstance(scan_result['findings'], list):
                    scan_result['findings'] = self._dedupe_findings(scan_result['findings'])

                #dedupe any per_host_findings lists
                ph = scan_result.get('per_host_findings') or {}
                if isinstance(ph, dict):
                    for hostk, flist in list(ph.items()):
                        if isinstance(flist, list):
                            ph[hostk] = self._dedupe_findings(flist)
                    scan_result['per_host_findings'] = ph

                #normalize output files
                output_files = scan_result.get('output_files') or scan_result.get('results_files') or {}
                scan_result['output_files'] = self._unique_output_files(output_files)

                #build host map (domain->ip, hostnames)
                host_map = self._build_host_map(scan_result, target_value)
                scan_result['host_map'] = host_map

                #if the scan was initiated with a domain but host_map empty, attempt resolution
                if target_type == 'domain' and not host_map:
                    try:
                        resolved_ip = socket.gethostbyname(target_value)
                        scan_result.setdefault('host_map', {})[resolved_ip] = {'hostnames': [target_value]}
                    except Exception:
                        pass

            #update database with results
            if isinstance(scan_result, dict) and scan_result.get('success'):
                self._mark_scan_completed(scan_id, scan_result)
            else:
                #scan_result may be dict with error or a falsy result, ensure message
                error_msg = scan_result.get('error') if isinstance(scan_result, dict) else None
                self._mark_scan_failed(scan_id, error_msg or 'Unknown error')

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

def start_scan_worker(scan_dir):
    #start the global scan worker
    global scan_worker
    if scan_worker is None:
        scan_worker = ScanWorker(scan_dir)
        scan_worker.start()
        return scan_worker
    return scan_worker

def stop_scan_worker():
    #stop the global scan worker
    global scan_worker
    if scan_worker:
        scan_worker.stop()
        scan_worker = None
        
# Done by Manuel Morales-Marroquin