#Cyber Clinic - Scan execution engine
#handles the actual execution of Nmap and Nikto scans

import subprocess
import json
import os
import logging
from datetime import datetime
from typing import Dict, Any, Optional
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

class ScanExecutor:
    #handles execution of security scanning tools (Nmap, Nikto)
    def __init__(self, results_dir="/src/results"):
        self.results_dir = results_dir
        self.ensure_results_directory()
    
    def ensure_results_directory(self):
        #create results directory if it doesn't exist
        os.makedirs(self.results_dir, exist_ok=True)
    
    def execute_scan(self, scan_job_id: int, scan_type: str, target_value: str, target_type: str, scan_options: Dict = None) -> Dict[str, Any]:
        #execute a scan based on the scan type and target
        logger.info(f"Starting {scan_type} scan for job {scan_job_id} against {target_value}")
        
        try:
            if scan_type.lower() == 'nmap':
                return self._execute_nmap_scan(scan_job_id, target_value, target_type, scan_options or {})
            elif scan_type.lower() == 'nikto':
                return self._execute_nikto_scan(scan_job_id, target_value, target_type, scan_options or {})
            else:
                raise ValueError(f"Unsupported scan type: {scan_type}")
                
        except Exception as e:
            logger.error(f"Scan execution failed for job {scan_job_id}: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'scan_job_id': scan_job_id
            }
    
    def _execute_nmap_scan(self, scan_job_id: int, target: str, target_type: str, options: Dict) -> Dict[str, Any]:
        #execute Nmap scan with appropriate options
        #base Nmap command
        cmd = ['nmap']
        #add common options
        cmd.extend(['-v', '-sV', '-sC', '--script=default'])
        #output formats
        output_base = f"{self.results_dir}/nmap_scan_{scan_job_id}"
        cmd.extend(['-oA', output_base])  
        
        #target-specific options
        if target_type == 'domain':
            cmd.extend(['-Pn'])
        elif target_type == 'range':
            cmd.extend(['-sn']) 
            
        #custom options from scan_options
        if options.get('port_range'):
            cmd.extend(['-p', options['port_range']])
        else:
            cmd.extend(['-p', '1-1000'])
            
        if options.get('scan_speed'):
            speed = options['scan_speed']
            if speed in ['1', '2', '3', '4', '5']:
                cmd.extend([f'-T{speed}'])
        else:
            cmd.extend(['-T3'])
            
        #add target
        cmd.append(target)
        
        logger.info(f"Executing Nmap command: {' '.join(cmd)}")
        
        try:
            #execute the scan
            start_time = datetime.now()
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=3600,
                cwd=self.results_dir
            )
            end_time = datetime.now()
            
            #parse results
            scan_results = self._parse_nmap_results(output_base, result)
            
            return {
                'success': result.returncode == 0,
                'scan_job_id': scan_job_id,
                'scan_type': 'nmap',
                'target': target,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration': (end_time - start_time).total_seconds(),
                'command': ' '.join(cmd),
                'return_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'results': scan_results,
                'output_files': {
                    'xml': f"{output_base}.xml",
                    'nmap': f"{output_base}.nmap",
                    'gnmap': f"{output_base}.gnmap"
                }
            }
            
        except subprocess.TimeoutExpired:
            logger.error(f"Nmap scan timed out for job {scan_job_id}")
            return {
                'success': False,
                'error': 'Scan timed out after 1 hour',
                'scan_job_id': scan_job_id
            }
    
    def _execute_nikto_scan(self, scan_job_id: int, target: str, target_type: str, options: Dict) -> Dict[str, Any]:
        #execute Nikto web vulnerability scan
        #ensure target has protocol for web scanning
        #uses HTTP by default since our Nikto doesn't have SSL support yet
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        #base Nikto command
        cmd = ['nikto']
        #output file
        output_file = f"{self.results_dir}/nikto_scan_{scan_job_id}.txt"
        cmd.extend(['-output', output_file])
        #target
        cmd.extend(['-h', target])
        #additional options
        cmd.extend(['-Format', 'txt'])
        
        #custom options from scan_options
        #note: dont use -p (port) option with full URIs as Nikto doesn't allow it
        if not target.startswith(('http://', 'https://')) and options.get('port'):
            cmd.extend(['-p', str(options['port'])])
            
        if options.get('timeout'):
            cmd.extend(['-timeout', str(options['timeout'])])
        else:
            cmd.extend(['-timeout', '10'])
            
        logger.info(f"Executing Nikto command: {' '.join(cmd)}")
        
        try:
            #execute the scan
            start_time = datetime.now()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800, 
                cwd=self.results_dir
            )
            end_time = datetime.now()
            #parse results
            scan_results = self._parse_nikto_results(output_file, result)
            
            return {
                'success': result.returncode == 0,
                'scan_job_id': scan_job_id,
                'scan_type': 'nikto',
                'target': target,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration': (end_time - start_time).total_seconds(),
                'command': ' '.join(cmd),
                'return_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'results': scan_results,
                'output_files': {
                    'txt': output_file
                }
            }
            
        except subprocess.TimeoutExpired:
            logger.error(f"Nikto scan timed out for job {scan_job_id}")
            return {
                'success': False,
                'error': 'Scan timed out after 30 minutes',
                'scan_job_id': scan_job_id
            }
    
    def _parse_nmap_results(self, output_base: str, subprocess_result) -> Dict[str, Any]:
        #parse Nmap XML output to extract structured results
        xml_file = f"{output_base}.xml"
        
        try:
            if os.path.exists(xml_file):
                tree = ET.parse(xml_file)
                root = tree.getroot()
                
                results = {
                    'scan_info': {},
                    'hosts': [],
                    'summary': {}
                }
                
                #parse scan info
                scaninfo = root.find('scaninfo')
                if scaninfo is not None:
                    results['scan_info'] = {
                        'type': scaninfo.get('type'),
                        'protocol': scaninfo.get('protocol'),
                        'numservices': scaninfo.get('numservices')
                    }
                #parse hosts
                for host in root.findall('host'):
                    host_data = {
                        'status': host.find('status').get('state') if host.find('status') is not None else 'unknown',
                        'addresses': [],
                        'ports': []
                    }
                    #get addresses
                    for address in host.findall('address'):
                        host_data['addresses'].append({
                            'addr': address.get('addr'),
                            'addrtype': address.get('addrtype')
                        })
                    #get ports
                    ports = host.find('ports')
                    if ports is not None:
                        for port in ports.findall('port'):
                            port_data = {
                                'protocol': port.get('protocol'),
                                'portid': port.get('portid'),
                                'state': port.find('state').get('state') if port.find('state') is not None else 'unknown'
                            }
                            
                            #get service info
                            service = port.find('service')
                            if service is not None:
                                port_data['service'] = {
                                    'name': service.get('name'),
                                    'product': service.get('product'),
                                    'version': service.get('version')
                                }
                            
                            host_data['ports'].append(port_data)
                    
                    results['hosts'].append(host_data)
                
                #parse run stats
                runstats = root.find('runstats')
                if runstats is not None:
                    finished = runstats.find('finished')
                    hosts = runstats.find('hosts')
                    if finished is not None:
                        results['summary']['elapsed'] = finished.get('elapsed')
                        results['summary']['time'] = finished.get('time')
                    if hosts is not None:
                        results['summary']['up'] = hosts.get('up')
                        results['summary']['down'] = hosts.get('down')
                        results['summary']['total'] = hosts.get('total')
                
                return results
            else:
                logger.warning(f"Nmap XML output file not found: {xml_file}")
                return {'raw_output': subprocess_result.stdout}
                
        except Exception as e:
            logger.error(f"Error parsing Nmap results: {e}")
            return {'raw_output': subprocess_result.stdout, 'parse_error': str(e)}
    
    def _parse_nikto_results(self, output_file: str, subprocess_result) -> Dict[str, Any]:
        #parse Nikto text output to extract structured results
        try:
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    content = f.read()
                
                results = {
                    'vulnerabilities': [],
                    'summary': {},
                    'raw_output': content
                }
                
                lines = content.split('\n')
                for line in lines:
                    line = line.strip()
                    
                    #parse vulnerability findings (lines starting with +)
                    if line.startswith('+ '):
                        results['vulnerabilities'].append({
                            'finding': line[2:],
                            'severity': 'info'
                        })
                    #parse summary information
                    elif 'items checked' in line.lower():
                        results['summary']['items_checked'] = line
                    elif 'scan completed' in line.lower():
                        results['summary']['completion'] = line
                
                return results
            else:
                logger.warning(f"Nikto output file not found: {output_file}")
                return {'raw_output': subprocess_result.stdout}
                
        except Exception as e:
            logger.error(f"Error parsing Nikto results: {e}")
            return {'raw_output': subprocess_result.stdout, 'parse_error': str(e)}
