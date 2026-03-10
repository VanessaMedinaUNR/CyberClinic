#Cyber Clinic Standalone Application - Scan Handler
#CS 426 Team 13 - Spring 2026

from re import match

from storage_handler import StorageHandler
from tunnel import TunnelHandler
import logging
import nmap
import ast
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def fetch_scans(authed_tunnel: TunnelHandler, subnet_name):
    scans = {}
    try:
        authed_tunnel.reconnect_tunnel()
        send = f'FETCH_SCANS|{subnet_name}'
        authed_tunnel.conn.send(send.encode())
        response = authed_tunnel.conn.recv(1024).decode()
        if response:
            pending_scans = response.split("|")
            msg = pending_scans.pop(0)
            if msg == "PENDING_SCANS":
                scan_list: dict = ast.literal_eval(pending_scans.pop(0))
                for scan_id, scan_data in scan_list.items():
                    if scan_data["report_id"] and scan_data['scan_type']:
                        report_id = scan_data['report_id']
                        if report_id not in scans.keys():
                            scans[report_id] = {}
                        scans[report_id][scan_id] = scan_data
                        scans[report_id][scan_id]["status"] = "pending"
                return scans
            elif msg == "NONE_PENDING":
                logger.info("No scans scheduled, moving on...")
                return {}
            else:
                raise ValueError(f"Unexpected response from server: {response}")
    except Exception as e:
        raise e

def execute_scans(scans: dict[str, dict[str]], storage: StorageHandler):
    check_tools()
    complete = False
    while not complete:
        complete = True
        for id, info in scans.items():
            if info['status'] == 'complete':
                continue
            elif info['status'] == 'error':
                logger.info(f"Scan {id} encountered an error during execution, retrying...")
                complete = False
                try:
                    execute_scan(id, info, storage)
                except Exception as e:
                    logger.error(f"Error executing scan {id}: {e}")
                    raise e
            elif info['status'] == 'pending':
                complete = False
                try:
                    execute_scan(id, info, storage)
                except Exception as e:
                    logger.error(f"Error executing scan {id}: {e}")
                    raise e
            else:
                logger.error(f"Scan {id} has unknown status {info['status']}, ignoring...")
    return scans

def execute_scan(id: str, info: dict[str], storage: StorageHandler):
    of = os.path.join('scans', info['report_id'])
    options = info['scan_options'] if 'scan_options' in info else {}
    match info['scan_type']:
        case 'nmap':
            of = os.path.join(of, f'nmap_scan_{id}.xml')
            args = ['-sT', '-Pn', '-sV', '--script=default,safe', '--reason', '--open']
            logger.info('Executing nmap scan...')
            scanner = nmap.PortScanner()
            #custom options from scan_options
            if options.get('port_range'):
                args.extend(['-p', options['port_range']])
            else:
                pass
                args.extend(['-p', '1-1000'])
                
            if options.get('scan_speed'):
                speed = options['scan_speed']
                if speed in ['1', '2', '3', '4', '5']:
                    args.extend([f'-T{speed}'])
            else:
                args.extend(['-T3'])
            nmap_results = scanner.scan(hosts=info["target_value"], arguments=' '.join(args))
            logger.debug(scanner.get_nmap_last_output())
            results = scanner.get_nmap_last_output().decode()
        case 'nikto':
            of = os.path.join(of, f'nikto_scan_{id}.json')
            logger.info('Executing nikto scan...')

            logger.error("Nikto is not installed, cannot execute nikto scan.")
        case _:
            info['status'] = 'impossible'
            raise ValueError(f"Unknown scan type: {info['scan_type']}")
        
    if storage.save_ext(of, results):
        info['status'] = 'complete'
        info['path'] = storage.fetch_ext(of)
    else:
        info['status'] = 'error'

def check_tools() -> dict[str, bool]:
    tools = {}
    try:
        scanner = nmap.PortScanner()
        tools['nmap'] = True
        tools['nikto'] = False
    except nmap.PortScannerError:
        tools['nmap'] = False
    except FileNotFoundError:
        tools['nikto'] = False
    return tools

def send_scans(authed_tunnel: TunnelHandler, scans: dict[str, dict[str]], storage: StorageHandler):
    scans_to_send = {}

    for scan_id, scan_info in scans.items():
        logger.debug(f"Preparing to send scan {scan_id} with status {scan_info}...")
        if not scan_info['status'] == 'complete':
            logger.info(f"Scan {scan_id} is not complete or already sent, skipping.")
        else:
            path = scan_info.get('path')
            if path and os.path.exists(path):
                report_id = scan_info['report_id']
                size = os.path.getsize(path)
                if report_id not in scans_to_send.keys():
                    scans_to_send[report_id] = {}
                scans_to_send[report_id][scan_id] = {
                    'path': path,
                    'name': os.path.basename(path),
                    'size': size,
                    'status': 'pending_send'
                }
            else:
                scans[scan_id]['status'] = 'error'
                logger.error(f"Scan {scan_id} has status complete but file does not exist at {path}, skipping.")
    logger.info(f"Scans to send: {scans_to_send}")
    
    all_sent = False
    while not all_sent:
        all_sent = True
        for report_id, scans in scans_to_send.items():
            for scan_id, scan_info in scans.items():
                if scan_info['status'] == 'sent':
                    continue
                elif scan_info['status'] == 'pending_send':
                    all_sent = False
                    try:
                        filename = scan_info['name']
                        logger.info(f"Reconnecting tunnel to send scan {scan_id} of report {report_id}...")
                        authed_tunnel.reconnect_tunnel()
                        logger.info(f"Sending scan {scan_id} of report {report_id} with filename {filename} and size {scan_info['size']}...")
                        authed_tunnel.conn.send(f'SEND_RESULTS|{report_id}|{scan_id}|{filename}|{scan_info["size"]}'.encode())
                        authed_tunnel.conn.recv(1024) # Wait for ACK
                        with open(scan_info['path'], 'rb') as f:
                            authed_tunnel.conn.sendfile(f)
                            logger.info(f"Finished sending scan {scan_id} of report {report_id}, waiting for confirmation...")
                        success = authed_tunnel.conn.recv(1024) # Wait for ACK
                        if success == b'RESULT_RECEIVED':
                            scan_info['status'] = 'sent'
                    except Exception as e:
                        logger.error(f"Error sending scan {scan_id}: {e}")
                        scan_info['status'] = 'error'
                elif scan_info['status'] == 'error':
                    all_sent = False
                    logger.info(f"Scan {scan_id} encountered an error during sending, retrying...")
                    scan_info['status'] = 'pending_send'
                else:
                    logger.error(f"Scan {scan_id} has unknown status {scan_info['status']}, ignoring...")