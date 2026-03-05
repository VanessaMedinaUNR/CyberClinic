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
                    if scan_data["report_id"] and scan_data['target_value'] and scan_data['scan_type']:
                        scans[scan_id] = scan_data
                        scans[scan_id]["status"] = "pending"
                return scans
            elif msg == "NONE_PENDING":
                logger.info("No scans scheduled, moving on...")
                return {}
    except Exception as e:
        raise e

def execute_scans(scans: dict[str, dict[str]], storage: StorageHandler):
    check_tools()
    for id, info in scans.items():
        logger.debug(info)
        results = ""
        of = os.path.join('scans', info['report_id'], f'{id}.xml')
        options = info['scan_options'] if 'scan_options' in info else {}
        match info['scan_type']:
            case 'nmap':
                args = ['-v', '-sT', '-Pn', '-sV', '--script=default,safe', '--reason', '--open']
                logger.info('Executing nmap scan...')
                scanner = nmap.PortScanner()
                #custom options from scan_options
                if options.get('port_range'):
                    args.extend(['-p', options['port_range']])
                else:
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
                logger.info('Executing nikto scan...')
                raise FileNotFoundError("Nikto is not installed, cannot execute nikto scan.")
            case _:
                raise ValueError(f"Unknown scan type: {info['scan_type']}")
            
        if storage.save_ext(of, results):
            return of
        else:
            raise FileNotFoundError(f"Failed to save {info['scan_type']} scan report to {of}")

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

def send_scans(authed_tunnel: TunnelHandler, scans: dict[str, dict[str]]):
    for scan in scans:
        logger.debug(scan)