#Cyber Clinic Standalone Application - Scan Handler
#CS 426 Team 13 - Spring 2026

from storage import StorageHandler
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
                logging.info("No scans scheduled, moving on...")
                return {}
    except Exception as e:
        raise e

def execute_scans(scans: dict[str, dict[str]], storage: StorageHandler):
    check_tools()
    for id, info in scans.items():
        logging.debug(info)
        if info['scan_type'] == 'nmap':
            logging.info('Executing nmap scan...')
            scanner = nmap.PortScanner()
            of = os.path.join('scans', info['report_id'], f'{id}.xml')
            nmap_results = scanner.scan(hosts=info["target_value"], arguments='-v -sT -Pn -sV --script=default,safe --reason --open')
            logging.debug(scanner.get_nmap_last_output())
            if storage.save_ext(of, scanner.get_nmap_last_output().decode()):
                return of
            else:
                raise FileNotFoundError(f"Failed to save nmap scan report to {of}")

def check_tools():
    tools = {}
    try:
        scanner = nmap.PortScanner()
        tools['nmap']= True
        tools['nikto'] = True
    except nmap.PortScannerError:
        tools['nmap'] = False
    except FileNotFoundError:
        tools['nikto'] = False
    return tools

def send_scans(authed_tunnel: TunnelHandler, scans: dict[str, dict[str]]):
    for scan in scans:
        logging.debug(scan)