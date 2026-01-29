#!/usr/bin/env python3

#Nmap + Nikto scan test that generates  pdf report

"""
To run the script:
1. Open terminal
2. Navigate to the Web folder:
   cd path\to\CyberClinic\Web
3. Run inside Docker container as root:
   docker-compose exec -u root backend python test_scan.py
"""
import os
import sys
import subprocess
from datetime import datetime
from app.report_generator import CustomReportGenerator
from app.parsers.nmap_parser import NmapParser
from app.parsers.nikto_parser import NiktoParser

#Approved targets for security testing
#These sites explicitly allow scanning with nmap and nikto
#Use ONLY for testing and development

#scanme.nmap.org
#badssl.com
#juice-shop.herokuapp.com
TARGET = "scanme.nmap.org"
SCAN_DIR = "/tmp/cyberclinic_scans"
REPORT_DIR = "/src/app/reports"

os.makedirs(SCAN_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)
print("\n" +"="*60)
print("CYBER CLINIC - SCAN TEST")
print("="*60)

#STEP 1: Run Nmap
print("\n[1/4] Running Nmap scan on", TARGET)
nmap_file = f"{SCAN_DIR}/nmap_scan.xml"
try:
    result = subprocess.run(["nmap", "-sV", "-p", "80,443", TARGET, "-oX", nmap_file], capture_output=True, timeout=120, text=True)
    if result.returncode == 0 and os.path.exists(nmap_file):
        print(f"✓ Nmap complete: {nmap_file}")
        with open(nmap_file) as f:
            size = len(f.read())/1024
            print(f"  File size: {size:.1f} KB")
    else:
        print(f"x Nmap failed with code {result.returncode}")
        if result.stderr:
            print(f"  Error: {result.stderr}")
        sys.exit(1)
except Exception as e:
    print(f"x Nmap error: {e}")
    sys.exit(1)

#STEP 2: Run Nikto
print("\n[2/4] Running Nikto scan on", TARGET)
nikto_file = f"{SCAN_DIR}/nikto_scan.txt"
nikto_success = False
try:
    result = subprocess.run(["nikto", "-h", TARGET, "-output", nikto_file], capture_output=True, timeout=300, text=True)
    if os.path.exists(nikto_file) and os.path.getsize(nikto_file) > 100:
        print(f"✓ Nikto complete: {nikto_file}")
        with open(nikto_file) as f:
            lines = len(f.readlines())
            print(f"  Lines: {lines}")
        nikto_success = True
    else:
        print(f"x Nikto produced no output or small file")
        nikto_success = False
except subprocess.TimeoutExpired:
    print(f"x Nikto timeout after 300 seconds - continuing with Nmap only")
    nikto_success = False
except FileNotFoundError:
    print(f"x Nikto not found - continuing with Nmap only")
    nikto_success = False
except Exception as e:
    print(f"x Nikto error: {e} - continuing with Nmap only")
    nikto_success = False

#STEP 3: Parse results
print("\n[3/4] Parsing scan results...")
try:
    nmap_parser = NmapParser()
    nmap_data = nmap_parser.parse_xml(nmap_file)
    print(f"✓ Nmap parsed successfully")
    print(f"  Hosts found: {nmap_data.get('total_hosts', 0)}")
    print(f"  Open ports: {nmap_data.get('total_open_ports', 0)}")
    print(f"  Findings: {len(nmap_data.get('findings', []))}")
except Exception as e:
    print(f"x Nmap parsing failed: {e}")
    sys.exit(1)

nikto_data = {}
if nikto_success and os.path.exists(nikto_file):
    try:
        nikto_parser = NiktoParser()
        nikto_data = nikto_parser.parse_file(nikto_file)
        print(f"✓ Nikto parsed successfully")
        print(f"  Findings: {len(nikto_data.get('findings', []))}")
    except Exception as e:
        print(f"x Nikto parsing failed: {e}")
        nikto_data = {}
else:
    print(f"  Nikto skipped")

#STEP 4: Generate report
print("\n[4/4] Generating report...")

#gets target IP from Nmap
target_ip = TARGET
if nmap_data.get('hosts') and len(nmap_data['hosts']) > 0:
    host = nmap_data['hosts'][0]
    target_ip = host.get('ip') or host.get('ipv4') or TARGET
    print(f"  Target IP: {target_ip}")

#prepares results paths (only include existing files)
results_paths = [nmap_file]
if nikto_success and os.path.exists(nikto_file):
    results_paths.append(nikto_file)

now = datetime.now()
report_data = {
    'scan_id': 1001,
    #use full to process both nmap and nikto
    'scan_type': 'full',  
    'target': {
        'name': TARGET,
        'value': target_ip,
        'type': 'domain'
    },
    'client': {
        'name': 'Cyber Clinic',
        'email': 'example@unr.edu'
    },
    'timestamps': {
        'started': now.strftime('%Y-%m-%d %H:%M:%S'),
        'completed': now.strftime('%Y-%m-%d %H:%M:%S')
    },
    'results_paths': results_paths
}

try:
    generator = CustomReportGenerator()
    generator.reports_dir = REPORT_DIR
    #generates HTML
    html_report = generator.generate_report(report_data, output_format='html')
    print(f"✓ HTML report: {os.path.basename(html_report)}")
    try:
        pdf_report = generator.generate_report(report_data, output_format='pdf')
        print(f"✓ PDF report: {os.path.basename(pdf_report)}")
    except Exception as e:
        print(f"x PDF generation skipped: {str(e)[:60]}")
        
except Exception as e:
    print(f"x Report generation failed: {e}")
    sys.exit(1)

print("\n" + "="*60)
print("Scan test completed")
print("="*60)
print(f"\nReports saved to: {REPORT_DIR}")
print(f"Total findings: {len(nmap_data.get('findings', [])) + len(nikto_data.get('findings', []))}")
