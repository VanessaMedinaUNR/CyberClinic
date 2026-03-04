"""
Cyber Clinic - Nmap + Nikto scan test that generates a PDF report.

To run the script:
1. Open terminal
2. Navigate to the Web folder:
   cd path/to/CyberClinic/Web
3. Run inside Docker container as root:
   docker compose exec -u root backend-dev python test_scan.py

Approved targets for security testing (explicitly allow scanning):
  - scanme.nmap.org
  - badssl.com
  - juice-shop.herokuapp.com
"""

import os
import sys
import subprocess
from datetime import datetime

#ensure the /src working directory is on the path when running inside Docker
sys.path.insert(0, '/src')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.report_generator import CustomReportGenerator
from app.parsers.nmap_parser import NmapParser
from app.parsers.nikto_parser import NiktoParser

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TARGET     = "scanme.nmap.org"
SCAN_DIR   = "/tmp/cyberclinic_scans"
REPORT_DIR = "/src/app/reports"

os.makedirs(SCAN_DIR,   exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

print("\n" + "=" * 60)
print("CYBER CLINIC - SCAN TEST")
print("=" * 60)

# ---------------------------------------------------------------------------
# STEP 1: Nmap
# ---------------------------------------------------------------------------
print(f"\n[1/4] Running Nmap scan on {TARGET}")
nmap_file = f"{SCAN_DIR}/nmap_scan.xml"
try:
    result = subprocess.run(
        ["nmap", "-sV", "-p", "80,443", TARGET, "-oX", nmap_file],
        capture_output=True, timeout=120, text=True
    )
    if result.returncode == 0 and os.path.exists(nmap_file):
        size = os.path.getsize(nmap_file) / 1024
        print(f"  ✓ Nmap complete: {nmap_file}  ({size:.1f} KB)")
    else:
        print(f"  ✗ Nmap failed (exit {result.returncode})")
        if result.stderr:
            print(f"    {result.stderr.strip()}")
        sys.exit(1)
except subprocess.TimeoutExpired:
    print("  ✗ Nmap timed out after 120 s")
    sys.exit(1)
except FileNotFoundError:
    print("  ✗ nmap not found — is it installed in this container?")
    sys.exit(1)
except Exception as e:
    print(f"  ✗ Nmap error: {e}")
    sys.exit(1)

# ---------------------------------------------------------------------------
# STEP 2: Nikto
# ---------------------------------------------------------------------------
print(f"\n[2/4] Running Nikto scan on {TARGET}")
nikto_file    = f"{SCAN_DIR}/nikto_scan.txt"
nikto_success = False
try:
    result = subprocess.run(
        ["nikto", "-h", TARGET, "-output", nikto_file],
        capture_output=True, timeout=300, text=True
    )
    if os.path.exists(nikto_file) and os.path.getsize(nikto_file) > 100:
        with open(nikto_file) as fh:
            lines = len(fh.readlines())
        print(f"  ✓ Nikto complete: {nikto_file}  ({lines} lines)")
        nikto_success = True
    else:
        print("  ✗ Nikto produced no output — continuing with Nmap only")
except subprocess.TimeoutExpired:
    print("  ✗ Nikto timed out after 300 s — continuing with Nmap only")
except FileNotFoundError:
    print("  ✗ nikto not found — continuing with Nmap only")
except Exception as e:
    print(f"  ✗ Nikto error: {e} — continuing with Nmap only")

# ---------------------------------------------------------------------------
# STEP 3: Parse results
# ---------------------------------------------------------------------------
print("\n[3/4] Parsing scan results...")

try:
    nmap_parser = NmapParser()
    nmap_data   = nmap_parser.parse_xml(nmap_file)
    print(f"  ✓ Nmap parsed")
    print(f"    Hosts found:  {nmap_data.get('total_hosts', 0)}")
    print(f"    Open ports:   {nmap_data.get('total_open_ports', 0)}")
    print(f"    Findings:     {len(nmap_data.get('findings', []))}")
except Exception as e:
    print(f"  ✗ Nmap parse failed: {e}")
    sys.exit(1)

nikto_data = {}
if nikto_success and os.path.exists(nikto_file):
    try:
        nikto_parser = NiktoParser()
        nikto_data   = nikto_parser.parse_file(nikto_file)
        print(f"  ✓ Nikto parsed")
        print(f"    Findings:     {len(nikto_data.get('findings', []))}")
    except Exception as e:
        print(f"  ✗ Nikto parse failed: {e}")
        nikto_data = {}
else:
    print("    Nikto skipped")

# ---------------------------------------------------------------------------
# STEP 4: Generate report
# ---------------------------------------------------------------------------
print("\n[4/4] Generating report...")

#derive target IP from Nmap output if available
target_ip = TARGET
if nmap_data.get('hosts'):
    host      = nmap_data['hosts'][0]
    target_ip = host.get('ip') or host.get('hostname') or TARGET
    print(f"    Target IP: {target_ip}")

results_paths = [nmap_file]
if nikto_success and os.path.exists(nikto_file):
    results_paths.append(nikto_file)

now = datetime.now()
report_data = {
    'scan_id':   1001,
    'scan_type': 'full',       # process both nmap and nikto data
    'target': {
        'name':  TARGET,
        'value': target_ip,
        'type':  'domain'
    },
    'client': {
        'name':  'Cyber Clinic',
        'email': 'example@unr.edu'
    },
    'timestamps': {
        'started':   now.strftime('%Y-%m-%d %H:%M:%S'),
        'completed': now.strftime('%Y-%m-%d %H:%M:%S')
    },
    'results_paths': results_paths
}

try:
    generator              = CustomReportGenerator()
    generator.reports_dir  = REPORT_DIR

    html_report = generator.generate_report(report_data, output_format='html')
    print(f"  ✓ HTML report: {os.path.basename(html_report)}")

    try:
        pdf_report = generator.generate_report(report_data, output_format='pdf')
        print(f"  ✓ PDF report:  {os.path.basename(pdf_report)}")
    except RuntimeError as e:
        print(f"  ✗ PDF skipped: {str(e)[:80]}")

except Exception as e:
    print(f"  ✗ Report generation failed: {e}")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
total_findings = (
    len(nmap_data.get('findings', []))  +
    len(nikto_data.get('findings', []))
)

print("\n" + "=" * 60)
print("Scan test completed")
print("=" * 60)
print(f"\n  Reports saved to : {REPORT_DIR}")
print(f"  Total findings   : {total_findings}")
print()
