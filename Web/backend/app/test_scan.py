#!/usr/bin/env python3
#Nmap + Nikto scan test that generates json report

"""
To run the script:
1. Open terminal
2. Go to the Web folder:
   cd path\to\CyberClinic\Web
3. Run inside Docker container as root:
   docker-compose exec -u root backend python test_scan.py

Example (run against multiple hosts):
  docker-compose exec -u root backend python3 test_scan.py badssl.com scanme.nmap.org testphp.vulnweb.com --scan-id 1002

Supported run modes (use --mode):
  - nmap  : run only Nmap (skip Nikto)
  - nikto : run only Nikto (skip Nmap)
  - both  : run both Nmap and Nikto (default)

Examples:
  docker compose run --rm -u root backend python3 /src/test_scan.py --mode nikto
  docker compose run --rm -u root backend python3 /src/test_scan.py --mode nmap
  docker compose run --rm -u root backend python3 /src/test_scan.py --mode both
"""
import os
import sys
import subprocess
from datetime import datetime
try:
    from app.report_generator import CustomReportGenerator
except Exception as _e:
    #fallback when jinja2 or full report_generator isn't available
    import json
    class CustomReportGenerator:
        def __init__(self):
            self.reports_dir = REPORT_DIR if 'REPORT_DIR' in globals() else '/tmp'
        def generate_report(self, report_data, output_format='json'):
            scan_id = report_data.get('scan_id', '0000')
            out_json = os.path.join(self.reports_dir, f"report_{scan_id}.json")
            #try to merge any provided result files into a simple report
            merged = dict(report_data)
            merged.setdefault('nmap', {})
            merged.setdefault('nikto', {'findings': []})
            for p in report_data.get('results_paths', []) or []:
                try:
                    if p.endswith('.xml'):
                        #try to parse with NmapParser if available
                        try:
                            np = NmapParser()
                            parsed = np.parse_xml(p)
                            merged['nmap'] = parsed
                        except Exception:
                            merged['nmap']['raw'] = f"Could not parse {p}"
                    elif p.endswith('.json'):
                        try:
                            with open(p, 'r', encoding='utf-8', errors='ignore') as fh:
                                data = json.load(fh)
                                #assume nikto format
                                merged['nikto']['findings'].extend(data.get('findings', []) if isinstance(data, dict) else [])
                        except Exception:
                            merged['nikto']['findings'].append({'file': p, 'note': 'unreadable'})
                except Exception:
                    pass
            #write JSON
            os.makedirs(self.reports_dir, exist_ok=True)
            with open(out_json, 'w', encoding='utf-8') as jf:
                json.dump(merged, jf, indent=2)
            if output_format == 'json':
                return out_json
            #for html, it writes a tiny stub that references the json file
            out_html = os.path.join(self.reports_dir, f"report_{scan_id}.html")
            try:
                with open(out_html, 'w', encoding='utf-8') as hf:
                    hf.write('<html><head><meta charset="utf-8"><title>Scan Report</title></head>')
                    hf.write('<body><h1>Scan Report (minimal)</h1>')
                    hf.write('<pre>')
                    hf.write(json.dumps(merged, indent=2))
                    hf.write('</pre></body></html>')
                return out_html
            except Exception:
                return out_json

from app.parsers.nmap_parser import NmapParser
from app.parsers.nikto_parser import NiktoParser

#Use ONLY approved targets for testing and development
DEFAULT_TARGET = "scanme.nmap.org"

#allows CLI input, domain, single IP, CIDR, or comma separated list
import argparse
parser = argparse.ArgumentParser(description='Run test NMap/Nikto scan and generate report')
#accept multiple positional targets (space separated) or a single comma-separated value
parser.add_argument('targets', nargs='*', default=[DEFAULT_TARGET],
                    help='Targets to scan. Provide one or more targets separated by space, or a single comma-separated string. Each target may be a domain, IP, CIDR, or a path to a file with targets.')
parser.add_argument('--scan-id', type=int, default=1001, help='Scan id to use for generated report files')
parser.add_argument('--expand-cidr', action='store_true', help='Expand CIDR ranges into individual IPs for per-host operations (limited to 256 hosts)')
parser.add_argument('--mode', choices=('nmap','nikto','both'), default='both', help='Run only nmap, only nikto, or both (default: both)')
args = parser.parse_args()
#normalize targets, if user provided multiple positional args, join with comma, if a single arg containing commas, keep as is
if args.targets:
    #args.targets is a list, if user passed a single comma separated string it will be that single element
    if len(args.targets) == 1 and ',' in args.targets[0]:
        TARGET_ARG = args.targets[0]
    else:
        TARGET_ARG = ','.join(args.targets)
else:
    TARGET_ARG = DEFAULT_TARGET
SCAN_ID = args.scan_id
EXPAND_CIDR = args.expand_cidr
MODE = args.mode

SCAN_DIR = "/tmp/cyberclinic_scans"
REPORT_DIR = "/src/reports"

os.makedirs(SCAN_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)
print("\n" + "=" * 60)
print("CYBER CLINIC - SCAN TEST")
print("=" * 60)

#record real start time for duration calculation
start_time = datetime.now().isoformat()

#allow passing multiple targets via CLI or MULTI_TARGETS env var
#accepts a single host, comma separated list, CIDR, or a path to a file with one target per line
def parse_targets(input_arg):
    if not input_arg:
        return [DEFAULT_TARGET]
    input_arg = input_arg.strip()
    #if the argument points to a file, read targets from it
    if os.path.exists(input_arg) and os.path.isfile(input_arg):
        with open(input_arg, "r", encoding="utf-8", errors="ignore") as fh:
            lines = [l.strip() for l in fh if l.strip() and not l.strip().startswith('#')]
            return lines or [DEFAULT_TARGET]
    #comma separated list
    if ',' in input_arg:
        return [t.strip() for t in input_arg.split(',') if t.strip()]
    #single target (domain, IP or CIDR)
    return [input_arg]

#determine targets: prefer CLI arg, then MULTI_TARGETS env var, then fallback to constant DEFAULT_TARGET
env_arg = os.getenv('MULTI_TARGETS')
raw_input = TARGET_ARG if TARGET_ARG else (env_arg or DEFAULT_TARGET)
TARGETS = parse_targets(raw_input)

#optionally expand CIDR ranges into individual IPs for testing per host actions
if EXPAND_CIDR:
    import ipaddress
    expanded = []
    for t in TARGETS:
        if '/' in t:
            try:
                net = ipaddress.ip_network(t, strict=False)
                #for safety limit expansion to 256 hosts
                hosts = list(net.hosts())
                if len(hosts) > 256:
                    print(f"CIDR {t} expands to {len(hosts)} hosts; skipping expansion for safety")
                    expanded.append(t)
                else:
                    expanded.extend([str(h) for h in hosts])
            except Exception as e:
                print(f"WARN failed to expand CIDR {t}: {e}; keeping as-is")
                expanded.append(t)
        else:
            expanded.append(t)
    TARGETS = expanded

print("Targets:", ", ".join(TARGETS))

#STEP 1: Run Nmap
if MODE != 'nikto':
    print("\n[1/4] Running Nmap scan on", ", ".join(TARGETS))
    nmap_file = f"{SCAN_DIR}/nmap_scan.xml"
    try:
        #iff multiple targets, use -iL with a temporary list file
        if len(TARGETS) > 1:
            targets_list_file = f"{SCAN_DIR}/nmap_targets.txt"
            with open(targets_list_file, 'w', encoding='utf-8') as tf:
                for t in TARGETS:
                    tf.write(t + "\n")
            nmap_cmd = ["nmap", "-sV", "-p", "80,443", "-iL", targets_list_file, "-oX", nmap_file]
        else:
            nmap_cmd = ["nmap", "-sV", "-p", "80,443", TARGETS[0], "-oX", nmap_file]

        result = subprocess.run(
            nmap_cmd,
            capture_output=True,
            timeout=120,
            text=True
        )
        if result.returncode == 0 and os.path.exists(nmap_file):
            print(f"OK Nmap complete: {nmap_file}")
            with open(nmap_file, encoding="utf-8", errors="ignore") as f:
                size = len(f.read()) / 1024
                print(f"  File size: {size:.1f} KB")
        else:
            print(f"FAIL Nmap failed with code {result.returncode}")
            if result.stderr:
                print(f"  Error: {result.stderr}")
            sys.exit(1)
    except Exception as e:
        print(f"FAIL Nmap error: {e}")
        sys.exit(1)
else:
    print("\n[1/4] Skipping Nmap (mode=nikto).")
    nmap_file = None

#STEP 2: Parse results (only if Nmap ran)
if MODE != 'nikto' and nmap_file and os.path.exists(nmap_file):
    print("\n[2/4] Parsing scan results...")
    try:
        nmap_parser = NmapParser()
        nmap_data = nmap_parser.parse_xml(nmap_file)
        print("OK Nmap parsed successfully")
        print(f"  Hosts found: {nmap_data.get('total_hosts', 0)}")
        print(f"  Open ports: {nmap_data.get('total_open_ports', 0)}")
        print(f"  Findings: {len(nmap_data.get('findings', []))}")
    except Exception as e:
        print(f"FAIL Nmap parsing failed: {e}")
        sys.exit(1)
else:
    #provide a minimal nmap_data shape so downstream logic still works when Nmap is skipped
    nmap_data = {'hosts': [], 'total_hosts': 0, 'total_open_ports': 0, 'findings': []}

#STEP 3: Run Nikto (moved after parsing Nmap)
if MODE != 'nmap':
    print("\n[3/4] Running Nikto scans based on Nmap results")
    nikto_file = f"{SCAN_DIR}/nikto_scan.json"
    nikto_success = False
    per_host_nikto_files = []

    #if Nmap found multiple hosts or target is a range, run per host Nikto
    hosts = nmap_data.get('hosts', []) or []
    if len(hosts) > 1:
        print("Detected multiple hosts in Nmap output. Running Nikto per host (best-effort)...")
        for idx, host in enumerate(hosts):
            addr = host.get('ip') or host.get('ipv4') or (host.get('addresses') or [None])[0]
            if isinstance(addr, dict):
                addr = addr.get('addr')
            if not addr:
                continue
            nikto_host_file = f"{SCAN_DIR}/nikto_scan_{idx}_{addr.replace(':','_')}.json"
            try:
                subprocess.run(
                    [
                        "nikto",
                        "-h", addr,
                        "-Tuning", "x",
                        "-C", "all",
                        "-usecookies",
                        "-timeout", "10",
                        "-Format", "json",
                        "-output", nikto_host_file
                    ],
                    capture_output=True,
                    timeout=180,
                    text=True
                )
                if os.path.exists(nikto_host_file) and os.path.getsize(nikto_host_file) > 100:
                    print(f"  OK Nikto for {addr}: {nikto_host_file}")
                    per_host_nikto_files.append(nikto_host_file)
            except Exception as e:
                print(f"  WARN per-host Nikto failed for {addr}: {e}")

    elif len(TARGETS) > 1 and not hosts:
        #nmap produced no hosts but user supplied multiple targets,  try Nikto per provided target
        print("Nmap returned no hosts, but multiple targets were provided. Running Nikto per provided target list...")
        for idx, addr in enumerate(TARGETS):
            nikto_host_file = f"{SCAN_DIR}/nikto_scan_{idx}_{addr.replace(':','_')}.json"
            try:
                subprocess.run(
                    [
                        "nikto",
                        "-h", addr,
                        "-Tuning", "x",
                        "-C", "all",
                        "-usecookies",
                        "-timeout", "10",
                        "-Format", "json",
                        "-output", nikto_host_file
                    ],
                    capture_output=True,
                    timeout=180,
                    text=True
                )
                if os.path.exists(nikto_host_file) and os.path.getsize(nikto_host_file) > 100:
                    print(f"  OK Nikto for {addr}: {nikto_host_file}")
                    per_host_nikto_files.append(nikto_host_file)
            except Exception as e:
                print(f"  WARN per-host Nikto failed for {addr}: {e}")

    else:
        #single host/domain, run a single Nikto against the first provided target
        try:
            result = subprocess.run(
                [
                    "nikto",
                    "-h", TARGETS[0],
                    "-Tuning", "x",
                    "-C", "all",
                    "-usecookies",
                    "-timeout", "10",
                    "-Format", "json",
                    "-output", nikto_file
                ],
                capture_output=True,
                timeout=300,
                text=True
            )
            if os.path.exists(nikto_file) and os.path.getsize(nikto_file) > 100:
                print(f"OK Nikto complete: {nikto_file}")
                with open(nikto_file, encoding="utf-8", errors="ignore") as f:
                    lines = len(f.readlines())
                    print(f"  Lines: {lines}")
                nikto_success = True
            else:
                print("WARN Nikto produced no output or small file")
                nikto_success = False
        except subprocess.TimeoutExpired:
            print("WARN Nikto timeout after 300 seconds - continuing")
            nikto_success = False
        except FileNotFoundError:
            print("WARN Nikto not found - continuing")
            nikto_success = False
        except Exception as e:
            print(f"WARN Nikto error: {e} - continuing")
            nikto_success = False
else:
    print("\n[2/4] Skipping Nikto (mode=nmap).")
    nikto_file = None
    nikto_success = False
    per_host_nikto_files = []

#record completed time for accurate duration
completed_time = datetime.now().isoformat()

#STEP 4: Generate report
print("\n[4/4] Generating report...")

#gets target IP from Nmap
#prefer original textual target for report name if provided
report_target_name = TARGET_ARG or env_arg or DEFAULT_TARGET

# determine target_ip for naming and display
target_ip = TARGETS[0]
if nmap_data.get('hosts') and len(nmap_data['hosts']) > 0:
    host = nmap_data['hosts'][0]
    target_ip = host.get('ip') or host.get('ipv4') or target_ip
    print(f"  Target IP: {target_ip}")

#build results_paths for report generator
results_paths = []
if nmap_file and os.path.exists(nmap_file):
    results_paths.append(nmap_file)
if per_host_nikto_files:
    results_paths.extend(per_host_nikto_files)
elif nikto_success and nikto_file and os.path.exists(nikto_file):
    results_paths.append(nikto_file)

#build nikto_data for summary 
nikto_data = {}
if per_host_nikto_files:
    merged = {'findings': []}
    nikto_parser = NiktoParser()
    for pf in per_host_nikto_files:
        try:
            parsed = nikto_parser.parse_file(pf)
            merged['findings'].extend(parsed.get('findings', []) or [])
        except Exception:
            pass
    nikto_data = merged
elif nikto_success and os.path.exists(nikto_file):
    try:
        nikto_parser = NiktoParser()
        nikto_data = nikto_parser.parse_file(nikto_file)
    except Exception:
        nikto_data = {}

now = datetime.now()

#determines target type for mixed inputs (ip, domain, ip_range, mixed)
def _compute_target_type_from_list(tlist):
    import re
    types = set()
    for t in tlist or []:
        if not t:
            continue
        s = str(t).strip()
        #CIDR or range
        if '/' in s:
            types.add('ip_range')
            continue
        if '-' in s and any(ch.isdigit() for ch in s):
            types.add('ip_range')
            continue
        #IPv4 regex
        if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', s):
            types.add('ip')
            continue
        #contains letters -> domain
        if any(c.isalpha() for c in s):
            types.add('domain')
            continue
        #fallback to numeric with dots -> ip, otherwise domain
        if re.match(r'^[0-9\.]+$', s):
            types.add('ip')
        else:
            types.add('domain')
    if not types:
        return 'unknown'
    if len(types) == 1:
        return next(iter(types))
    return 'mixed'

computed_target_type = _compute_target_type_from_list(TARGETS)

report_data = {
    'scan_id': SCAN_ID,
    'scan_type': ('nmap' if MODE == 'nmap' else ('nikto' if MODE == 'nikto' else 'full')),
    'target': {
        'name': report_target_name,
        'value': target_ip,
        'type': computed_target_type
    },
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
    generator = CustomReportGenerator()
    generator.reports_dir = REPORT_DIR
    try:
        json_report = generator.generate_report(report_data, output_format='json')
        html_report = generator.generate_report(report_data, output_format='html')
    except Exception as gen_err:
        print(f"Report generation failed inside generator: {gen_err}. Falling back to simple writer.")
        #build minimal merged report
        import json as _json
        merged = dict(report_data)
        merged.setdefault('nmap', {})
        merged.setdefault('nikto', {'findings': []})
        for p in results_paths:
            try:
                if isinstance(p, str) and p.endswith('.xml'):
                    try:
                        np = NmapParser()
                        parsed = np.parse_xml(p)
                        merged['nmap'] = parsed
                    except Exception:
                        merged['nmap'].setdefault('raw_files', []).append(p)
                elif isinstance(p, str) and p.endswith('.json'):
                    try:
                        with open(p, 'r', encoding='utf-8', errors='ignore') as fh:
                            data = _json.load(fh)
                            if isinstance(data, dict):
                                merged['nikto']['findings'].extend(data.get('findings', []) or [])
                    except Exception:
                        merged['nikto']['findings'].append({'file': p, 'note': 'unreadable'})
            except Exception:
                pass
        os.makedirs(REPORT_DIR, exist_ok=True)
        json_report = os.path.join(REPORT_DIR, f"report_{report_data.get('scan_id', SCAN_ID)}.json")
        with open(json_report, 'w', encoding='utf-8') as jf:
            _json.dump(merged, jf, indent=2)
        html_report = os.path.join(REPORT_DIR, f"report_{report_data.get('scan_id', SCAN_ID)}.html")
        try:
            with open(html_report, 'w', encoding='utf-8') as hf:
                hf.write('<html><head><meta charset="utf-8"><title>Scan Report</title></head>')
                hf.write('<body>')
                hf.write(f"<h1>Scan {report_data.get('scan_id')} - Minimal Report</h1>")
                hf.write('<h2>Summary</h2>')
                hf.write('<pre>')
                hf.write(_json.dumps({'nmap_summary': merged.get('nmap', {}), 'nikto_findings_count': len(merged.get('nikto', {}).get('findings', []))}, indent=2))
                hf.write('</pre>')
                hf.write('<h2>Full JSON</h2><pre>')
                hf.write(_json.dumps(merged, indent=2))
                hf.write('</pre></body></html>')
        except Exception:
            #if html write fails, continue with json only
            html_report = json_report
    print(f"OK JSON report: {os.path.basename(json_report)}")
    print(f"OK HTML report: {os.path.basename(html_report)}")
    #attempt to render the full Jinja2 template-based HTML by invoking the real generator
    try:
        from app.report_generator import CustomReportGenerator as RealGenerator
        try:
            real_gen = RealGenerator()
            #ensure real generator writes to the expected reports directory used by this script
            try:
                real_gen.reports_dir = REPORT_DIR
            except Exception:
                pass
            #try to generate a full HTML report using the original scan data structure
            try:
                full_html = real_gen.generate_report(report_data, output_format='html')
                print(f"OK Full HTML report (template): {os.path.basename(full_html)}")
                html_report = full_html
            except Exception as e:
                print(f"Template generator failed to create HTML: {e}")
        except Exception as e:
            print(f"Could not initialize real generator: {e}")
    except Exception:
        #real generator not available in this environment
        pass
except Exception as e:
    print(f"FAIL Report generation failed: {e}")
    sys.exit(1)

print("\n" + "=" * 60)
print("Scan test completed")
print("=" * 60)
print(f"\nReports saved to: {REPORT_DIR}")
print(f"Total findings: {len(nmap_data.get('findings', [])) + len(nikto_data.get('findings', []))}")
