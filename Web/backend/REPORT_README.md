# Report JSON guide 

- The backend creates one file per report: `report_<id>.json`.
- Fetch that JSON and render the whole report in react, don’t parse the HTML version

How I fetch the file
```js
async function loadReport(id){
  const res = await fetch(`/reports/report_${id}.json`);
  if(!res.ok) throw new Error('Failed to load report');
  return await res.json();
}
```

What's expected in the JSON
These are the fields I rely on. If something’s missing fall back to a safe default
- report_title (string)
- report_date (string)
- scan_date (string)
- scan_type (string)
- scan_type_display (string)
- scan_types_used (string[])
- scan_duration (string)
- hosts_list (string[]) — ordered list of host IPs (use this order)
- hosts_display_list (string[])
- hosts_summary (object) — ip -> [hostnames]
- nmap_data.hosts (array) — each host: { ip, hostnames, ports, optional open_ports }
  - port items: { port: "80/tcp" | 80, protocol, state: "open"|"closed", service: {name,product,version} }
- services_summary (array) — rows: { port, protocol, service, product, version, count, optional hosts }
- per_host_findings (object) — ip -> [findings]; `global` allowed
- finding_stats (object)
- tool_versions, default_tool_versions
- generated_by, confidentiality_notice

Treat missing arrays as [] and missing objects as {}

Small helpers I use (copy to `src/utils/report.js`)
```js
export function normalizePort(p){
  if(p == null) return '';
  if(typeof p === 'object') p = p.port || p.portid || '';
  return String(p).split('/')[0];
}
export function getHostIp(h){
  if(!h) return null;
  return h.ip || h.ipv4 || h.ipv6 || null;
}
export function hostProvidesService(h, svc){
  const ports = h.ports || [];
  const svcPort = String(svc.port || '').split('/')[0];
  const svcName = (svc.service || '').toLowerCase();
  for(const p of ports){
    const pRaw = (p && (p.port || p.portid)) || p;
    if(normalizePort(pRaw) === svcPort){
      const pname = (p && p.service && p.service.name) ? String(p.service.name).toLowerCase() : '';
      if(!svcName || pname === svcName) return true;
    }
  }
  return false;
}
```

My recommended component map 
- ReportHeader: { report_title, report_date, scan_type_display, tool_versions }
- SummaryCards: { finding_stats }
- HostsList: { hosts_list, hosts_summary, nmap_hosts }
  - show hostnames, open_ports (use host.open_ports if available else compute)
- ServicesTable: { services_summary, nmap_hosts }
  - use services_summary[].hosts if present; otherwise compute via nmap_hosts
- FindingsList: { per_host_findings }
- Footer: { generated_by, confidentiality_notice }

Render rules I follow
- Prefer scan_type_display; fallback to building a label from scan_types_used.
- If `nmap` isn’t in scan_types_used show: "Nmap not run" in Hosts/Services.
- If `nikto` isn’t in scan_types_used show: "Nikto not run" for web/vuln findings.
- Always use hosts_list order — keeps the original report flow.

Normalize everything before rendering
I call a normalizeReport(raw) at the top of the page so components get a predictable shape. This should:
- Ensure r.scan_types_used is an array
- Populate r.hosts_list from nmap_data if missing
- Ensure each nmap host has open_ports
- Ensure services_summary rows include hosts (or compute them)

Quick mock JSON (copy to `public/mock_report.json` while it's developing)
Use this to build UI without running backend:

```json
{
  "report_title":"Security Assessment - example",
  "report_date":"Feb 12, 2026",
  "scan_type":"nmap",
  "scan_types_used":["nmap"],
  "hosts_list":["45.33.32.156"],
  "hosts_summary":{"45.33.32.156":["scanme.nmap.org"]},
  "nmap_data":{"hosts":[{"ip":"45.33.32.156","hostnames":["scanme.nmap.org"],"ports":[{"port":"80/tcp","protocol":"tcp","state":"open","service":{"name":"http","product":"Apache httpd","version":"2.4.7"}}],"open_ports":["80"]}]},
  "services_summary":[{"port":"80","protocol":"tcp","service":"http","product":"Apache httpd","version":"2.4.7","count":1,"hosts":["45.33.32.156"]}],
  "per_host_findings":{"45.33.32.156":[{"title":"Unencrypted HTTP Service","severity":"medium","affected_component":"45.33.32.156:80","source":"nmap","recommendation":"Enable HTTPS"}]},
  "finding_stats":{"critical":0,"high":0,"medium":1,"low":0,"info":1,"total":2,"overall_risk":"Low"}
}
```