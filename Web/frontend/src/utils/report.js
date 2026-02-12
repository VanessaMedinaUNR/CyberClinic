// Utilities to normalize and prepare report JSON for React components
// Drop this into your frontend and import helpers where needed.

export function normalizePort(p){
  if(p == null) return '';
  if(typeof p === 'object') p = p.port || p.portid || '';
  return String(p).split('/')[0];
}

export function getHostIp(h){
  if(!h) return null;
  return h.ip || h.ipv4 || h.ipv6 || (h.addresses && (h.addresses.ipv4 || h.addresses.ipv6)) || null;
}

export function hostProvidesService(h, svc){
  const ports = h.ports || [];
  const svcPort = String(svc.port || '').split('/')[0];
  const svcName = (svc.service||'').toLowerCase();
  for(const p of ports){
    const pRaw = (p && (p.port || p.portid)) || p;
    const pnum = normalizePort(pRaw);
    const pname = (p && p.service && p.service.name) ? String(p.service.name).toLowerCase() : '';
    if(pnum === svcPort && (pname === svcName || !svcName)) return true;
  }
  return false;
}

// Compute hosts array for each service row (if services_summary[].hosts missing)
export function computeServiceHosts(servicesSummary = [], nmapHosts = []){
  const normalizedHosts = (nmapHosts || []).map(h => ({ ip: getHostIp(h), host: h }));
  return servicesSummary.map(svc => {
    const svcPort = normalizePort(svc.port);
    const svcName = (svc.service||'').toLowerCase();
    const hosts = [];
    for(const {ip, host} of normalizedHosts){
      if(!ip) continue;
      if(hostProvidesService(host || {}, svc)) hosts.push(ip);
    }
    return Object.assign({}, svc, { hosts });
  });
}

// Build host.open_ports arrays if missing
export function ensureHostOpenPorts(nmapHosts = []){
  return (nmapHosts || []).map(h => {
    const open = [];
    for(const p of (h.ports || [])){
      const pRaw = (p && (p.port || p.portid)) || p;
      const state = (p && p.state) || (p && p.status) || (p && p.state_name) || '';
      if(String(state).toLowerCase() === 'open' || !p.state && pRaw){
        const pnum = normalizePort(pRaw);
        if(pnum) open.push(pnum);
      }
    }
    return Object.assign({}, h, { open_ports: Array.from(new Set(open)) });
  });
}

// Normalize entire report into a component-friendly shape (non-destructive)
export function normalizeReport(report = {}){
  const r = Object.assign({}, report);
  r.scan_types_used = Array.isArray(r.scan_types_used) ? r.scan_types_used : (r.scan_types_used ? [r.scan_types_used] : []);
  r.hosts_list = Array.isArray(r.hosts_list) ? r.hosts_list : (r.nmap_data && Array.isArray(r.nmap_data.hosts) ? (r.nmap_data.hosts.map(h => getHostIp(h)).filter(Boolean)) : []);
  r.nmap_data = r.nmap_data || {};
  r.nmap_data.hosts = ensureHostOpenPorts(r.nmap_data.hosts || []);
  r.services_summary = Array.isArray(r.services_summary) ? r.services_summary : [];
  // ensure services have hosts
  r.services_summary = computeServiceHosts(r.services_summary, r.nmap_data.hosts);
  r.per_host_findings = r.per_host_findings || {};
  r.finding_stats = r.finding_stats || { critical:0, high:0, medium:0, low:0, info:0, total:0, overall_risk: 'Unknown' };
  r.tool_versions = r.tool_versions || {};
  r.default_tool_versions = r.default_tool_versions || {};
  r.generated_by = r.generated_by || {};
  r.confidentiality_notice = r.confidentiality_notice || '';
  return r;
}
