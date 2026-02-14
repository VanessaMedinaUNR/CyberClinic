import { useState, useEffect, useRef } from 'react'
import { useLocation, Link } from 'react-router-dom'
import Frame from 'react-frame-component';
import api from './api';
import './report.css';
import Toolbar from './toolbar';
import { TargetList, TargetTable } from './Components/Report/target';
export default function ReportViewer () {
    const { hash } = useLocation();
    const sectionRef = useRef(null);

    const [ reportData, setReportData ] = useState({
        report_title: '',
        report_date: '',
        client_name: '',
        targets: [],
        scan_type: '',
        scan_types_used: [],
        scan_duration: '',
        hosts_list: [],
        hosts_summary: {},
        overall_risk: '',
        scan_warning: '',
        finding_stats: {},
        hosts_scanned: 0,
        open_ports_total: 0,
        nmap_data: {},
        finding_types: {},
        tool_versions: {},
        default_tool_versions: [],
        services_summary: [],
        per_host_findings: {},
        findings: []
    });
    
    const location = useLocation();
    const report_id = location.state

    useEffect(() =>{
        loadReport();
    }, [])

    useEffect(() => {
        if (hash) {
        const element = document.getElementById(hash.replace('#', ''));
        if (element) {
            element.scrollIntoView({ behavior: 'smooth' });
        }
        }
    }, [hash]);

    async function loadReport() {
        'use server';
        api.get('/reports/' + report_id.id)
        .then(function (response) { 
            setReportData({
                ...reportData,
                report_title: response.data.report_title,
                report_date: response.data.report_date,
                client_name: response.data.client_name,
                targets: response.data.targets,
                scan_type: response.data.scan_type_display,
                scan_types_used: response.data.scan_types_used,
                scan_duration: response.data.scan_duration,
                hosts_list: response.data.hosts_list,
                hosts_summary: response.data.hosts_summary,
                overall_risk: response.data.overall_risk,
                overall_risk_class: response.data.overall_risk_class,
                scan_warning: response.data.scan_warning,
                finding_stats: response.data.finding_stats,
                hosts_scanned: response.data.hosts_scanned,
                open_ports_total: response.data.open_ports_total,
                nmap_data: response.data.nmap_data,
                finding_types: response.data.finding_types,
                tool_versions: response.data.tool_versions,
                default_tool_versions: response.data.default_tool_versions,
                services_summary: response.data.services_summary,
                per_host_findings: response.data.per_host_findings,
                findings: response.data.findings
            });
            for (const host in response.data.per_host_findings)
            {
                console.log(host);
            }
        })
        .catch(function (error) {
            console.log(error)
            return(
                <div id="bounding_box">
                    <Toolbar/>
                    <h1>Failed Fetching Report Data</h1>
                </div>
            )
        });
    }

    return(
        <div id = "bounding_box" style={{ alignItems: 'center'}}>
            <Toolbar/>
            <div 
                className="flex justify-center items-center"
                style={{ 
                    width: '90%',
                    border: '2px solid #919191',
                    marginLeft: 'auto',
                    marginRight: 'auto',
                    padding: '1em 5em 0 5em'
                }}
                //head={<link rel="stylesheet" href="./report.css" />}
            >
                <div className="cover-page">
                    <div className="cover-header">
                        <div className="cover-logo">Cyber Clinic</div>
                        <div className="cover-subtitle">University of Nevada, Reno • Computer Science & Engineering</div>
                        <div className="cover-title">
                            <h1>{reportData.client_name}</h1>
                            <h2>Security Assessment</h2>
                        </div>
                    </div>
                    <div className="cover-info">
                        <div className="cover-info-grid">
                            <div>
                                <div className="cover-info-label">Client</div>
                                <div className="cover-info-value">{ reportData.client_name }</div>
                            </div>
                            <div>
                                <div className="cover-info-label">Report Date</div>
                                <div className="cover-info-value">{ reportData.report_date }</div>
                            </div>
                            <div>
                                <div className="cover-info-label">Targets</div>
                                <div className="cover-info-value"><TargetList targets={reportData.targets}/></div>
                            </div>
                            <div>
                                <div className="cover-info-label">Scan Type</div>
                                <div className="cover-info-value">{ reportData.scan_type }</div>
                            </div>
                            <div>
                                <div className="cover-info-label">Contact</div>
                                <div className="cover-info-value">{ reportData.contact_email }</div>
                            </div>
                            <div>
                                <div className="cover-info-label">Duration</div>
                                <div className="cover-info-value">{ reportData.scan_duration }</div>
                            </div>
                        </div>
                        <div className="confidential-banner" style={{textAlign: 'center'}}>
                            <div className="confidential-title" style={{fontWeight: 800, fontSize:'1em'}}>CONFIDENTIAL</div>
                            <div className="confidential-text" style={{marginTop: '0.25em', fontSize:'0.95em'}}>This report contains sensitive security information and should be handled accordingly.</div>
                        </div>
                    </div>
                    <div className="cover-footer">
                        <div style={{textAlign: 'center'}}>Generated by Cyber Clinic - CS 425 Team 13</div>
                    </div>
                </div>

                <div className="content">
                    <h1>Executive Summary</h1>
                    <div className="executive-summary">
                        <p>This security assessment was conducted by Cyber Clinic on <strong>{ reportData.report_date }</strong>
                        &nbsp;for <strong>{ reportData.client_name }</strong>.</p>

                        <div>The scan targeted the following hosts:
                            <TargetTable targets={reportData.targets}/>
                        </div>

                        <p style={{marginTop: '0.8em', display: 'flex', alignItems: 'center', gap: '0.8em'}}>
                            <strong>Scan tools used:</strong>
                            {reportData.tools_used &&
                                reportData.tools_used.map((tool) => (
                                    <span style={{marginLeft: '0.5em'}}>
                                        {tool.name} {tool.version}
                                    </span>
                                ))
                            }
                            <span style={{flex: 1}}></span>
                            <strong>Overall Risk Level:</strong>
                            <span className={`overall-risk-pill ${ reportData.overall_risk_class }`} style={{marginLeft: '0.6em'}}>{ reportData.overall_risk }</span>
                        </p>

                        <div className="scan-warning">
                            { reportData.scan_warning }
                        </div>

                    </div>

                    <h2>Findings Overview</h2>
                    <div className="stats-grid">
                        <div className="stat-card critical">
                            <div className="stat-number">{ reportData.finding_stats.critical }</div>
                            <div className="stat-label">Critical</div>
                        </div>
                        <div className="stat-card high">
                            <div className="stat-number">{ reportData.finding_stats.high }</div>
                            <div className="stat-label">High</div>
                        </div>
                        <div className="stat-card medium">
                            <div className="stat-number">{ reportData.finding_stats.medium }</div>
                            <div className="stat-label">Medium</div>
                        </div>
                        <div className="stat-card low">
                            <div className="stat-number">{ reportData.finding_stats.low }</div>
                            <div className="stat-label">Low</div>
                        </div>
                        <div className="stat-card info">
                            <div className="stat-number">{ reportData.finding_stats.info }</div>
                            <div className="stat-label">Info</div>
                        </div>
                    </div>

                    <h2>Scan Details</h2>
                    <table>
                        <tbody>
                            <tr>
                                <th>Targets</th><td>{ reportData.hosts_list.join(', ') }</td>
                            </tr>
                            <tr><th>Scan Type</th><td>{ reportData.scan_type }</td></tr>
                            <tr><th>Scan Date</th><td>{ reportData.report_date }</td></tr>
                            <tr><th>Duration</th><td>{ reportData.scan_duration }</td></tr>
                            <tr><th>Hosts Scanned</th><td>{ reportData.hosts_scanned }</td></tr>
                            <tr><th>Open Ports</th><td>{ reportData.open_ports_total }</td></tr>
                        </tbody>
                    </table>

                    {/* Hosts Summary: show each scanned host with hostnames and ports to make multi-target output clear */}
                    <h2>Hosts Summary</h2>
                    { reportData.scan_types_used.includes('nmap') ?
                        <>
                            <>
                                {/* Table of contents for quick navigation when multiple hosts present */}
                                {reportData.hosts_list.length > 1 &&
                                    <div className="toc">
                                        <strong>Report Contents:</strong>
                                        <div style={{marginTop: '0.5em'}}>
                                            {reportData.hosts_list.map((host, index) => (
                                                <div key={index}>
                                                    <Link className="service-host-link" to={`#host-${ host.replaceAll('.', '-')}`} state={location.state}>
                                                        { reportData.hosts_summary[host] && reportData.hosts_summary[host][0] }
                                                    </Link>
                                                    <br/>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                }
                            </>

                            <>
                            {reportData.nmap_data.hosts.length > 0 ?
                                reportData.nmap_data.hosts.map((host, index) => (
                                    <div key={index} ref={sectionRef} id={`host-${ host.ip.replaceAll('.', '-') }`} className="host-section">
                                        <div className="host-header">
                                            <div>
                                                <h3 style={{marginBottom: '0.2em'}}>{ host.ip } {reportData.hosts_summary[host.ip] && reportData.hosts_summary[host.ip].length > 0 ? <>{reportData.hosts_summary[host.ip].join(', ')}</> : <></>}</h3>
                                                {/* build ports list from nmap_data.hosts if available */} 
                                                <div className="host-meta">Hostnames: {reportData.hosts_summary[host.ip] && reportData.hosts_summary[host.ip].length > 0 ? <>{reportData.hosts_summary[host.ip].join(', ')}</> : <>-</>} • Discovered ports: {
                                                    host.ports.length > 0 ?
                                                        <ul>
                                                            {host.ports.map((port, index) => (
                                                                <li key={index} style={{marginLeft: '0.8em'}}>{port.port} - {port.state}</li>
                                                            ))}
                                                        </ul>
                                                        : <>None</>
                                                    }
                                                </div>
                                            </div>
                                            <div className="host-badge">Findings: {reportData.per_host_findings[host.ip] ? reportData.per_host_findings[host.ip].length : <>0</> }</div>
                                        </div>
                                        <p style={{fontStyle: 'italic', color: '#444', marginTop: '0.6em'}}>Note: All findings listed under the 'Findings by Host' section for this host apply to { host.ip }. Use the links above to jump to each host section.</p>
                                    </div>
                                ))

                            : <p>No per-host details were available from Nmap.</p>}
                            </>
                        </>
                    : <p><em>Nmap was not run for this scan.</em></p>
                    }

                    <h2>Coverage Highlights</h2>
                    <div className="section-grid">
                        <div className="section-card">
                            <h4>Findings by Type</h4>
                            {reportData.finding_types ?
                                <table>
                                    <thead>
                                        <tr><th>Type</th><th>Count</th></tr>
                                    </thead>
                                    <tbody>
                                        {Object.keys(reportData.finding_types).map((type, index) => (
                                            <tr key={index}><td>{ type }</td><td>{ reportData.finding_types[type] }</td></tr>
                                        ))}
                                    </tbody>
                                </table>
                            :
                                <p>No categorized findings available.</p>
                            }
                        </div>
                        <div className="section-card">
                            <h4>Tools Used</h4>
                            <p><strong>Scan Tools:</strong> { reportData.scan_types_used.join(', ') }</p>
                            <p><strong>Versions:</strong></p>
                            {reportData.tool_versions.length > 0 ? 
                                <>
                                    {reportData.tool_versions.map((tool) => (
                                        <span key={tool.name} style={{marginLeft: '0.5em'}}>
                                            { tool.name }: { tool.version }
                                        </span>
                                    ))}
                                </>
                            :
                            <>
                                {reportData.default_tool_versions.map((tool) => (
                                    <span key={tool.name} style={{marginLeft: '0.5em'}}>
                                        { tool.name }: { tool.version }<br></br>
                                    </span>
                                ))}
                            </>}
                        </div>
                    </div>

                    <h2>Services Summary</h2>
                    { reportData.scan_types_used.includes('nmap') ?
                        <>
                            {reportData.services_summary.length > 0 ?
                                <>
                                        {reportData.nmap_data.hosts.map((host, index) => (
                                            <div key={index}>
                                                <h3>{host.ip}</h3>
                                                <table>
                                                    <thead>
                                                        <tr>
                                                            <th>Port</th>
                                                            <th>Protocol</th>
                                                            <th>Service</th>
                                                            <th>Product</th>
                                                            <th>Version</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        {host.ports.map((port, index) => (
                                                            <tr key={index}>
                                                                <td>{port.port}</td>
                                                                <td>{port.protocol}</td>
                                                                <td>{port.service.name}</td>
                                                                <td>{port.service.product}</td>
                                                                <td>{port.service.version}</td>
                                                            </tr>
                                                        ))}
                                                    </tbody>
                                                </table>
                                            </div>
                                        ))}
                                    </>
                                    : <p>No open services were detected.</p> }
                                </>
                            : <p><em>Nmap was not run for this scan; service summaries are unavailable.</em></p> }
                                    
                                    {/*
                                    {reportData.services_summary.map((svc) => (
                                        <tr>
                                            <td>{ svc.port }</td>
                                            <td>{ svc.protocol }</td>
                                            <td>{ svc.service }</td>
                                            <td>{ svc.product }</td>
                                            <td>{ svc.version }</td>
                                            <td>
                                                {/* Build list of host IPs providing this service by scanning nmap_data.hosts }
                                                
                                                    {% for p in hh.get('ports', []) %}
                                                        {% set p_port_raw = p.get('port') if (p is mapping) else (p) %}
                                                        {% set p_port = (p_port_raw|string).split('/')[0] if p_port_raw is not none else '' %}
                                                        {% set p_service = (p.get('service') if (p is mapping) else {}) and ((p.get('service') or {}).get('name')) %}

                                                        {% if p_port and (p_port|string) == (svc.port|string) and ((p_service|string) == (svc.service|string)) %}
                                                            {% if hh_ip and hh_ip not in hosts_list %}
                                                                {% set hosts_list = hosts_list + [hh_ip] %}
                                                            {% endif %}
                                                        {% endif %}
                                                    {% endfor %}
                                                {% endfor %}
                                                {{ hosts_list | join(', ') }}
                                            </td>
                                        </tr>
                                    */}

                    <h1>Detailed Findings</h1>
                    {reportData.finding_stats.total == 0 ?
                        <div className="no-findings">
                            <strong>No security findings were detected.</strong>
                            <p>Automated scans did not identify vulnerabilities. Manual testing recommended for higher assurance.</p>
                        </div>
                        :<>
                            {/* If per_host_findings exists and contains host-specific keys, render grouped sections */}
                            {/*host_only = host_keys|reject('equalto', 'global')|list if per_host_findings is defined else [] */}

                            { reportData.per_host_findings ?
                            <>
                                <h2>Findings by Host</h2>
                                {Object.entries(reportData.per_host_findings).map(([host, findings], index) => (
                                    <div key={index} id={`host-${ host.replaceAll('.', '-') }-findings`} className="host-section">
                                        <div className="host-header" style={{marginBottom: '0.6em'}}>
                                            <div>
                                                <h3 style={{margin: 0}}>Host: { host }</h3>
                                                <div className="host-meta">{findings.length} finding(s) • {/*reportData.hosts_summary[host].join(',')*/}</div>
                                            </div>
                                            <div><Link className="service-host-link" to={`#host-${ host.replaceAll('.', '-')}-findings`} state={location.state}>
                                                        View summary
                                                    </Link></div>
                                        </div>
                                        {findings.length > 0 ? <>
                                            {findings.map((finding, index) => (
                                                <div key={index} className="finding-card">
                                                    <div className="finding-header">
                                                        <h3>{ finding.title }</h3>
                                                        <span className={`severity-badge severity-${finding.severity}`}>{ finding.severity }</span>
                                                    </div>
                                                    <p><strong>Affected:</strong> { finding.affected_component }</p>
                                                    <p>{ finding.description }</p>
                                                    { finding.source &&
                                                        <p className="finding-source"><strong>Source:</strong> { finding.source }</p>
                                                    }
                                                    { finding.cvss &&
                                                        <p><strong>CVSS:</strong> { finding.cvss.score } ({ finding.cvss.severity })</p>
                                                    }
                                                    { finding.references &&
                                                        <p><strong>References:</strong> { finding.references.join(', ') }</p>
                                                    }
                                                    <p><strong>Recommendation:</strong> { finding['recommendation'] }</p>
                                                </div>
                                            ))}
                                        </>: <p>No findings for { host }. </p>}
                                    </div>
                                ))}

                                {/* Render global findings if present (primarily from web scans like Nikto) */}
                                {'nikto' in reportData.scan_types_used ? <>
                                    {Object.keys(reportData.per_host_findings).filter(([key]) => key === 'global').length() > 0 && <>
                                        <h2>Global / Shared Findings</h2>
                                        <p style={{fontStyle: 'italic', color: '#444'}}>These findings are at the site or application level and may apply across multiple hosts listed above.</p>
                                        {Object.keys(reportData.per_host_findings).filter(([key]) => key === 'global').map((finding) => (
                                            <div className="finding-card">
                                                <div className="finding-header">
                                                    <h3>{ finding.title }</h3>
                                                    <span className={`severity-badge severity-${finding.severity}`}>{ finding.severity }</span>
                                                </div>
                                                <p><strong>Affected:</strong> { finding.affected_component }</p>
                                                <p>{ finding.description }</p>
                                                {finding.source &&
                                                    <p className="finding-source"><strong>Source:</strong> { finding.source }</p>
                                                }
                                                {finding.cvss &&
                                                    <p><strong>CVSS:</strong> { finding.cvss.score } ({ finding.cvss.severity })</p>
                                                }
                                                {finding.references &&
                                                    <p><strong>References:</strong> { finding.references.join(', ') }</p>
                                                }
                                                <p><strong>Recommendation:</strong> { finding.recommendation }</p>
                                            </div>
                                        ))}
                                    </>}
                                </>: <p><em>Nikto was not run for this scan; web-level findings are unavailable.</em></p>}
                            </>
                            :
                            <>
                                {/* Fallback: render flat findings list as before */}
                                {reportData.findings.map((finding) => (
                                    <div className="finding-card">
                                        <div className="finding-header">
                                            <h3>{ finding.title }</h3>
                                            <span className={`severity-badge severity-${finding.severity}`}>{ finding.severity }</span>
                                        </div>
                                        <p><strong>Affected:</strong> { finding.affected_component }</p>
                                        <p>{ finding.description }</p>
                                        { finding.cvss &&
                                            <p><strong>CVSS:</strong> { finding.cvss.score } ({ finding.cvss.severity })</p>
                                        }
                                        { finding.references &&
                                            <p><strong>References:</strong> { finding.references.join(', ') }</p>
                                        }
                                        <p><strong>Recommendation:</strong> { finding.recommendation }</p>
                                    </div>
                                ))}
                            </>}

                        </>}

                    {/* Severity Classification */}
                    <h2>Severity Classification</h2>
                    <table className="classification-table">
                        <thead>
                            <tr>
                                <th style={{background: '#0033A0', color: 'white'}}>Severity</th>
                                <th style={{background: '#0033A0', color: 'white'}}>CVSS Score</th>
                                <th style={{background: '#0033A0', color: 'white'}}>Description</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr>
                                <td><span className="badge critical">Critical</span></td>
                                <td>9.0 - 10.0</td>
                                <td>Vulnerabilities that can be easily exploited and lead to complete system compromise</td>
                            </tr>
                            <tr>
                                <td><span className="badge high">High</span></td>
                                <td>7.0 - 8.9</td>
                                <td>Vulnerabilities that could lead to significant security breaches requiring skilled exploitation</td>
                            </tr>
                            <tr>
                                <td><span className="badge medium">Medium</span></td>
                                <td>4.0 - 6.9</td>
                                <td>Vulnerabilities that pose moderate risk and should be addressed during regular maintenance</td>
                            </tr>
                            <tr>
                                <td><span className="badge low">Low</span></td>
                                <td>0.1 - 3.9</td>
                                <td>Vulnerabilities that pose minimal risk but should still be remediated when convenient</td>
                            </tr>
                            <tr>
                                <td><span className="badge info">Info</span></td>
                                <td>0.0</td>
                                <td>Informational findings that do not pose direct security risks but may aid in security hardening</td>
                            </tr>
                        </tbody>
                    </table>

                    {/* Contact & Disclaimer Footer */}
                    <div className="report-footer" style={{marginTop: '2.5em'}}>
                        <div style={{maxWidth: '800px', margin: '0 auto', textAlign: 'left'}} className="disclaimer">
                            <h3>Contact Information</h3>
                            <p>For questions or assistance regarding this report, please contact Cyber Clinic:</p>
                            <p><strong>Email:</strong> { reportData.contact_email }</p>
                            <p><strong>Organization:</strong> { reportData.client_name }</p>
                            <p><strong>Website:</strong> <a href="https://github.com/VanessaMedinaUNR/CyberClinic">github.com/VanessaMedinaUNR/CyberClinic</a></p>
                            <p style={{height: '0.8em'}} aria-hidden="true"></p>
                            <hr />
                            <h3>Disclaimer</h3>
                            <p>This security assessment report is provided "as is" for informational purposes. While every effort has been made to ensure accuracy, Cyber Clinic makes no warranties regarding the completeness or accuracy of the information contained herein. The findings in this report reflect the state of security at the time of the assessment and may not account for vulnerabilities discovered after the scan date.</p>
                            <p style={{marginTop: '0.8em'}}>This report should be treated as confidential and shared only with authorized personnel responsible for security remediation.</p>
                        </div>
                    </div>

                    {/* Blue end footer matching cover accent */}
                </div>
            </div>
            <div className="page-end-footer">Generated on { reportData.report_date } • Report Version 1.0</div>
        </div>
    )
};