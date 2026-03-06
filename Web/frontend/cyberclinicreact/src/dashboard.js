import { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import Toolbar from './Components/toolbar';
import api from './api';
import './dashboard.css';

function Dashboard() {
    const navigate = useNavigate();
    const [scans, setScans] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [generatingId, setGeneratingId] = useState(null);
    const [generateError, setGenerateError] = useState(null);
    const pollRef = useRef(null);

    const fetchScans = useCallback((isInitial = false) => {
        if (isInitial) setLoading(true);
        api.get('/reports/list')
            .then(res => {
                const reports = res.data.reports;
                setScans(reports);
                setLoading(false);
                setError(null);

                const hasActive = reports.some(s => s.status === 'running' || s.status === 'pending');
                if (hasActive) {
                    pollRef.current = setTimeout(() => fetchScans(false), 15000);
                }
            })
            .catch(err => {
                console.error(err);
                if (isInitial) {
                    setError('Failed to load scans.');
                    setLoading(false);
                }
            });
    }, []);

    useEffect(() => {
        fetchScans(true);
        return () => {
            if (pollRef.current) clearTimeout(pollRef.current);
        };
    }, [fetchScans]);

    async function handleGenerateReport(reportId) {
        setGeneratingId(reportId);
        setGenerateError(null);
        try {
            await api.post(`/reports/generate/${reportId}`, { format: 'json' });
            fetchScans(false);
        } catch (err) {
            console.error(err);
            setGenerateError(`Failed to generate report for report #${reportId}.`);
        } finally {
            setGeneratingId(null);
        }
    }

    async function handleDownload(reportId, downloadUrl) {
        try {
            const response = await api.get(downloadUrl.replace('/api', ''), { responseType: 'blob' });
            const contentType = response.headers['content-type'] || 'application/pdf';
            const ext = contentType.includes('pdf') ? 'pdf' : contentType.includes('html') ? 'html' : 'bin';
            const blob = new Blob([response.data], { type: contentType });
            const url = window.URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', `cyberclinic_report_${reportId}.${ext}`);
            document.body.appendChild(link);
            link.click();
            link.remove();
            setTimeout(() => window.URL.revokeObjectURL(url), 10000);
        } catch (err) {
            alert('Download failed: ' + (err.response?.data?.error || err.message));
        }
    }

    function getStatusBadge(status) {
        const styles = {
            completed: { background: '#d4edda', color: '#155724', padding: '3px 10px', borderRadius: '12px', fontSize: '12px' },
            running:   { background: '#fff3cd', color: '#856404', padding: '3px 10px', borderRadius: '12px', fontSize: '12px' },
            pending:   { background: '#e2e3e5', color: '#383d41', padding: '3px 10px', borderRadius: '12px', fontSize: '12px' },
        };
        return <span style={styles[status] || styles.pending}>{status}</span>;
    }

    function formatDate(dateStr) {
        if (!dateStr) return '—';
        return new Date(dateStr).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
    }

    const hasActive = scans.some(s => s.status === 'running' || s.status === 'pending');

    return (
        <div id="bounding_box">
            <Toolbar/>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                <h1 style={{ fontSize: '20px', color: '#333', margin: 0 }}>Dashboard</h1>
                <div style={{ display: 'flex', gap: '10px' }}>
                    <button className="btn-black" onClick={() => navigate("/newTarget")}>+ Configure New Target</button>
                    <button className="btn-black" onClick={() => navigate("/newScan")}>+ Configure New Scan</button>
                </div>
            </div>

            <div className="content-card">
                <div className="card-title-row" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <h2 style={{ margin: 0 }}>Active Scans &amp; Reports</h2>
                    {hasActive && (
                        <span style={{ fontSize: '12px', color: '#856404', background: '#fff3cd', padding: '4px 10px', borderRadius: '12px' }}>
                            ⟳ Auto-refreshing every 15s
                        </span>
                    )}
                </div>

                {loading && <p style={{ color: '#666', padding: '10px' }}>Loading scans...</p>}
                {error   && <p style={{ color: 'red',  padding: '10px' }}>{error}</p>}
                {generateError && <p style={{ color: 'red', padding: '10px' }}>{generateError}</p>}

                {!loading && !error && (
                    <table id="scans-table">
                        <thead>
                            <tr>
                                <th>Name / Target</th>
                                <th>Scan Type</th>
                                <th>Date</th>
                                <th>Status</th>
                                <th style={{ textAlign: 'right' }}>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {scans.length === 0 && (
                                <tr>
                                    <td colSpan="5" style={{ textAlign: 'center', color: '#888', padding: '20px' }}>
                                        No scans yet. Configure a target and run a scan to get started.
                                    </td>
                                </tr>
                            )}
                            {scans.map(scan => (
                                <tr key={scan.report_id || scan.scan_id}>
                                    <td>
                                        <strong>{scan.target.name}</strong>
                                        <br />
                                        <span style={{ fontSize: '12px', color: '#666' }}>{scan.target.value}</span>
                                    </td>
                                    <td>{scan.scan_type}</td>
                                    <td>{formatDate(scan.completed_at || scan.started_at)}</td>
                                    <td>{getStatusBadge(scan.status)}</td>
                                    <td style={{ textAlign: 'right' }}>
                                        {scan.has_report ? (
                                            <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                                                <button
                                                    className="btn-black"
                                                    onClick={() => navigate('/report', { state: { id: scan.report_id || scan.scan_id } })}
                                                >
                                                    View Report
                                                </button>
                                                <button
                                                    className="btn-black"
                                                    onClick={() => handleDownload(scan.report_id || scan.scan_id, scan.download_url)}
                                                >
                                                    ↓ Download
                                                </button>
                                            </div>
                                        ) : scan.status === 'completed' ? (
                                            <button
                                                className="btn-black"
                                                disabled={generatingId === (scan.report_id || scan.scan_id)}
                                                onClick={() => handleGenerateReport(scan.report_id || scan.scan_id)}
                                                style={{ opacity: generatingId === (scan.report_id || scan.scan_id) ? 0.6 : 1 }}
                                            >
                                                {generatingId === (scan.report_id || scan.scan_id) ? 'Generating...' : 'Generate Report'}
                                            </button>
                                        ) : (
                                            <span style={{ fontSize: '12px', color: '#888' }}>
                                                {scan.status === 'running' ? 'Scan in progress...' : 'Pending...'}
                                            </span>
                                        )}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>
        </div>
    );
}

export default Dashboard;





