import { useState, useEffect,useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import Toolbar from './Components/toolbar';
import api from './api';
import './styles/dashboard.css';
import './styles/admindashboard.css';

function InviteModal({ onClose, onRefresh}){
    const [email, setEmail] = useState('');
    const [status,setStatus] = useState(null);
    const [msg, setMsg] = useState('');

    async function handleSubmit(e) {
        e.preventDefault();
        if(!email.trim()) return;
        setStatus('loading');
        setMsg('');
        try{
            const res = await api.post('/auth/admin/invite-user',{email:email.trim().toLowerCase()});
            setStatus('success');
            setMsg(res.data?.message || 'Invite sent.');
            setEmail('');
            onRefresh();
        }catch (err){
            setStatus('error');
            setMsg(err.response?.data?.error || 'Failed to send invite.');
        
        }
    }
    return(
        <div className="modal-overlay">
            <div className="modal-box">
                <div className="modal-header">
                    <h2>Invite User</h2>
                    <button className="modal-close" onClick={onClose}>x</button>
                </div>
                <p className="modal-desc">
                    send an invite to a new user. Theyll receive an email with instructions
                    to register under your organization.
                </p>
                <div className="modal-body">
                    <input
                        type="email"
                        className="invite-input"
                        placeholder="user@example.com"
                        value={email}
                        onChange={e => setEmail(e.target.value)}
                        onKeyDown={e => e.key === 'Enter' && handleSubmit(e)}
                        disabled={status === 'loading'}
                    />
                    {msg && (
                       <p className={status === 'success' ? 'feedback-success' : 'feedback-error'}> 
                            {msg}
                       </p>
                    )}
                    <div className="modal-footer">
                        <button className="btn-ghost" onClick={onClose}>Cancel </button>
                        <button 
                            className="btn-black"
                            onClick={handleSubmit}
                            disabled={status === 'loading' || !email.trim()}
                            style={{ opacity: (status === 'loading' || !email.trim()) ? 0.55 : 1 }}
                            > 
                                {status === 'loading' ? 'Sending...' : 'Send Invite'}
                            </button>
                    </div>
                </div>
            </div>
        </div>
    );
}
function AdminDashboard(){
    const navigate = useNavigate();

    const[users, setUsers] = useState([]);
    const[loading,setLoading] =useState(true);
    const[error, setError] =useState(null);
    const[toggleState, setToggleState] =useState({});
    const[showInvite, setShowInvite] =useState(false);
    
    const fetchUsers = useCallback((isInitial = false) => {
        if (isInitial) setLoading(true);
        api.get('/auth/admin/get-users')
        .then(res => {
            setUsers(res.data.users || []);
            setLoading(false);
            setError(null);
        })
        .catch(err => {
            const code = err.response?.status;
            if (code === 401 || code === 403){
                setError('Access denied. Admin privileges required.');
                setTimeout(() => navigate('/'), 3000);
            }else{
                setError('Failed to load users.');
            }
            setLoading(false);
        });
    }, [navigate]);
    useEffect(() => { fetchUsers(true);}, [fetchUsers]);
    async function handleToggle(user){
        const uid = user.user_id;
        setToggleState(prev => ({ ...prev, [uid]: 'loading' }));
        try{
            await api.post('/auth/admin/toggle-status', {
                user_id: uid,
                status: !user.active,
        });
        setUsers(prev =>
            prev.map(u => u.user_id === uid ? { ...u, active: !u.active } : u)
        );
        setToggleState(prev => ({ ...prev, [uid]: null}));
    }catch (err){
        console.error(err);
        setToggleState(prev => ({ ...prev, [uid]: 'error' }));
        setTimeout(() => setToggleState(prev => ({ ...prev, [uid]: null })), 3000)
    }
}
const pendingCount = users.filter(u => !u.active && u.email_verified).length;
return(
    <>
    <Toolbar />
    <div id="bounding_box">
        <div className="admin-header">
            <h1>Admin Dashboard</h1>
            <button className="btn-black" onClick={() => navigate('/dashboard')}> ← Dashboard
            </button>
            <button className="btn-black" onClick={() => setShowInvite(true)}> + Invite User
            </button>
        </div>
    <div className="content-card">
        <div className="admin-card-header">
            <h2> Organization Users</h2>
            <button
                className="btn-black"
                style={{padding: '6px 14px', fontSize: '13px', fontWeight: 'normal'}}
                onClick={() => fetchUsers(false)}>
                    ↻ Refresh
                </button>
        </div>
        {loading && <p style={{ color: '#666', padding: '10px' }}>Loading users...</p>}
        {error   && <p style={{ color: 'red',  padding: '10px' }}>{error}</p>}

        {!loading && !error && (
            <table id="scans-table">
                <thead>
                    <tr>
                        <th>Email</th>
                        <th>Phone</th>
                        <th>Email Verified</th>
                        <th>Status</th>
                        <th style={{ textAlign: 'right' }}>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {users.length === 0 && (
                        <tr>
                            <td colSpan="5" style={{ textAlign: 'center', color: '#888', padding: '20px' }}>
                            </td>
                        </tr>
                    )}
                    {users.map(user => {
                        const rowState = toggleState[user.user_id];
                        return(
                            <tr key={user.user_id}>
                                <td>{user.email}</td>
                                <td style={{ fontSize: '13px', color: '#555' }}>
                                    {user.phone_number || '—'}
                                </td>
                                <td>
                                    <span className={user.email_verified ? 'status-verified' : 'status-unverified'}>
                                        {user.email_verified ? 'Yes' : 'Pending'}
                                    </span>
                                </td>
                                <td>
                                    <span className={user.active ? 'status-active' : 'status-inactive'}>
                                        {user.active ? 'Active' : 'Inactive'}

                                    </span>
                                </td>
                                <td className="actions-cell">
                                    {rowState === 'error' ? (
                                        <span className="toggle-error">Failed — try again</span>
                                    ) : (
                                        <button
                                            className={`btn-black ${user.active ? 'btn-disable' : 'btn-enable'}`}
                                            disabled={rowState === 'loading'}
                                            style={{ opacity: rowState === 'loading' ? 0.55 : 1, minWidth: '120px' }}
                                            onClick={() => handleToggle(user)} > {rowState === 'loading' ? 'Updating...' : user.active ? 'Disable Access' : 'Enable Access'}
                                            </button>
                                    )}
                                </td>
                            </tr>
                        );
                    })}
                </tbody>
            </table>
        )}
    </div>
    {!loading && !error && pendingCount > 0 && (
                    <div className="pending-bar">
                        {pendingCount} user{pendingCount > 1 ? 's' : ''} pending activation — use Enable Access to approve.
                    </div>
                )}

            </div>

            {showInvite && (
                <InviteModal
                    onClose={() => setShowInvite(false)}
                    onRefresh={() => fetchUsers(false)}
                />
            )}
        </>
    );
}

export default AdminDashboard;