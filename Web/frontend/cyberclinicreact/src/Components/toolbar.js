import { useNavigate, useLocation } from "react-router-dom";
import { useState, useEffect } from "react";
import logo from '../img/logo_transparent.png';
import '../styles/toolbar.css';
import api from "../api";

export default function Toolbar() {
    const navigate = useNavigate();   
    const location = useLocation();
    const page = location.pathname
    const [loggedIn, setLoggedIn] = useState(false);
    useEffect(() => {
        api.get('/auth/status')
            .then(response => {
                setLoggedIn(response.data.logged_in);
            })
            .catch(error => {
                console.error('Error checking auth status:', error);
                setLoggedIn(false);
                if (page !== '/faq' && page !== '/')
                navigate('/');
            });
    }, []);

    return (
        <>
            <nav id="navbar">
                <div id="navleft">
                    <span className="navlink" onClick={() => navigate('/')}>Home</span>
                    <span className="navlink" onClick={() => navigate('/faq')}>FAQ</span>
                    {loggedIn && <span className="navlink" onClick={() => navigate('/dashboard')}>Dashboard</span>}
                </div>
                <div id="navbrand">
                    <img src={logo} alt="CyberClinic" id="nav-logo" />
                </div>
                <div id="navright">
                    {loggedIn ? (
                        <>
                            <span className="navlink" onClick={() => {
                                api.post('/auth/logout')
                                    .then(() => {
                                        sessionStorage.clear();
                                        setLoggedIn(false);
                                        navigate('/');
                                    })
                                    .catch(error => {
                                        console.error('Error logging out:', error);
                                        alert('Error logging out. Please try again.');
                                    });
                            }}>Logout</span>
                            <button type = "button" onClick={() => (navigate("/setting"))} style={{ textDecoration: 'none', background: 'none', border: 'none', cursor: 'pointer' }}>⚙️</button>
                        </>
                    ) : (
                        <span className="navlink" onClick={() => navigate('/login')}>Login / Create</span>
                    )}
                </div>
            </nav>
        </>
    ) 
} 