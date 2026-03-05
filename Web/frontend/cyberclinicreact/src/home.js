import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './home.css'

function Home() {
    const navigate = useNavigate();

    return (
        <div id="homepage">
            <nav id="navbar">
                <div id="navleft">
                    <button className="navlink" onClick={() => navigate('/')}>Home</button>
                    <button className="navlink" onClick={() => navigate('/faq')}>FAQ</button>
                </div>
                <div id="navbrand">CyberClinic</div>
                <div id="navright">
                    <button className="navlink" onClick={() => navigate('/login')}>Login / Create</button>
                </div>
            </nav>

            <div id="bounding_box">
                <div id="aboutgrid">
                    <div className="gridItem highlight">
                        <h2>Who Are We?</h2>
                    </div>
                    <div className="gridItem text-block">
                        <p>CyberClinic is a cybersecurity platform developed at the
                        University of Nevada, Reno. We provide automated vulnerability
                        scanning and security analysis tools.</p>
                    </div>
                    <div className="gridItem text-block">
                        <p>Our team of security researchers and engineers work together
                        to deliver fast, reliable, and actionable security reports.</p>
                    </div>
                    <div className="gridItem highlight">
                        <h2>How To Use?</h2>
                    </div>
                    <div className="gridItem mission-block">
                        <h1>Our Mission</h1>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default Home;