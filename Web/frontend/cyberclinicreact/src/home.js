import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import logo from './logo.png';
import './home.css'

function Home() {
    const navigate = useNavigate();

    return (
        <div id="homepage">
            <nav id="navbar">
                <div id="navleft">
                    <span className="navlink" onClick={() => navigate('/')}>Home</span>
                    <span className="navlink" onClick={() => navigate('/faq')}>FAQ</span>
                </div>
                <div id="navbrand">
                    <img src={logo} alt="CyberClinic" id="nav-logo" />
                </div>
                <div id="navright">
                    <span className="navlink" onClick={() => navigate('/login')}>Login / Create</span>
                </div>
            </nav>

            <div id="bounding_box">
                <div id="aboutgrid">
                    <div className="gridItem">
                        <h2>Who Are We?</h2>
                        <p>CyberClinic is a cybersecurity platform developed at the University of Nevada, Reno by Team 13 as part of CS 426. We support the mission of the Cyber Clinic, a student-led nonprofit helping small businesses, tribal agencies, and local governments address cybersecurity risks they can't afford to fix alone.</p>
                        <br/>
                        <p>Small organizations often lack the budget for commercial vulnerability scanners, which can cost over $1,000 annually. CyberClinic integrates trusted open-source tools like Nmap and Nikto to scan public-facing systems and deliver plain-English reports with clear remediation steps, making professional security analysis accessible to everyone.</p>
                        <br/>
                        <p>Our platform provides automated vulnerability scanning, readable security reports, and a direct path to connect with Cyber Clinic experts for further remediation and education. No technical background required. Just register, submit a domain or IP, and receive actionable insights.</p>
                    </div>
                    <div className="gridItem">
                        <h2>How To Use?</h2>
                        <p>1. <strong>Register</strong> — Create a secure account<br/>
                        2. <strong>Submit</strong> — Enter a domain or IP to assess<br/>
                        3. <strong>Download</strong> — Get the lightweight local scanner<br/>
                        4. <strong>Scan</strong> — Run Nmap / Nikto on your targets<br/>
                        5. <strong>Report</strong> — Receive a plain-English security summary<br/>
                        6. <strong>Connect</strong> — Reach Cyber Clinic experts for guidance</p>
                    </div>
                    <div className="gridItem mission-block">
                        <h1>Our Mission</h1>
                        <p>To make cybersecurity accessible and affordable for small organizations by providing free, automated vulnerability scanning with clear, actionable reports. Lowering the financial and technical barriers that leave communities exposed to preventable risks.</p>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default Home;








