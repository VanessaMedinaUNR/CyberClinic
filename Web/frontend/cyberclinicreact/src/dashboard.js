import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
//class is the link between your HTML and CSS
import './dashboard.css';

function Dashboard() {
    const navigate = useNavigate(); //able to navigate between pages 

    async function handleSubmit(e){
        e.preventDefault();
    }
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();

    }
    console.log("client_id: " + getCookie("client_id"));
    console.log("user_id: " + getCookie("user_id"));

    return (
        <div id="bounding_box">
            <div className="dashboard-header">
                <div className="brand-section">
                    <h1>CyberClinic</h1>
                    <p>University of Nevada, Reno</p>
                </div>
                <div className="user-controls">
                    <span id="User-email"> </span> 
                    <button type = "button" onClick={() => (navigate("/setting"))} style={{ textDecoration: 'none', background: 'none', border: 'none', cursor: 'pointer' }}>⚙️</button>
                </div>
             </div>
            {/* remember that when trying to navigate it is /... not ./ been having issues */}
             <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
             <h1 style={{ fontSize: '20px', color: '#333', margin: 0 }}>Dashboard </h1>
             <button className="btn-black" id = "newScan" onClick={() => (navigate("/newScan"))}>+ Configure New Scan 
             </button>
            </div>
            <div className="content-card">
                <div className="card-title-row">
                    <h2>Active scan & Reports</h2>
                </div>
                <table id="scans-table">
                    <thead>
                        <tr>
                            <th>Name / Target</th>
                            <th>Date</th>
                            <th> Security Rating </th>
                            <th style={{ textAlign: 'right' }}>Actions</th>
                        </tr>
                    </thead>
                    <tbody>

                    </tbody>
                </table>
            </div>
        </div>
    );
}
export default Dashboard;

   



