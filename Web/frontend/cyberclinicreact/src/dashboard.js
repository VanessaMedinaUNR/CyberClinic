import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Toolbar from './Components/toolbar';
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

    return (
        <div id="bounding_box">
            <Toolbar/>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                <h1 style={{ fontSize: '20px', color: '#333', margin: 0 }}>Dashboard </h1>
                <button className="btn-black" id = "newTarget" onClick={() => (navigate("/newTarget"))}>+ Configure New Target 
                </button>
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

   



