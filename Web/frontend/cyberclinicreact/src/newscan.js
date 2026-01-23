import { useState } from 'react';
import { useNavigate } from 'react-router-dom';

function NewScan () {

    const navigate = useNavigate();
    const[ selectedTarget, setSelectedTarget ] = useState("");
    const [ scanType, setScanType ]  = useState("");
    

    function getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
    }

    async function handleSubmit(e) {
        e.preventDefault();

        const response = await fetch("http://localhost:5000/api/scans/submit", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                selectedTarget: selectedTarget,
                scanType: scanType,
                client_id: getCookie("client_id"), // Default client for development
                user_id: getCookie("user_id")   // Default user for development
            })
        });

        const result = await response.json();
        console.log(result);
    
        if (response.ok) {
            
            window.location.href = "dashboard.html"; 
        } else {
            alert(result.error || "Scan failed.");
        }
    }

    return( 
        <div id = "bounding_box">
        <h1>Generate a New Scan!</h1>
        <h4>Please select your target and what type of scan</h4>
            <form id="newScanForm">
                <div>
                    <label htmlFor="target_type">Select your target: </label>
                    <select name="target_type" id="target_type" value = { selectedTarget } onChange= {(e) => setSelectedTarget(e.target.value)}required>
                        <option value="domain">Domain</option>
                        <option value="ip">IP</option>
                        <option value="range">Range</option>
                    </select>
                </div>
                <div>
                    <label htmlFor="scan_type">Select scan type:</label>
                    <select name="scan_type" id="scan_type" value = { scanType } onChange = {(e) => setScanType(e.target.value)}required>
                        <option value="nmap">NMAP (Network/Port Scan)</option>
                        <option value="nikto">Nikto (Web Vulnerability Scan)</option>
                        <option value="full">Full</option>
                    </select>
                </div>
                <div id="external_buttons">
                    <button type="submit">Generate Scan</button>
                    <button type="button" onClick={() => (navigate("./dashboard"))}>Back</button>
                </div>
            </form>    
        </div>
    );
}

export default NewScan;