import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
const axios = require("axios");

function NewScan () {

    const navigate = useNavigate();
    const[ selectedTarget, setSelectedTarget ] = useState("");
    const [ scanType, setScanType ]  = useState("");
    const [ targets, setTargets] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetch(process.env.REACT_APP_BACKEND_SERVER + "/api/target/list-targets", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                client_id: getCookie("client_id"), // Default client for development
                user_id: getCookie("user_id")   // Default user for development
            })
        })
        .then(response => response.json())
        .then(data => {
            const target_list = JSON.parse(data.target_list)
            setTargets(target_list.map((item) => ({ value: item, label: item })));
        })
        .catch(err => console.error('Error fetching data:', err))
        .finally(() => setLoading(false));
    }, []);
    

    function getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
    }

    async function handleSubmit(e) {
        e.preventDefault();
        console.log("Target: " + selectedTarget + "\tType: " + scanType)

        const response = await fetch(process.env.REACT_APP_BACKEND_SERVER + "/api/scans/submit", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                target_name: selectedTarget,
                scan_type: scanType,
                client_id: getCookie("client_id"), // Default client for development
                user_id: getCookie("user_id")   // Default user for development
            })
        });

        const result = await response.json();
        console.log(result);
    
        if (response.ok) {
            navigate("/dashboard")
        } else {
            alert(result.error || "Scan failed.");
        }
    }

    return( 
        <div id = "bounding_box">
        <h1>Generate a New Scan!</h1>
        <h4>Please select your target and what type of scan</h4>
            <form id="newScanForm" onSubmit={handleSubmit}>
                <div>
                    <label htmlFor="target_name">Select your target: </label>
                    <select disabled={loading} name="target_name" id="target_name" value = { selectedTarget } onChange= {(e) => setSelectedTarget(e.target.value)}required>
                        <option key="None" value="None">Select a target</option>
                        {targets.map((item) => (
                            <option key={item.value} value={item.value}>
                            {item.label}
                            </option>
                        ))}
                    </select>
                </div>
                <div>
                    <label htmlFor="scan_type">Select scan type:</label>
                    <select name="scan_type" id="scan_type" value = { scanType } onChange = {(e) => setScanType(e.target.value)}required>
                        <option value="None">NMAP/Nikto/Full</option>
                        <option value="nmap">NMAP (Network/Port Scan)</option>
                        <option value="nikto">Nikto (Web Vulnerability Scan)</option>
                        <option value="full">Full</option>
                    </select>
                </div>
                <div id="external_buttons">
                    <button type="submit">Generate Scan</button>
                    <button type="button">Back</button>
                    {/* fixed the ./bashbaord, its not suppoused to have the .*/}
                </div>
            </form>    
        </div>
    );
}

export default NewScan;