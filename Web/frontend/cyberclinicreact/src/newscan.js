import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

function NewScan () {

    const navigate = useNavigate();
    const[ selectedTarget, setSelectedTarget ] = useState("");
    const [ scanType, setScanType ]  = useState("");
    const [ targets, setTargets] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        axios.get(process.env.REACT_APP_BACKEND_SERVER + "/api/target/list-targets")
        .then(function (response) { 
            const target_list = JSON.parse(response.data.target_list);
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

        const scanTarget = JSON.stringify({
                target_name: selectedTarget,
                scan_type: scanType,
                jwt_token: getCookie("jwt_token") //Migrate to jwt token for auth
            })

        axios.post(process.env.REACT_APP_BACKEND_SERVER + "/api/scans/submit", scanTarget, {
            headers: {
                "Content-Type": "application/json"
            },
        }).then(function (response) {
            alert(response.data.message);
            navigate("/dashboard")
        }).catch(function (error) {
            if (!error.response)
            {
                alert("Connection error: Please try again later");
            }
            else
            {  
                alert("Scan failed: " + error.response.data.error);
            }
        });
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