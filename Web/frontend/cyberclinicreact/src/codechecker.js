import { useState } from "react";
import Toolbar from './Components/toolbar';
import './styles/codechecker.css';
import ReactMarkdown from "react-markdown";
import api from "./api";
import { useNavigate } from "react-router-dom";
import spinload from './img/spinload.gif'



function CodeChecker() {

    const [code, setCode] = useState("");
    const [result, setResult] = useState("");
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

   
    async function saveCode(code, report){
        
        api.post("/saveCode/savecode",  {
           code_input: code,
           report: report 
        })
        .then(function (response) {
            console.log("saved successfully");
        })
        .catch(function (error) {
            if (!error.response)
            {
                alert("Connection error: Please try again later");
            }
            else
            {  
                alert("Saving user code failed: " + error.response.data.error);
                if (error.response.status === 401){ navigate('/') }
            }
        });
    }

    async function handleScan(){
        setResult("Please wait while we analyze your code...");
        setLoading(true);
        console.log("Sending code for analysis:", code);
        api.post("/ai/codescan", JSON.stringify({ code: code }), {
            headers: { "Content-Type": "application/json" },
        }).then(function (response) {
            const data = response.data;
            setLoading(false);
            setResult(data.analysis);
            saveCode(code, data.analysis);
        }
        ).catch(function (error) {
            console.error("Error:", error);
            setLoading(false);
            setResult("Error scanning code.");
        });
        
    };

    function copyToClipboard(text) {
        if ('clipboard' in navigator) {
            navigator.clipboard.writeText(text).then(() => {
                console.log('Text copied');
            }).catch(err => {
                console.error('Failed to copy: ', err);
            });
        } else {
            // Fallback for older browsers using document.execCommand
            let textArea = document.getElementById("result").textContent
            try {
                textArea.select();
                document.execCommand('copy');
            } catch (err) {
                console.error('Failed to copy: ', err);
                alert('Failed to copy!')
            }
        }
    };
      
    function getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();

    }

    return (
        <div className="codechecker-wrapper">
            
            <div id="code_box">
                <Toolbar/>
                <h1>Code Checker</h1>
                <h3>Please input your code to see what security vulnerabilities are found and how they could be improved</h3>
                <textarea placeholder="Paste your code here..." value = { code } onChange={(e) => setCode(e.target.value)} disabled={loading}/>
                <div style={{'display': 'flex', 'justify-content': 'space-between'}}>
                    <button onClick={handleScan} disabled={loading}>
                        {loading ? "Scanning..." : "Scan Code"}
                    </button>
                    <button onClick={() => navigate("/saved-codes")}>Saved Codes</button>
                </div>

                {result && (
                    <div className="result_box">
                        <h4>Analysis Result:</h4>
                        <pre id="result">
                            {result}
                        </pre>
                        {loading ?
                            <img src={spinload} alt="loading..."/>
                        :
                            <div style={{ 'display': 'flex', 'justify-content': 'space-between' }}>
                                <button onClick={copyToClipboard}>Copy to Clipboard</button>
                                <button onClick={() => { setResult(""); setCode("") }}>Clear</button>
                                <button onClick={() => saveCode(code, result)}>Save Code</button>
                            </div>
                        }
                    </div>
                )}

            </div>
        </div>    
    );
}
export default CodeChecker;

   



