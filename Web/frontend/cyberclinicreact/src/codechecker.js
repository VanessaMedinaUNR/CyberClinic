import { useState } from "react";
import Toolbar from './Components/toolbar';
import './styles/codechecker.css';
import ReactMarkdown from "react-markdown";
import api from "./api";

function CodeChecker() {

    const [code, setCode] = useState("");
    const [result, setResult] = useState("");
    const [loading, setLoading] = useState(false);

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
        }
        ).catch(function (error) {
            console.error("Error:", error);
            setLoading(false);
            setResult("Error scanning code.");
        });
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
                <button onClick={handleScan} disabled={loading}>
                    {loading ? "Scanning..." : "Scan Code"}
                </button>

                {result && (
                    <div className="result_box">
                        <h4>Analysis Result:</h4>
                        <pre>
                            {result}
                        </pre>
                        {!loading &&
                            <div style={{ display: 'flex', gap: '10px' }}>
                                <button onClick={() => navigator.clipboard.writeText(result)}>Copy to Clipboard</button>
                                <button onClick={() => { setResult(""); setCode("") }}>Clear</button>
                            </div>
                        }
                    </div>
                )}
            </div>
        </div>    
    );
}
export default CodeChecker;

   



