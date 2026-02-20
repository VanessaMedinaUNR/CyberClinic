import { useState } from "react";
import Toolbar from './Components/toolbar';
import './codechecker.css';
import ReactMarkdown from "react-markdown";

function CodeChecker() {

    const [code, setCode] = useState("");
    const [result, setResult] = useState("");

    const handleScan = async () => {
        try {
            const response = await fetch("http://localhost:4000/codescan", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ code })
            });

            const data = await response.json();
            setResult(data.analysis);
        } catch (error) {
            console.error("Error:", error);
            setResult("Error scanning code.");
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
                <textarea placeholder="Paste your code here..." value = { code } onChange={(e) => setCode(e.target.value)}/>
                <button onClick={handleScan}>Scan Code</button>

                {result && (
                    <div className="result_box">
                        <h4>Analysis Result:</h4>
                        <pre>
                            <ReactMarkdown>
                                {result}
                            </ReactMarkdown>
                               
                        </pre>
                    </div>
                )}
            </div>
        </div>    
    );
}
export default CodeChecker;

   



