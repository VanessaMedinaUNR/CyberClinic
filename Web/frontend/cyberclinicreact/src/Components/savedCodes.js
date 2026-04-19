import { useEffect, useState } from "react";
import api from "../api";
import { useNavigate } from "react-router-dom";

function SavedCodes() {
    const [codes, setCodes] = useState([]);
    const [loading, setLoading] = useState(true);
    const navigate = useNavigate();

    useEffect(() => {
        fetchCodes();
    }, []);

    function fetchCodes() {
        setLoading(true);

        api.get("/saveCode/getsavecodes")
            .then((res) => {
                setCodes(res.data);
                setLoading(false);
            })
            .catch((err) => {
                setLoading(false);

                if (err.response?.status === 401) {
                    navigate("/");
                } else {
                    console.error(err);
                    alert("Failed to load saved codes");
                }
            });
    }

    function deleteReport(report_id) {
        api.post("/saveCode/deletereport", {
            report_id: report_id
        })
        .then(() => {
            fetchCodes(); // refresh list after delete
        })
        .catch((err) => {
            if (err.response?.status === 401) {
                navigate("/");
            } else {
                alert("Delete failed");
            }
        });
    }

    return (
        <div className="saved-codes">
            <h1>Saved Codes</h1>

            {loading && <p>Loading...</p>}

            {!loading && codes.length === 0 && (
                <p>No saved codes found.</p>
            )}

            {codes.map((item) => (
                <div key={item.report_id} className="code-card">
                    
                    <h3>Report #{item.report_id}</h3>

                    <pre style={{ background: "#eee", padding: "10px" }}>
                        {item.code_input}
                    </pre>

                    <div style={{ marginTop: "10px" }}>
                        <strong>Report:</strong>
                        <pre>{item.report}</pre>
                    </div>

                    <button
                        onClick={() => deleteReport(item.report_id)}
                        style={{ marginTop: "10px", color: "red" }}
                    >
                        Delete
                    </button>
                </div>
            ))}
        </div>
    );
}

export default SavedCodes;