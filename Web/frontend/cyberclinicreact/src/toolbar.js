import { useNavigate, useLocation } from "react-router-dom";

export default function Toolbar() {
    const navigate = useNavigate();   
    const location = useLocation();
    const dashboard = location.pathname === '/dashboard'
    return (
        <>
            <div className="dashboard-header">
                <div className="brand-section">
                    <h1>CyberClinic</h1>
                    <p>University of Nevada, Reno </p>
                </div>
                {dashboard === true &&
                    <div className="user-controls">
                        <span id="User-email"> </span> 
                        <button type = "button" onClick={() => (navigate("/setting"))} style={{ textDecoration: 'none', background: 'none', border: 'none', cursor: 'pointer' }}>⚙️</button>
                    </div>
                }
            </div>
             {dashboard === false &&
                <a onClick={(e)=>{ //when clicks runs the code 
                    e.preventDefault();//this is code
                    navigate('/dashboard'); //goes to dash board //svg got from got this from https://www.svgrepo.com/svg/324205/back-arrow-navigation
                }} className="back-link">
                    <svg fill="#000000" viewBox="0 0 52 52" data-name="Layer 1" id="Layer_1" xmlns="http://www.w3.org/2000/svg"><g id="SVGRepo_bgCarrier" strokeWidth="0"></g><g id="SVGRepo_tracerCarrier"><path d="M50,24H6.83L27.41,3.41a2,2,0,0,0,0-2.82,2,2,0,0,0-2.82,0l-24,24a1.79,1.79,0,0,0-.25.31A1.19,1.19,0,0,0,.25,25c0,.07-.07.13-.1.2l-.06.2a.84.84,0,0,0,0,.17,2,2,0,0,0,0,.78.84.84,0,0,0,0,.17l.06.2c0,.07.07.13.1.2a1.19,1.19,0,0,0,.09.15,1.79,1.79,0,0,0,.25.31l24,24a2,2,0,1,0,2.82-2.82L6.83,28H50a2,2,0,0,0,0-4Z"></path></g></svg>
                </a>
            }
        </>
    ) 
} 