import { useState } from 'react';
import { useNavigate } from "react-router-dom";

import './login.css';

function Forgotpw() {

  const [email, setEmail] = useState("");
  const navigate = useNavigate();

  async function handleSubmit(e) {
    e.preventDefault();

    const response = await fetch("http://localhost:5000/api/auth/forgot-pw", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            email: email
        })
    });
    
    const result = await response.json();
      if (response.ok) {
          navigate("./login");
      } else {
          alert(result.error || "Retreiving pw failed.");
      }
    }

  return (
    <div id = "bounding_box">
        <h1>Forgot your password</h1>
        <h4>Please enter the email you'd like your password reset information sent to.</h4>
        <form id="forgotpw">
            <div>
                <label for="email">Enter your email:</label>
                <input type="email" name="email" id="email" value = {email} onChange={(e) => setEmail(e.target.value)} required/>
            </div>
            <div>
                <button type="submit" onClick="">Sent Reset Link</button>
            </div>
        </form> 
    </div> 
  );
}

export default Forgotpw;