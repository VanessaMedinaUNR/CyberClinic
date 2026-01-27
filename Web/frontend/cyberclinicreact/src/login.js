import { useState } from 'react';
import { useNavigate } from "react-router-dom";

//useState: render changes on website 
//useNavigate: have access to change pages 

import './login.css';

function Login() {

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const navigate = useNavigate();
  

  /*function setCookie(name,value,days) {
    let expires = "";
    if (days) {
        const date = new Date();
        date.setTime(date.getTime() + (days*24*60*60*1000));
        expires = "; expires=" + date.toUTCString();
    }
    document.cookie = name + "=" + (value || "")  + expires + "; path=/";
  }*/

  async function handleSubmit(e) {
    e.preventDefault();

    const response = await fetch("http://localhost:5000/api/auth/login", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            email: email,
            password: password
        })
    });
    
    const result = await response.json();
      if (response.ok) {
          //const client_id = result.user.client_id;
          //const user_id = result.user.user_id;
          //setCookie("client_id", client_id, 5);
          //setCookie("user_id", user_id, 5);
          navigate("./dashboard");
      } else {
          alert(result.error || "Login failed.");
      }
    }
    
  return (
    <div id = "bounding_box">
        <h1>Welcome to CyberClinic</h1>
        <h2>University of Nevada, Reno</h2>

        <form id="loginForm" onSubmit={handleSubmit}>
            <div>
                <label for="email">Enter your email:</label>
                <input type="email" name="email" id="email" value = {email} onChange={(e) => setEmail(e.target.value)} required/>
            </div>
            <div>
                <label for="password">Enter your password</label>
                <input type="text" name="password" id="password" value = {password} onChange={(e) => setPassword(e.target.value)}required />
            </div>
            <div>
                <button id="submit" type="submit">Submit</button>
            </div>
        </form>
        <div id="external_buttons">
            <button id="signup" type="button" onClick={() => (navigate("./dashboard"))}>Sign Up</button>

            <button id="forgotpw" type="button" onClick={() => (navigate("/forgotpw"))}>Forgot Password</button>
        </div>

    </div>
  );
}

export default Login;
