import { useState } from 'react';
import { useNavigate } from "react-router-dom";
import api from './api';

//useState: render changes on website 
//useNavigate: have access to change pages 

import './login.css';

function Login() {

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const navigate = useNavigate();
  

  function setCookie(name,value,days) {
    let expires = "";
    if (days) {
        const date = new Date();
        date.setTime(date.getTime() + (days*24*60*60*1000));
        expires = "; expires=" + date.toUTCString();
    }
    document.cookie = name + "=" + (value || "")  + expires + "; path=/";
  }

  async function handleSubmit(e) {
        e.preventDefault();

        const userAuth = JSON.stringify({
            email: email,
            password: password
        })

        api.post("/auth/login", userAuth, {
            headers: { 'Content-Type': 'application/json' }
        }).then(function (response) {
            const jwt_token = response.data.access_token;
            const refresh_token = response.data.refresh_token;
            localStorage.setItem("access_token", jwt_token); //Add JWT token to local storage
            localStorage.setItem("refresh_token", refresh_token); //Add JWT refresh token to local storage
            navigate("./dashboard");
        }).catch(function (error) {
            if (!error.response)
                {
                    alert("Connection error: Please try again later");
                }
            else
                {    
                    alert("Login failed: " + error.response.data.error);
                }
        }); 
    }

  return (
    <div id = "bounding_box">
        <h1>Welcome to CyberClinic</h1>
        <h2>University of Nevada, Reno</h2>

        <form id="loginForm" onSubmit={handleSubmit}>
            <div>
                <label htmlFor="email">Enter your email:</label>
                <input type="email" name="email" id="email" value = {email} onChange={(e) => setEmail(e.target.value)} required/>
            </div>
            <div>
                <label htmlFor="password">Enter your password</label>
                <input type="text" name="password" id="password" value = {password} onChange={(e) => setPassword(e.target.value)}required />
            </div>
            <div>
                <button id="submit" type="submit">Submit</button>
            </div>
        </form>
        <div id="external_buttons">
            <button id="signup" type="button" onClick={() => (navigate("./signup"))}>Sign Up</button>

            <button id="forgotpw" type="button" onClick={() => (navigate("/forgotpw"))}>Forgot Password</button>
        </div>

    </div>
  );
}

export default Login;
