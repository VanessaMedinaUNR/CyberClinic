import { useState } from 'react';
import { useNavigate } from "react-router-dom";
import axios from 'axios';
import { setAuthToken } from './App';

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
    'use server';
    e.preventDefault();

    const userAuth = JSON.stringify({
        email: email,
        password: password
    })

    await axios.post(process.env.REACT_APP_BACKEND_SERVER + "/api/auth/login", userAuth, {
        headers: { 'Content-Type': 'application/json' }
    }).then(function (response) {
        const jwt_token = response.data.access_token;
        localStorage.setItem("access_token", jwt_token); //Add JWT token to local storage
        setAuthToken(jwt_token); //Update axios Authorization header
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
    
/*
    const result = await response.json();
      if (response.ok) {
        const jwt_token = result.access_token;
        localStorage.setItem("access_token", jwt_token);
        setAuthToken(result.access_token); //Migrate to jwt token for auth
        navigate("./dashboard");
      } else {
          
      }
*/    
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
            <button id="signup" type="button" onClick={() => (navigate("./signup"))}>Sign Up</button>

            <button id="forgotpw" type="button" onClick={() => (navigate("/forgotpw"))}>Forgot Password</button>
        </div>

    </div>
  );
}

export default Login;
