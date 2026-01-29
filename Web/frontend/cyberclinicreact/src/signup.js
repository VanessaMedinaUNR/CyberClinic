import { useState, useEffect } from 'react';
import { useNavigate } from "react-router-dom";
import axios from "axios";


function Signup() {

    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [phone, setPhone] = useState("");
    const [organization, setOrganization] = useState("");
    const navigate = useNavigate();

    const [user, setUser] = useState("");

    async function handleSubmit(e) {
        e.preventDefault();

/*
        axios.post(process.env.REACT_APP_BACKEND_SERVER + "/api/auth/register", {
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                email: email,
                password: password,
                organization: organization,
                phone: phone
            })
        })
        .then(response => response.json())
        .then((data) => {
            console.log(data);
            setUser(data);
            navigate("/login")
        })
        .catch((error) => {
            console.error('Error:', error);
            alert(error || "Signup failed.");
        });
*/

        const response = await fetch(process.env.REACT_APP_BACKEND_SERVER + "/api/auth/register", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                email: email,
                password: password,
                organization: organization,
                phone: phone
            })
        });

        const result = await response.json();
        console.log(result);
    
        if (response.ok) {
            navigate("/")
        } else {
            alert(result.error || "Registration failed.");
        }
    }

    return (
        <div id = "bounding_box">
        <h1>Welcome to CyberClinic</h1>
        <h2>University of Nevada Reno</h2>
        <form id="signup" onSubmit={handleSubmit}>
            <div>
                <label htmlFor="email">Enter your email:</label>
                <input type="email" name="email" id="email" value = {email} onChange = {(e) => setEmail(e.target.value)}required/>
            </div>
            <div>
                <label htmlFor="password">Enter your password:</label>
                <input type="text" name="password" id="password" value = {password} onChange = {(e) => setPassword(e.target.value)} required/>
            </div>
            <div>
                <label htmlFor="phone">Enter your phone number:</label>
                <input type="tel" name="phone" id="phone" value = {phone} onChange = {(e) => setPhone(e.target.value)}required/>
            </div>
            <div>
                <label htmlFor="organization">Enter your organization name:</label>
                <input type="text" name="organization" id="organization" value ={organization} onChange = {(e) => setOrganization(e.target.value)}required/>
            </div>

            <div>
                <button id="submit" type="submit">Submit</button>
            </div>
        </form>
   </div> 
    );
}

export default Signup;