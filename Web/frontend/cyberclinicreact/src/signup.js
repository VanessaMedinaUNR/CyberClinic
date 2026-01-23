import { useState } from 'react';
import { useNavigate } from "react-router-dom";

function Signup() {

    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [phone, setPhone] = useState("");
    const [organization, setOrganization] = useState("");
    const navigate = useNavigate();

    async function handleSubmit(e) {
        e.preventDefault();

        const response = await fetch("http://localhost:5000/api/auth/login", {
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
        if (response.ok) {
            navigate("./login");
        }else{
            alert(result.error || "Signup failed.")
        }
    }

    return (
        <div id = "bounding_box">
        <h1>Welcome to CyberClinic</h1>
        <h2>University of Nevada Reno</h2>
        <form id="signup">
            <div>
                <label for="email">Enter your email:</label>
                <input type="email" name="email" id="email" value = {email} onChange = {(e) => setEmail(e.target.value)}required/>
            </div>
            <div>
                <label for="password">Enter your password:</label>
                <input type="text" name="password" id="password" value = {password} onChange = {(e) => setPassword(e.target.value)} required/>
            </div>
            <div>
                <label for="phone">Enter your phone number:</label>
                <input type="tel" name="phone" id="phone" value = {phone} onChange = {(e) => setPhone(e.target.value)}required/>
            </div>
            <div>
                <label for="organization">Enter your organization name:</label>
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