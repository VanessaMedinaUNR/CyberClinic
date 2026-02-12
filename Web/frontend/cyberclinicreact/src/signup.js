import { useState } from 'react';
import { useNavigate } from "react-router-dom";
import api from './api';
import LocationSelector from './Components/LocationSelector';


function Signup() {

    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [phone, setPhone] = useState("");
    const [organization, setOrganization] = useState("");
    const navigate = useNavigate();
    const [ newClient, setNewClient ] = useState(false);

    const [location, setLocation] = useState('');

    const getLocation = (loc) => {
        setLocation(loc);
    }

    async function handleSubmit(e) {
        e.preventDefault();

        const userData = {
            email: email,
            password: password,
            organization: organization,
            phone: phone
        }
        if (newClient){
            if (location)
            {
                userData.location = location
            }
        }
        console.log(userData)

        await api.post("/auth/register", JSON.stringify(userData), {
            headers: {
                "Content-Type": "application/json"
            }
        })
        .then(function (response) {
            alert(response.data.message);
            if (response.status === 201)
            {
                navigate("/")
            }
            else
            {
                setNewClient(true)
            }
        })
        .catch(function (error) {
            if (!error.response)
            {
                alert("Connection error: Please try again later");
            }
            else
            {  
                alert("Registration failed: " + error.response.data.error);
            }
        });
    }

    return (
        <div id = "bounding_box">
            <h1>Welcome to CyberClinic</h1>
            <h2>University of Nevada Reno</h2>
            <form id="signup" onSubmit={handleSubmit}>
                <div>
                    <label htmlFor="email">Enter your email:</label>
                    <input type="email" name="email" id="email" disabled={newClient} value = {email} onChange = {(e) => setEmail(e.target.value)}required/>
                </div>
                <div>
                    <label htmlFor="password">Enter your password:</label>
                    <input type="text" name="password" id="password" disabled={newClient} value = {password} onChange = {(e) => setPassword(e.target.value)} required/>
                </div>
                <div>
                    <label htmlFor="phone">Enter your phone number:</label>
                    <input type="tel" name="phone" id="phone" disabled={newClient} value = {phone} onChange = {(e) => setPhone(e.target.value)}required/>
                </div>
                <div>
                    <label htmlFor="organization">Enter your organization name:</label>
                    <input type="text" name="organization" id="organization" disabled={newClient} value ={organization} onChange = {(e) => setOrganization(e.target.value)}required/>
                </div>
                {newClient === true && <LocationSelector sendLocation={getLocation}/>}
                <div>
                    <button id="submit" type="submit">Submit</button>
                </div>
            </form>
        </div> 
    );
}

export default Signup;