import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

function NewTarget () {

    const navigate = useNavigate();
    const[ targetName, setTargetName ] = useState("");
    const [ targetType, setTargetType ]  = useState("");
    const [ targetValue, setTargetValue ]  = useState("");
    const [ targetPublic, setTargetPublic ]  = useState("");
    

    function getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
    }

    async function handleSubmit(e) {
        e.preventDefault();

        const target = JSON.stringify({
                target_name: targetName,
                target_type: targetType,
                target_value: targetValue,
                public_facing: targetPublic,
            })

        axios.post(process.env.REACT_APP_BACKEND_SERVER + "/api/target/add-target", target, {
            headers: {
                "Content-Type": "application/json"
            }
        })
        .then(function (response) {
            alert(response.data.message);
            navigate("/dashboard")
        }).catch(function (error){
            if (!error.response)
            {
                alert("Connection error: Please try again later");
            }
            else
            {  
                alert("Fetching targets failed: " + error.response.data.error)
            }
        });
    }

    return( 
        <div id = "bounding_box">
            <h1>Create a New Target!</h1>
            <h4>Please enter a name for your target, select target type; ip, domain, or range, if it is public facing, and it's target value!</h4>
            <form id="newTargetForm" onSubmit={handleSubmit}>
                <div>
                    <label for="target_name">Enter your scan name:</label>
                    <input type="text" name="target_name" id="target_name" value = { targetName } onChange= {(e) => setTargetName(e.target.value)}required></input>
                </div>
                <div>
                    <label for="target_type">Select your target type:</label>
                    <select name="target_type" id="target_type" value = { targetType } onChange= {(e) => setTargetType(e.target.value)}required>
                        <option value="">Domain/IP/Range</option>
                        <option value="domain">Domain</option>
                        <option value="ip">IP</option>
                        <option value="range">Range</option>
                    </select>
                </div>
                <div>
                    <label for="target_value">Enter target value:</label>
                    <input type="text" name="target_value" id="target_value" value = { targetValue } onChange= {(e) => setTargetValue(e.target.value)}required></input>
                </div>
                <div>
                    <label for="public_facing">Public?</label>
                    <input type="checkbox" name="public_facing" id="public_facing" value = { targetPublic } onChange= {(e) => setTargetPublic(e.target.checked)}></input>
                </div>
                <div id="external_buttons">
                    <button type="submit">Add Target</button>
                    <button type="button">Back</button>
                    {/* fixed the ./bashbaord, its not suppoused to have the .*/}
                </div>
            </form>    
        </div>
    );
}

export default NewTarget;