import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from './api';
import Toolbar from './Components/toolbar';

function NewTarget () {

    const navigate = useNavigate();
    const[ targetName, setTargetName ] = useState("");
    const [ targetType, setTargetType ]  = useState("None");
    const [ targetValue, setTargetValue ]  = useState("");
    const [ targetPublic, setTargetPublic ]  = useState("");

    async function handleSubmit(e) {
        e.preventDefault();

        const target = JSON.stringify({
                target_name: targetName,
                target_type: targetType,
                target_value: targetValue,
                public_facing: targetPublic,
            })

        await api.post("/target/add-target", target, {
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
                alert("Failed to add target: " + error.response.data.error)
                if (error.response.status === 401){ navigate('/') }
            }
        });
    }

    return( 
        <div id = "bounding_box">
            <Toolbar/>
            <h1>Create a New Target!</h1>
            <h4>Please enter a name for your target, select target type; ip, domain, or range, if it is public facing, and it's target value!</h4>
            <form id="newTargetForm" onSubmit={handleSubmit}>
                <div>
                    <label htmlFor="target_name">Enter your scan name:</label>
                    <input type="text" name="target_name" id="target_name" value = { targetName } onChange= {(e) => setTargetName(e.target.value)}required></input>
                </div>
                <div>
                    <label htmlFor="target_type">Select your target type:</label>
                    <select name="target_type" id="target_type" value = { targetType } onChange= {(e) => setTargetType(e.target.value)}required>
                        <option value="None" disabled>Domain/IP/Range</option>
                        <option value="domain">Domain</option>
                        <option value="ip">IP</option>
                        <option value="range">Range</option>
                    </select>
                </div>
                <div>
                    <label htmlFor="target_value">Enter target value:</label>
                    <input type="text" name="target_value" id="target_value" value = { targetValue } onChange= {(e) => setTargetValue(e.target.value)}required></input>
                </div>
                <div>
                    <label htmlFor="public_facing">Public?</label>
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