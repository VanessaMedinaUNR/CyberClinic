import { useState, useRef } from 'react';

export default function LocationSelector({sendLocation}) {
    const [location, setLocation] = useState({
        country: 'Select A Country',
        state: 'Select A State',
        city: 'Select A City',
    });

    const updateLocation = (e) =>
    {
        const { name, value } = e.target;
        setLocation(prev => ({...prev, [name]: value}))
        if (location.country !== "" && (location.state !== "" && location.city !== ""))
        {
            sendLocation(location)
        }
    }
    return <>
        <div>
            <label htmlFor="Country">Select a Country:</label>
            <input type="text" name="country" id="country" value = {location.country} onChange = {(e) => updateLocation(e)}required/>
        </div>
        <div>
            <label htmlFor="State">Select a State:</label>
            <input type="text" name="state" id="state" value = {location.state} onChange = {(e) => updateLocation(e)}required/>
        </div>
        <div>
            <label htmlFor="City">Select a City:</label>
            <input type="text" name="city" id="city" value = {location.city} onChange = {(e) => updateLocation(e)}required/>
        </div>
    </>
}