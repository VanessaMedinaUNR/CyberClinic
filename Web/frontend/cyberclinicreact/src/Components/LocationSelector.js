import { useState } from 'react';
import { CountryDropdown, StateDropdown, CityDropdown } from "react-country-state-dropdown";

export default function LocationSelector({sendLocation}) {
    const [location, setLocation] = useState({
        country: '',
        state: '',
        city: '',
    });

    const updateLocation = (field, value) =>
    {
        const newLocation = {...location, [field]: value};
        setLocation(newLocation)
        if (newLocation.country && newLocation.state && newLocation.city)
        {
            sendLocation(location)
        }
    };
    return <>
        <div>
            <label htmlFor="Country">Select a Country:</label>
            <CountryDropdown value={location.country} onChange = {(val) => updateLocation("country",val)}required/>
        </div>
        <div>
            <label htmlFor="State">Select a State:</label>
            <StateDropdown country={location.country} value={location.state} onChange = {(val) => updateLocation("state",val)}required/>
        </div>
        <div>
            <label htmlFor="City">Select a City:</label>
            <CityDropdown country={location.country} state={location.state} value={location.city} onChange = {(val) => updateLocation("city", val)}required/>
        </div>
    </>
}

