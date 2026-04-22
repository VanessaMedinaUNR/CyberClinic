import { useState, useEffect } from 'react';
import { CountryDropdown, StateDropdown, CityDropdown } from "react-country-state-dropdown";

export default function LocationSelector({sendLocation}) {
    const [country, setCountry] = useState(null);
    const [state, setState] = useState(null);
    const [city, setCity] = useState(null);
    
    const [loc, setLoc] = useState({
        country: '',
        state: '',
        city: '',
    });

    const handleSetCountry = (e, c) => {
        console.log(c)
        setCountry(c);
        setLoc({...loc, "country": c.iso2});
    };
    const handleSetState = (e, st) => {
        setState(st);
        setLoc({...loc, "state": st.value})
    };
    const handleSetCity = (e, cit) => {
        setCity(cit);
        setLoc({...loc, "city": cit.value})
    };

    useEffect(() => {
        sendLocation(loc);
    }, [loc]);

    return <>
        <div>
            <label htmlFor="Country">Select a Country:</label>
            <CountryDropdown value={country} onChange = {handleSetCountry}required/>
        </div>
        <div>
            <label htmlFor="State">Select a State:</label>
            <StateDropdown country={country} value={state} onChange = {handleSetState}required/>
        </div>
        <div>
            <label htmlFor="City">Select a City:</label>
            <CityDropdown country={country} state={state} value={city} onChange = {handleSetCity}required/>
        </div>
    </>
}

