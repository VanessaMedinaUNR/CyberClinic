import { useState, useEffect } from 'react';

export default function LocationSelector({sendLocation}) {
    const [location, setLocation] = useState({
        country: '',
        state: '',
        city: '',
    });

    const updateLocation = (e) => {
        const { name, value } = e.target;
        setLocation(prev => ({...prev, [name]: value}));
    }

    useEffect(() => {
        if (location.country && location.state && location.city) {
            sendLocation(location);
        }
    }, [location]);

    return <>
        <div>
            <label htmlFor="country">Country:</label>
            <input type="text" name="country" id="country" value={location.country} onChange={updateLocation} placeholder="e.g. US" required/>
        </div>
        <div>
            <label htmlFor="state">State / Province:</label>
            <input type="text" name="state" id="state" value={location.state} onChange={updateLocation} placeholder="e.g. Nevada" required/>
        </div>
        <div>
            <label htmlFor="city">City:</label>
            <input type="text" name="city" id="city" value={location.city} onChange={updateLocation} placeholder="e.g. Reno" required/>
        </div>
    </>
}