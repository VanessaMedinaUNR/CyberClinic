// on html only copy paste what is in the body NOT THE SCRIPT 
//copy the html body into the return then on top is where you will put the java/script 
//when writing new code, html goes into return 
//pushing through react: git add .
//git commit -m " "
//git push origin reactrefactor

import { useState, useEffect } from 'react';
import { useNavigate } from "react-router-dom";
import Toolbar from './Components/toolbar';
import './setting.css';
import api from './api';

function Setting() {
    const navigate = useNavigate();
    const [userData, setUserData] = useState({
        email: '',
        admin: false,
        phone: '',
        scan_frequency: -1
    });

  useEffect(() => {
    api.get("/auth/user")
    .then(function (response) {
        const user = response.data
        setUserData({
          email: user.email,
          admin: user.admin,
          phone: user.phone,
          scan_frequency: user.scan_frequency
        });
    })
    .catch(function (error) {
        if (!error.response)
        {
            alert("Connection error: Please try again later");
        }
        else    
        {
            console.log('Error fetching data: ' + error);
            if (error.response.status === 401){ navigate('/') }
        }
    });
  }, [navigate]);

    function updateUser(newDetails){
        api.post("/auth/user", newDetails, {
            headers: {
                "Content-Type": "application/json"
            },
        })
        .then(function (response) {
            alert(response.data.message);
            localStorage.setItem('access_token', response.data.access_token)
            localStorage.setItem('refresh_token', response.data.refresh_token)
            window.location.reload();
        })
        .catch(function (error) {
            if (!error.response)
            {
                alert("Connection error: Please try again later");
            }
            else
            {  
                alert("User update failed: " + error.response.data.error);
                if (error.response.status === 401){ navigate('/') }
            }
        });
    }

    async function handleUpdateDetails(e){
        e.preventDefault();
        const newDetails = JSON.stringify({
            email: userData.email,
            phone: userData.phone,
        })

        updateUser(newDetails);
    }

    async function handleChangePassword(e){
        e.preventDefault();
        
        if (userData.new_password === userData.confirm_password) {
            const passwordUpdate = JSON.stringify({
                old_password: userData.old_password,
                new_password: userData.new_password,
            })
            updateUser(passwordUpdate);
        } else { alert("Passwords do not match") }
    }
    async function handleSaveClientSettings(e){
        e.preventDefault();

        const scanFrequency = JSON.stringify({ scan_frequency: userData.scan_frequency })
        updateUser(scanFrequency)
    }
return(
    <div id="bounding_box">
        <Toolbar/> 
        <h1 className="page-title"> Account Settings </h1>
        <div className="setting-card">
            <div className="card-header">
                <h3>User Details</h3>
                <p>Update Your contact information</p>
            </div>
            <div className= "form-group">
                <label className="form-label"> Email</label>
                <input type="Email" className="form-input" value={ userData.email } onChange={ (e) => setUserData({ ...userData, email: e.target.value }) }/>
            </div>
            <div className ="form-group">
                <label className="form-label"> Phone Number</label>
                <input type="tel"className="form-input" value={ userData.phone } onChange={ (e) => setUserData({ ...userData, phone: e.target.value }) }/>
            </div>
            <button className="btn-action" onClick={ handleUpdateDetails }>
                Update Details
            </button>
        </div>
        <div className="setting-card">
            <div className=" card-header">
                <h3> Security </h3>
                <p> Change Your password to keep your account secure</p>
            </div>
            <div className="form-group">
                <label className="form-label"> Old Password </label>
                <input type="password" className="form-input" value={ userData.old_password } onChange={ (e) => setUserData({ ...userData, old_password: e.target.value })}/>
            </div>
            <div className ="form-group" >
                <label className="form-label"> New Password </label>
                <input type="password" className="form-input" value={ userData.new_password } onChange={ (e) => setUserData({ ...userData, new_password: e.target.value })}/>
            </div>
            <div className ="form-group" >
                <label className="form-label"> Confirm New Password </label>
                <input type="password" className="form-input" value={ userData.confirm_password } onChange={ (e) => setUserData({ ...userData, confirm_password: e.target.value })}/>
            </div>
            <button className="btn-action" onClick = { handleChangePassword }>
                Change Password
            </button>
        </div>
        {userData.admin === true &&    
            <div className="setting-card">
                <div className="card-header">
                    <h3>Client Information</h3>
                    <p>Manage your organization settings</p>
                </div>
                <div className="form-group">
                    <label className="form-label"> Automated Scan Frequency </label>
                    <select className="form-input" value={ userData.scan_frequency } onChange = {(e) => setUserData({...userData, scan_frequency: e.target.value})}>
                        <option value="-1">None</option>
                        <option value="1">Daily</option>
                        <option value="2">Weekly</option>
                        <option value="3">Monthly</option>
                    </select>
                    </div>
                <button className="btn-action" onClick = { handleSaveClientSettings }>Save Client Settings</button>
            </div>
        }
        <div className="help-icon">?</div>
    </div>
    );
}
export default Setting;
