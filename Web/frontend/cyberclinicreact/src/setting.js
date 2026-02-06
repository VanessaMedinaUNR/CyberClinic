// on html only copy paste what is in the body NOT THE SCRIPT 
//copy the html body into the return then on top is where you will put the java/script 
//when writing new code, html goes into return 
//pushing through react: git add .
//git commit -m " "
//git push origin reactrefactor

import { useState, useEffect } from 'react';
import { useNavigate } from "react-router-dom";
import './setting.css';
import axios from 'axios';

function Setting() {
    const navigate = useNavigate();
    const [userData, setUserData] = useState({
        email: '',
        admin: false,
        phone: '',
        scan_frequency: -1
    });

  useEffect(() => {
    axios.get(process.env.REACT_APP_BACKEND_SERVER + "/api/auth/user")
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
        console.error('Error fetching data: Authentication Required');
        if (error.response.status === 401){ navigate('/') }
    });
  }, [navigate]);

    function updateUser(newDetails){
        axios.post(process.env.REACT_APP_BACKEND_SERVER + "/api/auth/user", newDetails, {
            headers: {
                "Content-Type": "application/json"
            },
        })
        .then(function (response) {
            alert(response.data.message);
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
            const form = e.target;
            const formData = new FormData(form);
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
        <div className="dashboard-header">
            <div className="brand-section">
                <h1>CyberClinic</h1>
                <p>University of Nevada, Reno </p>
            </div>
        </div>
        <a onClick={(e)=>{ //when clicks runs the code 
            e.preventDefault();//this is code
            navigate('/dashboard'); //goes to dash board //svg got from got this from https://www.svgrepo.com/svg/324205/back-arrow-navigation
        }} className="back-link">
            <svg fill="#000000" viewBox="0 0 52 52" data-name="Layer 1" id="Layer_1" xmlns="http://www.w3.org/2000/svg"><g id="SVGRepo_bgCarrier" strokeWidth="0"></g><g id="SVGRepo_tracerCarrier"><path d="M50,24H6.83L27.41,3.41a2,2,0,0,0,0-2.82,2,2,0,0,0-2.82,0l-24,24a1.79,1.79,0,0,0-.25.31A1.19,1.19,0,0,0,.25,25c0,.07-.07.13-.1.2l-.06.2a.84.84,0,0,0,0,.17,2,2,0,0,0,0,.78.84.84,0,0,0,0,.17l.06.2c0,.07.07.13.1.2a1.19,1.19,0,0,0,.09.15,1.79,1.79,0,0,0,.25.31l24,24a2,2,0,1,0,2.82-2.82L6.83,28H50a2,2,0,0,0,0-4Z"></path></g></svg>
        </a> 
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
