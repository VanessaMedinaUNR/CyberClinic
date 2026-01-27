// on html only copy paste what is in the body NOT THE SCRIPT 
//copy the html body into the return then on top is where you will put the java/script 
//when writing new code, html goes into return 
//pushing through react: git add .
//git commit -m " "
//git push origin reactrefactor

import { useState } from 'react';
import { useNavigate } from "react-router-dom";
import './setting.css';

function Setting() {
    const navigate = useNavigate();

    async function handleUpdateDetails(e){
        e.preventDefault();
    }
    async function handleChangePassword(e){
        e.preventDefault();
    }
    async function handleSaveClientSettings(e){
        e.preventDefault();
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
                <input type="Email" className="form-input"value="user@email.com" placeholder=" user@email.com"/>
            </div>
            <button className="btn-action">
                Update Details
            </button>
        </div>
        <div className="setting-card">
            <div className=" card-header">
                <h3> Secuirty </h3>
                <p> Change Your password to keep your account secure</p>
            </div>
            <div className="form-group">
                <label className="form-label"> Old Password </label>
                <input type="password" className="form-input" placeholder="......."/>
            </div>
            <div className ="form-group" >
                <label className="form-label"> New Password </label>
                <input type="password" className="form-input" placeholder=""/>
            </div>
            <div className ="form-group" >
                <label className="form-label"> Confirm New Password </label>
                <input type="password" className="form-input" placeholder=""/>
        </div>
        <button className="btn-action">
            Change Password
        </button>
    </div>
    <div className="setting-card">
        <div className="card-header">
            <h3>Client Information</h3>
            <p>Manage your organization settings</p>
        </div>
        <div className="form-group">
            <label className="form-label"> Defualt scan Frequency </label>
            <select className="form-input">
                <option>Daily</option>
                <option>Weekly</option>
                <option selected>Monthly</option>
            </select>
            </div>
        <button className="btn-action" onClick = {handleSaveClientSettings}>Save Client Settings</button>
    </div>
<div className="help-icon">?</div>
</div>
    );
}
export default Setting;
