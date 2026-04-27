import { useState } from 'react';
import api from '../api';
import '../styles/helpContact.css';

function HelpContact() {
    const [open, setOpen] = useState(false);
    const [submitted, setSubmitted] = useState(false);
    const [loading, setLoading] = useState(false);
    const [formData, setFormData] = useState({
        email: '',
        reason: ''
    });
    function handleChange(e) {
        setFormData({ ...formData, [e.target.name]: e.target.value });
    }
    async function handleSubmit(e) {
        e.preventDefault();
        setLoading(true);
        api.post('/auth/help', formData)
        .then(function(){
            setSubmitted(true);
        })
        .catch(function(error) {
            if (!error.response) {
                alert("Connection error: Please try again later");
            } else {
                alert("Failed to send: " + error.response.data.error);
            }
        })
        .finally(function() {
            setLoading(false);
        });
        
    }
    function handleClose() {
        setOpen(false);
        // reset form after the popup finishes closing
        setTimeout(() => {
            setSubmitted(false);
            setFormData({ email: '', reason: '' });
        }, 300);
    }
    return(
        <>
        { open && (
            <div className="hc-overlay" onClick={ handleClose }>
                    <div className="hc-popup" onClick={ e => e.stopPropagation() }>

                        <div className="hc-header">
                            <span>Contact Support</span>
                            <button className="hc-close" onClick={ handleClose }>✕</button>
                        </div>
                        { submitted ? (
                            // show a confirmation once the message is sent
                            <div className="hc-success">
                                <div className="hc-success-icon">✓</div>
                                <p className="hc-success-title">Message Sent!</p>
                                <p className="hc-success-sub">We'll get back to you at <strong>{ formData.email }</strong> as soon as possible.</p>
                                <button className="hc-btn" onClick={ handleClose }>Close</button>
                            </div>
                        ) : (
                            <form className="hc-form" onSubmit={ handleSubmit }>
                                <p className="hc-desc">Need help? Send us a message and we'll get back to you.</p>

                                <div className="hc-group">
                                    <label className="hc-label">Your Email</label>
                                    <input
                                        type="email"
                                        name="email"
                                        className="hc-input"
                                        placeholder="you@example.com"
                                        value={ formData.email }
                                        onChange={ handleChange }
                                        required
                                    />
                                </div>
                                <div className="hc-group">
                                    <label className="hc-label">How can we help?</label>
                                    <textarea
                                        name="reason"
                                        className="hc-input hc-textarea"
                                        placeholder="Describe your issue or question..."
                                        value={ formData.reason }
                                        onChange={ handleChange }
                                        required
                                        rows={ 4 }
                                    />
                                </div>

                                <button className="hc-btn" type="submit" disabled={ loading }>
                                    { loading ? 'Sending...' : 'Send Message' }
                                </button>
                            </form>
                        )}

                    </div>
                </div>
            )}
            <div className="help-icon" onClick={ () => setOpen(o => !o) } title="Get Help">?</div>
       
        </>
    );
}
export default HelpContact;