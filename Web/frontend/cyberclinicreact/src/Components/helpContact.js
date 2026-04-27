import { useState } from 'react';
import { useLocation } from 'react-router-dom';
import api from '../api';
import '../styles/helpContact.css';

function HelpContact() {
    const [open, setOpen] = useState(false);
    const [submitted, setSubmitted] = useState(false);
    const [loading, setLoading] = useState(false);
    const [formData, setFormData] = useState({
        email: '',
        issue_category: '',
        message: '',
        additional_info: ''
    });

    const state = useLocation().state;
    if (window.location.href.includes('/report')) {
        const report_id = state?.report_id;
        if (report_id) {
            formData.additional_info += `\n\n[Report ID: ${report_id}]`;
        }
    }

    function handleChange(e) {
        setFormData({ ...formData, [e.target.name]: e.target.value });
    }
    async function handleSubmit(e) {
        e.preventDefault();
        setLoading(true);
        api.post('/contact', formData)
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
            setFormData({ email: '', issue_category: '', message: '', additional_info: '' });
        }, 300);
    }
    return(
        <>
        { open && (
            <div className="hc-overlay" onClick={ handleClose }>
                    <div className="hc-popup" onClick={ e => e.stopPropagation() }>

                        <div className="hc-header">
                            <span style={{ color: 'white' }}>Contact Support</span>
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
                                    <label className="hc-label">Issue Category</label>
                                    <select
                                        name="issue_category"
                                        className="hc-input"
                                        value={ formData.issue_category }
                                        onChange={ handleChange }
                                        required
                                    >
                                        <option value="" disabled={ true }>Select a category</option>
                                        <option value="General Inquiry">General Inquiry</option>
                                        <option value="Technical Question or Issue">Technical Question or Issue</option>
                                        <option value="Report Question">Report Question</option>
                                        <option value="Feature Request">Feature Request</option>
                                    </select>
                                </div>

                                <div className="hc-group">
                                    <label className="hc-label">How can we help?</label>
                                    <textarea
                                        name="message"
                                        className="hc-input hc-textarea"
                                        placeholder="Describe your issue or question..."
                                        value={ formData.message }
                                        onChange={ handleChange }
                                        required
                                        rows={ 4 }
                                    />
                                </div>
                                <div className="hc-group">
                                    <label className="hc-label">Additional Information (optional)</label>
                                    <textarea
                                        name="additional_info"
                                        className="hc-input hc-textarea"
                                        placeholder="Provide any additional details here (Report ID, etc.)..."
                                        value={ formData.additional_info }
                                        onChange={ handleChange }
                                        rows={ 2 }
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