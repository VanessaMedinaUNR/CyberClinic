#Cyber clinic backend - Email service
#Sends verification, invite, and report notification emails via SMTP

import smtplib
import os
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)

SMTP_HOST    = os.environ.get('SMTP_HOST', 'mailhog')
SMTP_PORT    = int(os.environ.get('SMTP_PORT', 1025))
SMTP_USER    = os.environ.get('SMTP_USER', '')
SMTP_PASS    = os.environ.get('SMTP_PASS', '')
EMAIL_FROM   = os.environ.get('EMAIL_FROM', 'noreply@cyberclinic.unr.edu')
APP_BASE_URL = os.environ.get('APP_BASE_URL', 'http://localhost:3000')
BACKEND_URL  = os.environ.get('BACKEND_URL', 'http://localhost:5001')


def _send(to, subject, html_body):
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From']    = EMAIL_FROM
    msg['To']      = to
    msg.attach(MIMEText(html_body, 'html'))
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
        if SMTP_USER and SMTP_PASS:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASS)
        smtp.sendmail(EMAIL_FROM, to, msg.as_string())
    logger.info(f"Email sent to {to}: {subject}")


def send_verification_email(to, token):
    link = f"{BACKEND_URL}/api/auth/verify/{token}"
    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto">
      <h2 style="color:#2c3e50">Welcome to CyberClinic</h2>
      <p>Please verify your email address to activate your account:</p>
      <p>
        <a href="{link}"
           style="background:#2c3e50;color:white;padding:10px 24px;
                  text-decoration:none;border-radius:4px;display:inline-block">
          Verify Email
        </a>
      </p>
      <p style="color:#888;font-size:12px">
        This link expires in 24 hours. If you did not create an account, ignore this email.
      </p>
    </div>
    """
    _send(to, "Verify your CyberClinic account", html)


def send_invite_email(to, token, invited_by, temp_password):
    link = f"{BACKEND_URL}/api/auth/verify/{token}"
    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto">
      <h2 style="color:#2c3e50">You've been invited to CyberClinic</h2>
      <p><strong>{invited_by}</strong> has invited you to join their organization.</p>
      <p>Click below to verify your account and get started:</p>
      <p>
        <a href="{link}"
           style="background:#2c3e50;color:white;padding:10px 24px;
                  text-decoration:none;border-radius:4px;display:inline-block">
          Accept Invitation
        </a>
      </p>
      <p>Your temporary password: <strong style="font-size:16px">{temp_password}</strong></p>
      <p style="color:#888;font-size:12px">
        Please change your password after your first login. This link expires in 24 hours.
      </p>
    </div>
    """
    _send(to, "You've been invited to CyberClinic", html)


def send_report_notification(admin_email, report_id, client_name):
    link = f"{APP_BASE_URL}/reports/{report_id}"
    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto">
      <h2 style="color:#2c3e50">Scan Report Ready</h2>
      <p>A new security scan report is available for <strong>{client_name}</strong>.</p>
      <p>
        <a href="{link}"
           style="background:#2c3e50;color:white;padding:10px 24px;
                  text-decoration:none;border-radius:4px;display:inline-block">
          View Report
        </a>
      </p>
    </div>
    """
    _send(admin_email, f"CyberClinic: New report ready for {client_name}", html)

# Done by Manuel Morales-Marroquin