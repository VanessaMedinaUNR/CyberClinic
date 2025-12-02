#Cyber Clinic user model
#CS 425 Team 13 - Database models

from datetime import datetime

class User:
    #represents a user account in our cyber clinic system
    #stores their personal info and account settings
    
    def __init__(self, username, email, password_hash):
        #create a new user with their basic information
        #password should already be hashed for security
        self.id = None  #database will set this when user is saved
        self.username = username
        self.email = email
        self.password_hash = password_hash  #never store plain text passwords
        self.created_at = datetime.now()
        self.last_login = None
        self.is_active = True
        self.organization = None  #company or group they work for
        
    def to_dict(self):
        #convert user info to dictionary format for sending as JSON
        #leaves out sensitive information like passwords
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'is_active': self.is_active,
            'organization': self.organization
        }
    
    def __str__(self):
        #create a readable text version of the user
        #useful when printing user info for debugging
        return f"User(username='{self.username}', email='{self.email}')"


class ScanRequest:
    #represents a security scan that a user requested
    #keeps track of what to scan and the current progress
    
    def __init__(self, user_id, target_domain, scan_type):
        #create a new scan request for a specific user
        #stores what they want to scan and how
        self.id = None  #database will set this when scan is saved
        self.user_id = user_id
        self.target_domain = target_domain  #website or IP address to scan
        self.scan_type = scan_type  #what tool to use: nmap, nikto, etc
        self.status = 'pending'  #current state: pending, running, completed, failed
        self.created_at = datetime.now()
        self.completed_at = None
        self.results_file = None  #location of scan results when finished
        
    def to_dict(self):
        #convert scan info to dictionary format for sending as JSON
        #frontend can use this to show scan progress to users
        return {
            'id': self.id,
            'user_id': self.user_id,
            'target_domain': self.target_domain,
            'scan_type': self.scan_type,
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'results_file': self.results_file
        }
    
    def __str__(self):
        #create a readable text version of the scan request
        #useful when printing scan info for debugging
        return f"ScanRequest(target='{self.target_domain}', status='{self.status}')"
