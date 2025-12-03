#Cyber Clinic user model

from datetime import datetime

class UserAccount:
    #represents a user account with backend-generated UUID
    #corresponds to updated user table schema
    
    def __init__(self, email, organization, phone_number):
        #create new user - password hashing handled by PostgreSQL pgcrypto
        self.user_id = None  #UUID - backend generated
        self.email = email
        self.organization = organization  #required organization field
        self.phone_number = phone_number  #required phone field
        self.password_hash = None  #handled by PostgreSQL pgcrypto
        self.is_active = True  #boolean - account status
        self.created_at = None  #timestamp - set by database
        self.last_login = None  #timestamp - updated on login
        
    def to_dict(self):
        #convert user info to JSON format - exclude sensitive data
        return {
            'user_id': self.user_id,
            'email': self.email,
            'organization': self.organization,
            'phone_number': self.phone_number,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }
    
    def verify_password(self, password):
        #password verification will be handled by PostgreSQL pgcrypto
        #this method signature matches UML but implementation in database
        pass
    
    def update_contact_info(self, email=None, phone=None, organization=None):
        #update user contact information
        if email:
            self.email = email
        if phone:
            self.phone_number = phone
        if organization:
            self.organization = organization
            
    def deactivate_account(self):
        #deactivate user account
        self.is_active = False
        
    def activate_account(self):
        #reactivate user account
        self.is_active = True
    
    def __str__(self):
        return f"UserAccount(user_id={self.user_id}, email='{self.email}', org='{self.organization}')"


class ScanJob:
    #represents a scan execution matching project UML design
    #tracks scan status and timing for network targets
    
    def __init__(self, target):
        #create scan job for a network target
        self.scan_id = None  #uuid - database will generate
        self.status = 'pending'  #enum: pending, running, completed, failed
        self.started_at = None  #datetime - set when scan starts
        self.finished_at = None  #datetime - set when scan completes
        self.target = target  #NetworkTarget object
        
    def mark_running(self):
        #update scan state to running as specified in UML
        self.status = 'running'
        self.started_at = datetime.now()
        
    def mark_completed(self):
        #finalize scan as complete as specified in UML
        self.status = 'completed'
        self.finished_at = datetime.now()
        
    def mark_failed(self, error):
        #record scan failure with error message as specified in UML
        self.status = 'failed'
        self.finished_at = datetime.now()
        self.error = error
        
    def needs_agent(self):
        #determine if scan requires standalone application
        #returns true for internal subnets, false for public domains
        return not self.target.is_public_facing if self.target else False
        
    def to_dict(self):
        #convert scan job to JSON format for API responses
        return {
            'scan_id': str(self.scan_id) if self.scan_id else None,
            'status': self.status,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'finished_at': self.finished_at.isoformat() if self.finished_at else None,
            'needs_agent': self.needs_agent()
        }
    
    def __str__(self):
        return f"ScanJob(scan_id={self.scan_id}, status='{self.status}')"


class NetworkTarget:
    #represents domains or subnets that can be scanned
    #matches Network table in database schema
    
    def __init__(self, subnet_name, subnet_ip, subnet_netmask, is_public_facing=True):
        #create network target matching database schema
        self.subnet_id = None  #bigserial - database will set
        self.subnet_name = subnet_name  #varchar
        self.subnet_ip = subnet_ip  #inet 
        self.subnet_netmask = subnet_netmask  #inet
        self.is_public_facing = is_public_facing  #bool
        self.domains = []  #list of associated domains
        
    def is_public(self):
        #return whether scan runs through web portal or needs agent
        return self.is_public_facing
        
    def add_domain(self, domain, port=443):
        #add domain to scan target as specified in UML
        self.domains.append({'domain': domain, 'port': port})
        
    def to_scan_config(self):
        #generate executable scan configuration as specified in UML
        return {
            'target_id': self.subnet_id,
            'target_name': self.subnet_name,
            'ip_range': str(self.subnet_ip),
            'netmask': str(self.subnet_netmask),
            'domains': self.domains,
            'scan_type': 'public' if self.is_public_facing else 'internal'
        }
        
    def __str__(self):
        return f"NetworkTarget(name='{self.subnet_name}', public={self.is_public_facing})"
