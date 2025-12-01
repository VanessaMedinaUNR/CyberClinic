#Cyber Clinic authentication routes
#CS 425 Team 13 - User login/registration

from flask import Blueprint, request, jsonify
import hashlib
import re

#create a blueprint to organize all authentication routes
#keeps login/register code separate from main app
auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

#temporary storage for user accounts (will use real database later)
#this is just for testing until we connect to postgresql
users_db = {}

def hash_password(password):
    #convert plain text password into a secure hash
    #we never store the actual password, only the hashed version
    return hashlib.sha256(password.encode()).hexdigest()

def validate_email(email):
    #check if the email address looks correct
    #uses a pattern to make sure it has @ symbol and domain
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

@auth_bp.route('/register', methods=['POST'])
def register():
    #handle when someone wants to create a new account
    #check their info and save the new user if everything looks good
    try:
        #get the user information from the request
        data = request.get_json()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        organization = data.get('organization', '').strip()
        
        #make sure they provided the required information
        if not username or not email or not password:
            return jsonify({
                'error': 'missing required fields',
                'required': ['username', 'email', 'password']
            }), 400
        
        #check if the email address looks valid
        if not validate_email(email):
            return jsonify({'error': 'invalid email format'}), 400
        
        #make sure password is long enough to be secure
        if len(password) < 6:
            return jsonify({'error': 'password must be at least 6 characters'}), 400
        
        #make sure username isn't already taken
        if username in users_db:
            return jsonify({'error': 'username already exists'}), 409
        
        #make sure email isn't already registered
        for user_data in users_db.values():
            if user_data['email'] == email:
                return jsonify({'error': 'email already registered'}), 409
        
        #create the new user account with secure password hash
        password_hash = hash_password(password)
        user_data = {
            'username': username,
            'email': email,
            'password_hash': password_hash,
            'organization': organization,
            'created_at': '2025-11-30',  #will use proper datetime later
            'is_active': True
        }
        
        #save the user to our temporary storage
        users_db[username] = user_data
        
        #send back success message without showing password
        return jsonify({
            'message': 'user registered successfully',
            'user': {
                'username': username,
                'email': email,
                'organization': organization
            }
        }), 201
        
    except Exception as e:
        #handle any unexpected errors that might happen
        return jsonify({'error': 'registration failed', 'details': str(e)}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    #handle when someone wants to log into their account
    #check their username and password then let them in if correct
    try:
        #get the login information from the request
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        #make sure they provided both username and password
        if not username or not password:
            return jsonify({
                'error': 'missing credentials',
                'required': ['username', 'password']
            }), 400
        
        #check if this username exists in our system
        if username not in users_db:
            return jsonify({'error': 'invalid credentials'}), 401
        
        user_data = users_db[username]
        
        #check if the password they entered matches what we have stored
        password_hash = hash_password(password)
        if password_hash != user_data['password_hash']:
            return jsonify({'error': 'invalid credentials'}), 401
        
        #make sure their account is still active
        if not user_data['is_active']:
            return jsonify({'error': 'account deactivated'}), 403
        
        #login successful, send back their account info
        return jsonify({
            'message': 'login successful',
            'user': {
                'username': user_data['username'],
                'email': user_data['email'],
                'organization': user_data['organization']
            },
            'session': 'temporary-session-token'  #will implement proper jwt later
        }), 200
        
    except Exception as e:
        #handle any unexpected errors during login
        return jsonify({'error': 'login failed', 'details': str(e)}), 500

@auth_bp.route('/users', methods=['GET'])
def list_users():
    #show all registered users (for development testing only)
    #this will be removed in production for security reasons
    #create a list of users without showing passwords
    user_list = []
    for username, user_data in users_db.items():
        user_list.append({
            'username': user_data['username'],
            'email': user_data['email'],
            'organization': user_data['organization'],
            'is_active': user_data['is_active']
        })
    
    return jsonify({
        'users': user_list,
        'count': len(user_list),
        'note': 'development endpoint, will be removed in production'
    }), 200
