#Cyber Clinic Authentication Routes
#Handles user login and registration with email-based authentication

from flask import Blueprint, request, jsonify
import re
import uuid
import hashlib
import secrets
from app.database import get_db

#create blueprint for authentication routes
auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')
#temporary storage for development (fallback when DB is unavailable)
users_db = {}

#validation functions
def is_valid_email(email):
    """Validate email format using regex pattern"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def is_valid_phone(phone):
    """Validate phone number format (flexible, accepts various international formats)"""
    if not phone or len(phone.strip()) < 7:
        return False
    #check for multiple plus signs (invalid)
    if phone.count('+') > 1:
        return False
    #remove all formatting characters and spaces
    cleaned = re.sub(r'[\s\-\(\)\+\.\s]', '', phone)
    #check if it's all digits after cleaning
    if not cleaned.isdigit():
        return False
    length = len(cleaned)
    return 7 <= length <= 15

#password hashing for fallback storage
def hash_password(password):
    """Create secure password hash using PBKDF2"""
    salt = secrets.token_hex(16)
    hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}:{hash_bytes.hex()}"

def verify_password(password, stored_hash):
    """Verify password against stored hash"""
    try:
        salt, hash_hex = stored_hash.split(':', 1)
        hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return hash_hex == hash_bytes.hex()
    except ValueError:
        return False

@auth_bp.route('/register', methods=['POST'])
def register():
    #handle when someone wants to create a new account
    #PostgreSQL expects: email, organization, password, phone_number
    #backend generates user_id automatically
    try:
        #get the user information from the request
        data = request.get_json()
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        organization = data.get('organization', '').strip()
        phone_number = data.get('phone', '').strip() 
        
        #make sure they provided the required information
        if not email or not password or not organization or not phone_number:
            return jsonify({
                'error': 'missing required fields',
                'required': ['email', 'password', 'organization', 'phone']
            }), 400
        
        #validate email format
        if not is_valid_email(email):
            return jsonify({'error': 'invalid email format'}), 400
        
        #validate phone number format
        if not is_valid_phone(phone_number):
            return jsonify({'error': 'invalid phone number format'}), 400
        
        #make sure password is long enough to be secure
        if len(password) < 6:
            return jsonify({'error': 'password must be at least 6 characters'}), 400
        
        #generate unique user ID
        user_id = str(uuid.uuid4())
        
        try:
            #use database when available
            db = get_db()
            
            #check if email is already registered
            existing_user = db.execute_single(
                "SELECT id FROM users WHERE email = %s", (email,)
            )
            
            if existing_user:
                return jsonify({'error': 'email already registered'}), 409
            
            #insert new user into database
            #password hashing will be done by PostgreSQL pgcrypto
            db.execute_command(
                """INSERT INTO users (id, email, password_hash, organization, phone_number)
                   VALUES (%s, %s, crypt(%s, gen_salt('bf')), %s, %s)""",
                (user_id, email, password, organization, phone_number)
            )
            
            #send back success message without showing password
            return jsonify({
                'message': 'user registered successfully',
                'user': {
                    'user_id': user_id,
                    'email': email,
                    'organization': organization,
                    'phone_number': phone_number
                }
            }), 201
            
        except Exception as db_error:
            #fallback to temporary storage for development
            #check if email is already registered in temp storage
            for temp_user_data in users_db.values():
                if temp_user_data['email'] == email:
                    return jsonify({'error': 'email already registered'}), 409
            
            #create new user in temporary storage with secure password hashing
            password_hash = hash_password(password)
            user_data = {
                'user_id': user_id,
                'email': email,
                'password_hash': password_hash, 
                'organization': organization,
                'phone_number': phone_number,
                'created_at': '2025-12-03',
                'is_active': True
            }
            
            #save to temporary storage using email as key since no username
            users_db[email] = user_data
            
            #send back success message
            return jsonify({
                'message': 'user registered successfully (temp storage)',
                'user': {
                    'user_id': user_id,
                    'email': email,
                    'organization': organization,
                    'phone_number': phone_number
                }
            }), 201
        
    except Exception as e:
        #handle any unexpected errors that might happen
        return jsonify({'error': 'registration failed', 'details': str(e)}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    #handle when someone wants to log into their account
    #login with email and password
    try:
        #get the login information from the request
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        #make sure they provided both email and password
        if not email or not password:
            return jsonify({
                'error': 'missing credentials',
                'required': ['email', 'password']
            }), 400
        
        try:
            #use database when available
            db = get_db()
            
            #check if user exists and password is correct using pgcrypto
            user_data = db.execute_single(
                """SELECT id, email, organization, phone_number, is_active
                   FROM users 
                   WHERE email = %s AND password_hash = crypt(%s, password_hash)""",
                (email, password)
            )
            
            if not user_data:
                return jsonify({'error': 'invalid credentials'}), 401
            
            #make sure account is active
            if not user_data['is_active']:
                return jsonify({'error': 'account deactivated'}), 403
            
            #login successful
            return jsonify({
                'message': 'login successful',
                'user': {
                    'user_id': user_data['id'],
                    'email': user_data['email'],
                    'organization': user_data['organization'],
                    'phone_number': user_data['phone_number']
                },
                'session': 'temporary-session-token'
            }), 200
            
        except Exception as db_error:
            #fallback to temporary storage for development
            if email not in users_db:
                return jsonify({'error': 'invalid credentials'}), 401
            
            user_data = users_db[email]
            
            #check if password matches using secure verification
            if not verify_password(password, user_data['password_hash']):
                return jsonify({'error': 'invalid credentials'}), 401
            
            #make sure account is active
            if not user_data['is_active']:
                return jsonify({'error': 'account deactivated'}), 403
            
            #login successful
            return jsonify({
                'message': 'login successful (temp storage)',
                'user': {
                    'user_id': user_data['user_id'],
                    'email': user_data['email'],
                    'organization': user_data['organization'],
                    'phone_number': user_data['phone_number']
                },
                'session': 'temporary-session-token'
            }), 200
        
    except Exception as e:
        #handle any unexpected errors during login
        return jsonify({'error': 'login failed', 'details': str(e)}), 500
