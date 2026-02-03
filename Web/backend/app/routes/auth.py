#Cyber Clinic Authentication Routes
#Handles user login and registration with email-based authentication

from flask import Blueprint, request, jsonify
import re
import uuid
import secrets
import logging
import hashlib
import phonenumbers
from app.database import get_db
from flask_jwt_extended import create_access_token
from datetime import datetime, timezone, timedelta

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

#create blueprint for authentication routes
auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')
#temporary storage for development (fallback when DB is unavailable)
users_db = {}

#validation functions
def is_valid_email(email):
    """Validate email format using regex pattern"""
    pattern = r'^\w+@[a-zA-Z_]+?\.[a-zA-Z]{2,3}$'
    return bool(re.match(pattern, email))

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
        client_name = data.get('organization', '').strip()
        phone_number = data.get('phone', '').strip() 
        
        #make sure they provided the required information
        if not email or not password or not client_name or not phone_number:
            return jsonify({
                'error': 'missing required fields',
                'required': ['email', 'password', 'organization', 'phone']
            }), 400
        
        #validate email format
        if not is_valid_email(email):
            return jsonify({'error': 'invalid email format'}), 400
        
        #validate phone number format
        try:
            parsed_phone = phonenumbers.parse(phone_number, "US")
        except Exception:
            return jsonify({'error': 'invalid phone number format'}), 400
        if not phonenumbers.is_valid_number(parsed_phone):
            return jsonify({'error': 'invalid phone number'}), 400
        formatted_phone = phonenumbers.format_number(parsed_phone, phonenumbers.PhoneNumberFormat.NATIONAL)
        logger.info(f'Formatted Phone: {formatted_phone}')
        #make sure password is long enough to be secure
        if len(password) < 6:
            return jsonify({'error': 'password must be at least 6 characters'}), 400
        
        #generate unique user ID
        user_id = str(uuid.uuid4())
        client_id = str(uuid.uuid4())
        
        try:
            #use database when available
            db = get_db()
            
            #check if email is already registered
            existing_user = db.execute_single(
                "SELECT user_id FROM users WHERE email = %s", (email,)
            )
            
            if existing_user:
                return jsonify({'error': 'email already registered'}), 409
            
            client = db.execute_single(
                "SELECT client_id FROM client WHERE client_name = %s", (client_name,)
            )

            client_admin = False # User not admin by default

            # Create new client if it does not already exist
            if not client:
                print("Creating client")
                client_admin = True # First user to a client is admin by default
                db.execute_command(
                     """INSERT INTO client (client_id, client_name)
                     VALUES (%s, %s)""",
                     (client_id, client_name)
                )
                
            
            #insert new user into database
            #password hashing will be done by PostgreSQL pgcrypto
            db.execute_command(
                """INSERT INTO users (user_id, email, password_hash, client_admin, phone_number)
                VALUES (%s, %s, crypt(%s, gen_salt('bf')), %s, %s)""",
                (user_id, email, password, client_admin, formatted_phone)
            )
            db.execute_command(
                """INSERT INTO client_users (user_id, client_id)
                VALUES (%s, %s)""",
                (user_id, client_id)
            )
            
            #send back success message without showing password
            return jsonify({
                'message': 'user registered successfully',
                'user': {
                    'user_id': user_id,
                    'email': email,
                    'organization': client_name,
                    'phone_number': phone_number
                }
            }), 201
            
        except Exception as db_error:
            #Database connection error
            logger.warning(db_error)
            return jsonify({
                'error': 'Connection Error',
                'details': 'Please try again later'
            }), 500
        
    except Exception as e:
        #handle any unexpected errors that might happen
        logger.error(str(e))
        return jsonify({'error': 'registration failed'}), 500

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
                """SELECT u.user_id, cu.client_id, email, phone_number, client_admin
                   FROM users u 
                   JOIN client_users cu ON u.user_id = cu.user_id
                   WHERE email = %s AND password_hash = crypt(%s, password_hash)""",
                (email, password)
            )

            if not user_data:
                logger.warning(f'Failed login for {email}')
                return jsonify({'error': 'invalid credentials'}), 401
            
            client = db.execute_single(
                """SELECT * FROM client WHERE client_id = %s""",
                (user_data['client_id'],)
            )
            
            #Generate JWT Token
            token = create_access_token(identity=user_data["user_id"])

            #login successful
            return jsonify({
                'message': 'login successful',
                'access_token': token
            }), 200
            
        except Exception as db_error:
            #Database connection error
            logger.warning(db_error)
            return jsonify({
                'error': 'Connection Error',
                'details': 'Please try again later'
            }), 500
        
    except Exception as e:
        #handle any unexpected errors during login
        return jsonify({'error': 'login failed', 'details': str(e)}), 500

# Done by Morales-Marroquin and Austin Finch