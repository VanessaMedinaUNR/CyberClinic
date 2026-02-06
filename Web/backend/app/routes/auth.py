#Cyber Clinic Authentication Routes
#Handles user login and registration with email-based authentication

from flask import Blueprint, request, jsonify
import re
import bcrypt
import secrets
import logging
import hashlib
import phonenumbers
from app.database import get_db
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
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

def validate_and_format_phone(phone_number):
    #validate phone number format
    try:
        parsed_phone = phonenumbers.parse(phone_number, "US")
    except Exception:
        return jsonify({'error': 'invalid phone number format'}), 400
    if not phonenumbers.is_valid_number(parsed_phone):
        return jsonify({'error': 'invalid phone number'}), 400
    formatted_phone = phonenumbers.format_number(parsed_phone, phonenumbers.PhoneNumberFormat.NATIONAL)
    return(formatted_phone)


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
        
        #validate and format phone number
        formatted_phone = validate_and_format_phone(phone_number)
        
        #make sure password is long enough to be secure
        if len(password) < 6:
            return jsonify({'error': 'password must be at least 6 characters'}), 400
        
        
        try:
            #use database when available
            db = get_db()
            
            #check if email is already registered
            existing_user = db.execute_single(
                "SELECT user_id FROM users WHERE email = %s", (email,)
            )
            
            if existing_user:
                return jsonify({'error': 'email already registered'}), 409
            
            client_id: str
            client = db.execute_single(
                "SELECT client_id FROM client WHERE client_name = %s", (client_name,)
            )

            client_admin = False # User not admin by default

            # Create new client if it does not already exist
            if not client:
                print("Creating client")
                client_admin = True # First user to a client is admin by default
                client_id = db.execute_single(
                     """INSERT INTO client (client_name)
                     VALUES (%s)
                     RETURNING client_id""",
                     (client_name,)
                )["client_id"]
            else:
                client_id = client["client_id"]
                
            
            #insert new user into database
            #password hashing will be done by PostgreSQL pgcrypto
            user_id = db.execute_single(
                """INSERT INTO users (email, password_hash, client_admin, phone_number)
                VALUES (%s, crypt(%s, gen_salt('bf')), %s, %s)
                RETURNING user_id""",
                (email, password, client_admin, formatted_phone,)
            )["user_id"]
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

@auth_bp.route('/user', methods=['GET'])
@jwt_required()
def get_user():
    user_id = get_jwt_identity()

    try:
        db = get_db()

        user = db.execute_single(
            """SELECT * FROM users NATURAL JOIN (client_users NATURAL JOIN client) WHERE user_id = %s""",
            (user_id,)
        )

        return jsonify({
            'email': user['email'],
            'phone': user['phone_number'],
            'admin': user['client_admin'],
            'scan_frequency': user['scan_frequency']
        }), 200
    except Exception as e:
        logger.error(e)
        return jsonify({
            'error': 'Connection Error',
            'details': 'Please try again later'
        }), 500

@auth_bp.route('/user', methods=['POST'])
@jwt_required()
def update_user():
    user_id = get_jwt_identity()

    try:
        data = request.get_json()
        email = data.get('email')
        phone = data.get('phone')
        old = data.get('old_password')
        new = data.get('new_password')
        scan_frequency = data.get('scan_frequency')

        updated = False

        if email:
            #validate email format
            if not is_valid_email(email):
                return jsonify({'error': 'invalid email format'}), 400
            db = get_db()
            db.execute_command(
                """UPDATE users SET email = %s WHERE user_id = %s""",
                (email, user_id,)
            )
            updated = True
            logger.info(f'{user_id}: email updated.')
        if phone: 
            #validate and format phone number
            formatted_phone = validate_and_format_phone(phone)
            db = get_db()
            db.execute_command(
                """UPDATE users SET phone_number = %s WHERE user_id = %s""",
                (formatted_phone, user_id,)
            )
            updated = True
            logger.info(f'{user_id}: phone number updated.')
        if new and old:
            db = get_db()
            check = db.execute_single(
                """SELECT password_hash FROM users WHERE user_id = %s AND password_hash = crypt(%s, password_hash)""",
                (user_id, old,)
            )["password_hash"]
            if check:
                if bcrypt.checkpw(bytes(new, encoding="utf-8"), bytes(check, encoding="utf-8")):
                    return jsonify({
                        'error': 'New password cannot be the same as old password',
                        'details': 'Please try again'
                    }), 406
                db.execute_command(
                    """UPDATE users SET password_hash = crypt(%s, gen_salt('bf')) WHERE user_id = %s""",
                    (new, user_id,)
                )
                updated = True
                logger.info(f"{user_id}: Password updated.")
            else:
                return jsonify({
                    'error': 'Invalid Password',
                    'details': 'Please try again'
                }), 406
        if scan_frequency:
            db = get_db()
            client_id = db.execute_single(
                """SELECT client_id FROM client_users WHERE user_id = %s""",
                (user_id,)
            )['client_id']
            db.execute_command(
                """UPDATE client SET scan_frequency = %s WHERE client_id = %s""",
                (scan_frequency, client_id,)
            )
            updated = True
            logger.info(f'{client_id}: Scan frequency updated.')

        if not updated:
            return jsonify({
                'error': 'User Not Updated',
                'details': 'Please try again later'
            }), 500

        return jsonify({
            'message': 'User updated sucessfully!'
        }), 200

    except Exception as e:
        logger.error(e)
        return jsonify({
            'error': 'Format Error',
            'details': 'Please try again'
        }), 500

# Done by Morales-Marroquin and Austin Finch