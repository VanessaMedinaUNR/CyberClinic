#Cyber Clinic Authentication Routes
#Handles user login and registration with email-based authentication

from flask import Blueprint, request, jsonify, redirect
import os
import re
import bcrypt
import secrets
import logging
import hashlib
import phonenumbers
from app.database import get_db, block_jwt
from app.email_service import send_verification_email, send_invite_email
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, create_refresh_token, get_jwt
from datetime import timedelta, datetime

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
        logger.info(data)
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        client_name = data.get('organization', '').strip()
        phone_number = data.get('phone', '').strip()

        location = data.get('location', None)
        
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
        phone_result = validate_and_format_phone(phone_number)
        if isinstance(phone_result, tuple):
            return phone_result
        formatted_phone = phone_result

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

            #new org: ask for location first, then create everything in one transaction
            if not client:
                if not location:
                    return jsonify({
                        'message': f'Welcome {client_name}! Please enter your organization location.'
                    }), 202

                country  = location.get('country', '').strip()
                province = location.get('state', '').strip()
                city     = location.get('city', '').strip()

                if not country or not province or not city:
                    return jsonify({'error': 'country, state, and city are required for new organizations'}), 400

                verification_token = secrets.token_urlsafe(32)
                token_expires_at   = datetime.utcnow() + timedelta(hours=24)

                #single transaction: client + user + client_users all roll back together on failure
                with db.get_cursor() as cursor:
                    cursor.execute(
                        """INSERT INTO client (client_name, country, province, city)
                           VALUES (%s, %s, %s, %s) RETURNING client_id""",
                        (client_name, country, province, city)
                    )
                    client_id = cursor.fetchone()['client_id']

                    cursor.execute(
                        """INSERT INTO users (email, password_hash, client_admin, active, phone_number, verification_token, token_expires_at)
                           VALUES (%s, crypt(%s, gen_salt('bf')), TRUE, TRUE, %s, %s, %s) RETURNING user_id""",
                        (email, password, formatted_phone, verification_token, token_expires_at)
                    )
                    user_id = cursor.fetchone()['user_id']

                    cursor.execute(
                        "INSERT INTO client_users (user_id, client_id) VALUES (%s, %s)",
                        (user_id, client_id)
                    )

            else:
                #existing org: add user as non-admin, no location needed
                client_id          = client["client_id"]
                verification_token = secrets.token_urlsafe(32)
                token_expires_at   = datetime.utcnow() + timedelta(hours=24)

                with db.get_cursor() as cursor:
                    cursor.execute(
                        """INSERT INTO users (email, password_hash, client_admin, active, phone_number, verification_token, token_expires_at)
                           VALUES (%s, crypt(%s, gen_salt('bf')), FALSE, FALSE, %s, %s, %s) RETURNING user_id""",
                        (email, password, formatted_phone, verification_token, token_expires_at)
                    )
                    user_id = cursor.fetchone()['user_id']

                    cursor.execute(
                        "INSERT INTO client_users (user_id, client_id) VALUES (%s, %s)",
                        (user_id, client_id)
                    )

            try:
                send_verification_email(email, verification_token)
            except Exception as email_err:
                logger.warning(f"Could not send verification email to {email}: {email_err}")

            return jsonify({
                'message': 'Registration successful. Please check your email to verify your account.',
                'user': {
                    'email': email,
                    'organization': client_name,
                }
            }), 201
            
        except Exception as db_error:
            #database connection error
            logger.warning(db_error)
            return jsonify({
                'error': 'Connection Error',
                'details': 'Please try again later'
            }), 500
        
    except Exception as e:
        #handle any unexpected errors that might happen
        logger.error(str(e))
        return jsonify({'error': 'Registration failed'}), 500

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
                """SELECT u.user_id, cu.client_id, email, phone_number, client_admin, active, email_verified
                   FROM users u 
                   JOIN client_users cu ON u.user_id = cu.user_id
                   WHERE email = %s AND password_hash = crypt(%s, password_hash)""",
                (email, password)
            )

            if not user_data:
                logger.warning(f'Failed login for {email}')
                return jsonify({'error': 'Invalid credentials'}), 401
            elif not user_data['email_verified']:
                logger.warning(f'Unverified email login attempt for {email}')
                return jsonify({'error': 'Email not verified'}), 403
            elif not user_data['active']:
                logger.warning(f'Inactive account login attempt for {email}')
                return jsonify({'error': 'Account not active. Please contact your client administrator.'}), 403

            #generate JWT Token
            token = create_access_token(identity=user_data["user_id"], expires_delta=timedelta(minutes=10), fresh=True)
            refresh_token = create_refresh_token(user_data["user_id"], expires_delta=timedelta(hours=2))

            #login successful
            return jsonify({
                'message': 'login successful',
                'access_token': token,
                'refresh_token': refresh_token
            }), 200
            
        except Exception as db_error:
            #database connection error
            logger.warning(db_error)
            return jsonify({
                'error': 'Connection Error',
                'details': 'Please try again later'
            }), 500
        
    except Exception as e:
        #handle any unexpected errors during login
        return jsonify({'error': 'login failed', 'details': str(e)}), 500


@auth_bp.route('/status', methods=['GET'])
@jwt_required(optional=True)
def status():
    #check if user is logged in by verifying JWT token
    try:
        user_id = get_jwt_identity()
        if user_id:
            db = get_db()
            userdata = db.execute_single(
                """SELECT * FROM users WHERE user_id = %s""",
                (user_id,)
            )
            return jsonify({'logged_in': True, 'admin': userdata['client_admin']}), 200
        else:
            return jsonify({'logged_in': False}), 200
    except Exception as e:
        logger.error(f"Error checking login status: {e}")
        return jsonify({'error': 'Status check failed'}), 500


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    #handle when someone wants to log out of their account
    try:
        jti = get_jwt()['jti']
        block_jwt(jti)
        return jsonify({'message': 'logout successful'}), 200
    except Exception as e:
        logger.error(e)
        return jsonify({'error': 'Logout failed', 'details': str(e)}), 500


@auth_bp.route('/refresh', methods = ['POST'])
@jwt_required(refresh=True)
def refresh_token():
    current_user = get_jwt_identity()
    new_token = create_access_token(identity=current_user, fresh=False, expires_delta=timedelta(minutes=10))
    new_refresh_token = create_refresh_token(identity=current_user, expires_delta=timedelta(minutes=30))
    old = get_jwt()['jti']
    block_jwt(old)
    return {"access_token": new_token, "refresh_token": new_refresh_token}, 200

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

        admin = bool(user['client_admin'])
        if admin:
            return jsonify({
                'email': user['email'],
                'phone': user['phone_number'],
                'admin': admin,
                'scan_frequency': user['scan_frequency']
            }), 200
        else:
            return jsonify({
                'email': user['email'],
                'phone': user['phone_number'],
                'admin': admin,
            }), 200
    except Exception as e:
        logger.error(e)
        return jsonify({
            'error': 'Connection Error',
            'details': 'Please try again later'
        }), 500

@auth_bp.route('/user', methods=['POST'])
@jwt_required(fresh=True)
def update_user():
    user_id = get_jwt_identity()
    access_token = get_jwt()
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
            user_check = db.execute_single(
                """SELECT password_hash FROM users WHERE user_id = %s AND password_hash = crypt(%s, password_hash)""",
                (user_id, old,)
            )
            if not user_check:
                return jsonify({
                    'error': 'Invalid Password',
                    'details': 'Please try again'
                }), 406
            check = user_check["password_hash"]
            if bcrypt.checkpw(bytes(new, encoding="utf-8"), bytes(check, encoding="utf-8")):
                return jsonify({
                    'error': 'New password cannot be the same as old password',
                    'details': 'Please try again'
                }), 406
            db.execute_command(
                """UPDATE users SET password_hash = crypt(%s, gen_salt('bf')) WHERE user_id = %s""",
                (new, user_id,)
            )
            blocked = block_jwt(access_token["jti"])
            if blocked:
                access_token = create_access_token(identity=user_id, fresh=True, expires_delta=timedelta(minutes=5))
            updated = True
            logger.info(f"{user_id}: Password updated.")
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
            'message': 'User updated sucessfully!',
            'access_token': access_token
        }), 200

    except Exception as e:
        logger.error(e)
        return jsonify({
            'error': 'Format Error',
            'details': 'Please try again'
        }), 500

@auth_bp.route('/verify/<token>', methods=['GET'])
def verify_email(token):
    try:
        db = get_db()
        user = db.execute_single(
            """SELECT user_id FROM users
               WHERE verification_token = %s AND token_expires_at > NOW()""",
            (token,)
        )
        if not user:
            return jsonify({'error': 'Invalid or expired verification link'}), 400
        db.execute_command(
            """UPDATE users
               SET email_verified = TRUE, verification_token = NULL, token_expires_at = NULL
               WHERE user_id = %s""",
            (user['user_id'],)
        )
        app_base_url = os.environ.get('APP_BASE_URL', 'http://localhost:3000')
        return redirect(f"{app_base_url}/login?verified=true")
    except Exception as e:
        logger.error(f"Email verification failed: {e}")
        return jsonify({'error': 'Verification failed'}), 500


@auth_bp.route('/admin/invite-user', methods=['POST'])
@jwt_required()
def invite_user():
    requesting_user_id = get_jwt_identity()
    try:
        db = get_db()

        requester = db.execute_single(
            "SELECT client_admin, email FROM users WHERE user_id = %s",
            (requesting_user_id,)
        )
        if not requester or not requester['client_admin']:
            return jsonify({'error': 'Admin access required'}), 403

        data = request.get_json()
        email        = data.get('email', '').strip().lower()
        phone_number = data.get('phone', '').strip()

        if not email:
            return jsonify({'error': 'Email required'}), 400
        if not is_valid_email(email):
            return jsonify({'error': 'Invalid email format'}), 400

        existing = db.execute_single("SELECT user_id FROM users WHERE email = %s", (email,))
        if existing:
            return jsonify({'error': 'Email already registered'}), 409

        client = db.execute_single(
            "SELECT client_id FROM client_users WHERE user_id = %s",
            (requesting_user_id,)
        )
        if not client:
            return jsonify({'error': 'Client not found'}), 404
        client_id = client['client_id']

        formatted_phone = '(000) 000-0000'
        if phone_number:
            try:
                parsed = phonenumbers.parse(phone_number, "US")
                if phonenumbers.is_valid_number(parsed):
                    formatted_phone = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
            except Exception:
                pass

        temp_password  = secrets.token_urlsafe(12)
        invite_token   = secrets.token_urlsafe(32)
        token_expires_at = datetime.utcnow() + timedelta(hours=24)

        user_id = db.execute_single(
            """INSERT INTO users
               (email, password_hash, client_admin, phone_number, verification_token, token_expires_at)
               VALUES (%s, crypt(%s, gen_salt('bf')), FALSE, %s, %s, %s)
               RETURNING user_id""",
            (email, temp_password, formatted_phone, invite_token, token_expires_at)
        )["user_id"]

        db.execute_command(
            "INSERT INTO client_users (user_id, client_id) VALUES (%s, %s)",
            (user_id, client_id)
        )

        try:
            send_invite_email(email, invite_token, requester['email'], temp_password)
        except Exception as email_err:
            logger.warning(f"Could not send invite email to {email}: {email_err}")

        return jsonify({'message': f'Invitation sent to {email}'}), 201

    except Exception as e:
        logger.error(f"Invite user failed: {e}")
        return jsonify({'error': 'Failed to send invitation'}), 500


@auth_bp.route('/admin/toggle-status', methods=['POST'])
@jwt_required()
def toggle_user_status():
    user_id = get_jwt_identity()
    try:
        db = get_db()
        admin_check = db.execute_single(
            """SELECT client_admin FROM users WHERE user_id = %s""",
            (user_id,)
        )["client_admin"]
        if not admin_check:
            return jsonify({
                'error': 'Unauthorized',
                'details': 'Admin privileges required'
            }), 403
        
        data = request.get_json()
        approve_user_id = data.get('user_id')
        status = data.get('status')
        db.execute_command(
            """UPDATE users SET active = %s WHERE user_id = %s""",
            (status, approve_user_id,)
        )
        logger.info(f'{approve_user_id} status updated by {user_id}')
        return jsonify({
            'message': 'User status updated successfully'
        }), 200
    except Exception as e:
        logger.error(e)
        return jsonify({
            'error': 'Connection Error',
            'details': 'Please try again later'
        }), 500
    
@auth_bp.route('/admin/get-users', methods=['GET'])
@jwt_required()
def get_users():
    user_id = get_jwt_identity()
    try:
        db = get_db()
        admin_check = db.execute_single(
            """SELECT client_admin FROM users WHERE user_id = %s""",
            (user_id,)
        )["client_admin"]
        if not admin_check:
            return jsonify({
                'error': 'Unauthorized',
                'details': 'Admin privileges required'
            }), 403
        
        users = db.execute_query(
            """SELECT user_id, email, phone_number, active, email_verified FROM users
            NATURAL JOIN (client_users NATURAL JOIN client)
            WHERE client_id = (SELECT client_id FROM client_users WHERE user_id = %s) AND user_id != %s""",
            (user_id, user_id,)
        )

        return jsonify({
            'users': users
        }), 200
    except Exception as e:
        logger.error(e)
        return jsonify({
            'error': 'Connection Error',
            'details': 'Please try again later'
        }), 500

# Done by Manuel Morales-Marroquin and Austin Finch