from app.database import get_db
import psycopg2
import os
from dotenv import load_dotenv
import socket
import ssl
import logging

#setup logging
logger = logging.getLogger(__name__)

def authenticate_client_credentials(auth_string):
    """
    Parse and authenticate Austin's client format: "apphash:email:password"
    Returns: (success, user_data, message)
    """
    try:
        #parse format: "hash:email:password"
        parts = auth_string.split(':', 2)
        if len(parts) != 3:
            return False, None, "Invalid authentication format"
        
        app_hash, email, password = parts
        
        #verify user credentials using our auth system
        db = get_db()
        
        #check credentials using same method as our login endpoint
        user_data = db.execute_single(
            """SELECT id, email, organization, phone_number, is_active
               FROM users 
               WHERE email = %s AND password_hash = crypt(%s, password_hash)""",
            (email.strip(), password)
        )
        
        if not user_data:
            return False, None, "Invalid credentials"
        
        if not user_data['is_active']:
            return False, None, "Account deactivated"
        
        logger.info(f"VPN authentication successful for {email}")
        return True, user_data, "Authentication successful"
        
    except Exception as e:
        logger.error(f"VPN authentication error: {e}")
        return False, None, f"Authentication failed: {e}"

def start_vpn_server(host, port, cert, key):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=cert, keyfile=key)
    bindsocket = socket.socket()
    bindsocket.bind((host, port))
    bindsocket.listen(5)
    print(f"VPN server listening on {host}:{port}")
    while True:
        newsocket, fromaddr = bindsocket.accept()
        print(f"Connection from {fromaddr}")
        conn = context.wrap_socket(newsocket, server_side=True)
        try:
            data = conn.recv(1024)
            auth_string = data.decode('latin-1').strip()
            print(f"Received authentication: {auth_string[:20]}...")
            
            #authenticate using Austin's format
            success, user_data, message = authenticate_client_credentials(auth_string)
            
            if success:
                #send success response
                response = f"AUTH_SUCCESS:{user_data['id']}:{user_data['email']}"
                conn.sendall(response.encode('latin-1'))
                logger.info(f"VPN client authenticated: {user_data['email']}")
            else:
                #send failure response
                conn.sendall(f"AUTH_FAILED:{message}".encode('latin-1'))
                logger.warning(f"VPN authentication failed from {fromaddr}: {message}")
                
        except Exception as e:
            logger.error(f"VPN server error: {e}")
            try:
                conn.sendall(b"AUTH_FAILED:Server error")
            except:
                pass
        finally:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError as e:
                print(f"Error during shutdown: {e}")
            conn.close()


def get_user_by_email(email):
    """Get user data by email for VPN authentication"""
    try:
        db = get_db()
        user_data = db.execute_single(
            "SELECT id, email, organization, phone_number, is_active FROM users WHERE email = %s",
            (email,)
        )
        return user_data
    except Exception as e:
        logger.error(f"Failed to get user by email {email}: {e}")
        return None

if __name__ == '__main__':
    load_dotenv()
    
    #use the database manager for connections
    try:
        db = get_db()
        if db.connect():
            logger.info("Database connection established for VPN server")
        else:
            logger.error("Failed to connect to database")
    except Exception as e:
        logger.error(f"Database connection error: {e}")

    vpn_host = os.getenv('VPN_HOST', '127.0.0.1')
    hostname = socket.gethostname()
    print(f"Hostname: {hostname}")
    print(f"VPN Host: {vpn_host}")
    
    vpn_port = int(os.getenv('VPN_PORT', 6666))
    cert = os.getenv('VPN_CRT', '/src/certs/server.crt')
    key = os.getenv('VPN_KEY', '/src/certs/server.key')

    start_vpn_server(hostname, vpn_port, cert, key)
