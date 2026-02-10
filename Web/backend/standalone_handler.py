import atexit
from app.database import get_db
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
        parts = auth_string.split(':')
        if len(parts) != 3:
            return False, None, "Invalid authentication format"
        
        app_hash, email, password = parts
        
        #verify user credentials using our auth system
        db = get_db()
        
        #check credentials using same method as our login endpoint
        user_data = db.execute_single(
            """SELECT user_id, email, client_id, client_admin FROM users NATURAL JOIN client_users WHERE users.email = %s AND password_hash = crypt(%s, password_hash)""",
            (email.strip(), password)
        )
        
        if not user_data:
            return False, None, "Invalid credentials"
        
        if not user_data['client_admin']:
            return False, None, "This action can only be completed by an Administrator"
        
        logger.info(f"VPN authentication successful for {email}")
        return True, user_data, "Authentication successful"
        
    except Exception as e:
        logger.error(f"VPN authentication error: {e}")
        return False, None, f"Authentication failed: {e}"


def start_auth_tunnel(host, port, cert, key, bindsocket):
    logger.info(f'loading {cert}')
    logger.info(f'loading {key}')

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert, keyfile=key)
    print(f"Auth tunnel listening on {host}:{port}")
    while True:
        newsocket, fromaddr = bindsocket.accept()
        print(f"Connection from {fromaddr}")
        conn = context.wrap_socket(newsocket, server_side=True)
        authenticate_standalone_client(conn, fromaddr)
        

def authenticate_standalone_client(conn, fromaddr):
    try:
        data = conn.recv(1024)
        auth_string = data.decode('latin-1').strip()
        print(f"Received authentication: {auth_string[:20]}...")
        
        #authenticate using Austin's format
        success, user_data, message = authenticate_client_credentials(auth_string)
        
        if success:
            #send success response
            response = f"AUTH_SUCCESS"
            conn.sendall(response.encode('latin-1'))
            client_id = user_data['client_id']
            logger.info(f"Client authenticated: {client_id}")

            valid, key = validate_subnet(conn, client_id)
            if not valid:
                return
        else:
            #send failure response
            conn.sendall(f"AUTH_FAILED:{message}".encode('latin-1'))
            logger.warning(f"Tunnel authentication failed from {fromaddr}: {message}")
                
    except Exception as e:
        logger.error(f"Auth tunnel error: {e}")
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

def validate_subnet(conn, client_id):
    try:
        db = get_db()
        subnet_list = db.execute_query(
            """SELECT subnet_name FROM network WHERE client_id = %s AND public_facing = FALSE""",
            (client_id,)
        )
        if not subnet_list:
            response = f"SUBNET_INVALID"
            conn.sendall(response.encode('latin-1'))
        else:
            logger.info(f'Client Subnet List: {subnet_list}')
            response = f"SUBNET_LIST"
            for subnet in subnet_list:
                name = subnet['subnet_name']
                response += f':{name}'
            conn.sendall(response.encode('latin-1'))

            data = conn.recv(1024)
            subnet = data.decode('latin-1').strip()
            response = f"SUBNET_INVALID"
            for check in subnet_list:
                name = check["subnet_name"]
                logger.info(f"{name} : {subnet}")
                if name == subnet:
                    response = f"SUBNET_VALID"
                    break
            conn.sendall(response.encode('latin-1'))
    except ConnectionError:
        logger.info(f'Standalone client reset the connection')
        return False, None
    except Exception as e:
        logger.warning(f"Unhandled server error {e}")
        return False, None


def get_user_by_email(email):
    """Get user data by email for VPN authentication"""
    try:
        db = get_db()
        user_data = db.execute_single(
            "SELECT user_id, email, client_id, client_admin FROM users NATURAL JOIN client_users WHERE users.email = %s",
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

    vpn_host = os.getenv('BACKEND_SERVER', '0.0.0.0')
    hostname = socket.gethostname()
    print(f"Hostname: {hostname}")
    print(f"VPN Host: {vpn_host}")
    
    vpn_port = int(os.getenv('VPN_PORT', 6666))
    cert = os.getenv('VPN_CRT', '/src/certs/server.crt')
    key = os.getenv('VPN_KEY', '/src/certs/server.key')
    vpn_pass = os.getenv('VPN_PASS', 'cyberclinicdev')

    bindsocket = socket.socket()
    bindsocket.bind(('0.0.0.0', vpn_port))
    bindsocket.listen(5)
    atexit.register(bindsocket.close)

    start_auth_tunnel(hostname, vpn_port, cert, key, bindsocket)

# Done by Austin Finch and Morales-Marroquin
