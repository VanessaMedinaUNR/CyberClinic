from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime, timedelta, timezone
from cryptography.x509.oid import NameOID
from app.database import get_db
from cryptography import x509
from threading import Thread
import ipaddress
import base64
import logging
import socket
import atexit
import ssl

#setup logging
logger = logging.getLogger(__name__)

class StandaloneHandler:
    def __init__(self, auth_port: int, auth_cert, auth_key, auth_pass: str, authed_port: int, authed_cert, authed_key, authed_pass: str, poll_interval=30):
        self.auth_port = auth_port
        self.auth_cert = auth_cert
        self.auth_key = auth_key
        self.auth_pass = auth_pass

        self.authed_port = authed_port
        self.authed_cert = authed_cert
        self.authed_key = authed_key
        self.authed_pass = authed_pass

        self.poll_interval = poll_interval
        self.running = False
        self.worker_thread = None
    
    def start(self):
        #start the background worker
        if not self.running:
            self.running = True
            self.worker_thread = Thread(target=self.start_handler, daemon=True)
            self.worker_thread.start()
            logger.info("Standalone handler started")
    
    def stop(self):
        #stop the background worker
        self.running = False
        if self.worker_thread:
            self.worker_thread.join()
        logger.info("Standalone handler stopped")

    def start_auth_tunnel(self, bindsocket: socket.socket, authed_socket: socket.socket):
        logger.info(f'loading {self.auth_cert}')
        logger.info(f'loading {self.auth_key}')

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=self.auth_cert, keyfile=self.auth_key, password=self.auth_pass)
        logger.info(f"Auth tunnel listening on {bindsocket.getsockname()[0]}:{bindsocket.getsockname()[1]}")
        while True:
            newsocket, fromaddr = bindsocket.accept()
            logger.info(f"Connection from {fromaddr}")
            try:
                conn = context.wrap_socket(newsocket, server_side=True)
                try:
                    self.parse_command(conn, fromaddr, authed_socket=authed_socket)
                except Exception as e:
                    logger.warning(f"Auth Tunnel Error: {e}")
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError as e:
                    logger.warning(f"Error during shutdown: {e}")
            except Exception as e:
                logger.error(f"Auth tunnel error: {e}")
                try:
                    conn.send(b'AUTH_FAIL')
                except OSError as e:
                    logger.warning(f"Error sending AUTH_FAIL: {e}")
                logger.warning(f"Failed Authentication attempt from {fromaddr}")
            finally:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError as e:
                    logger.warning(f"Error during shutdown: {e}")
                conn.close()
                logger.info(f"Connection from {fromaddr} closed")


    def parse_command(self, conn: ssl.SSLSocket, client_id=None, authed_socket=None):
        fromaddr = conn.getpeername()
        data = conn.recv(1024).decode()
        response = data.split("|")
        if response:
            command = response.pop(0)
            match command:
                case "AUTH":
                    result, identity = self.authenticate_standalone_client(conn, fromaddr, response)
                    if result == True:
                        conn.send(b'AUTH_SUCCESS')
                        Thread(target=self.start_authed_tunnel, args=(authed_socket, identity)).start()
                    else:
                        conn.send(b'AUTH_FAIL')
                        logger.warning(f"Failed Authentication attempt from {fromaddr}")
                        raise ConnectionError(f"Failed Authentication attempt from {fromaddr}")
                case "CHECK":
                    conn.send(b'TRUE')
                    self.parse_command(conn, client_id, authed_socket)
                case "CLOSE":
                    logger.info(f"Connection from {fromaddr} closed by client")
                    raise ConnectionError(f"Connection from {fromaddr} closed by client")
                case "FETCH_SCANS":
                    if client_id is None:
                        logger.warning(f"Unauthorized FETCH_SCANS attempt from {fromaddr}")
                        conn.send(b'UNAUTHORIZED')
                        raise ConnectionError(f"Unauthorized FETCH_SCANS attempt from {fromaddr}")
                    subnet_name = response.pop(0)
                    self.fetch_scans(conn, subnet_name, client_id)
                case "SEND_RESULTS":
                    if client_id is None:
                        logger.warning(f"Unauthorized SEND_RESULTS attempt from {fromaddr}")
                        conn.send(b'UNAUTHORIZED')
                        raise ConnectionError(f"Unauthorized SEND_RESULTS attempt from {fromaddr}")
                    results = response.pop(0)
                case _:
                    logger.warning(f"Invalid command from {fromaddr}: {command}")
                    conn.send(b'INVALID_COMMAND')
                    raise ValueError(f"Invalid command from {fromaddr}: {command}")
    

    def authenticate_standalone_client(self, conn: ssl.SSLSocket, fromaddr, auth_string: list[str]):
        success, identity = self.parse_auth_request(
            conn=conn,
            fromaddr=fromaddr,
            auth_string=auth_string
        )
        
        if success:
            conn.send(b'AUTH_SUCCESS')
            logger.debug(f"Standalone Client Authenticated at IP: {fromaddr[0]}")
            return True, identity
        else:
            conn.send(b'AUTH_FAIL')
            logger.warning(f"Failed Authentication attempt from {fromaddr}")
            raise ValueError(f"Failed Authentication attempt from {fromaddr}")


    def parse_auth_request(self, conn: ssl.SSLSocket, fromaddr, auth_string: str) -> tuple[bool, tuple[str, bytes]]:
        try:
            db = get_db()
    
            logger.debug(f"Received authentication: {auth_string[:2]}...")
            
            """
            Parse client authentication format: "apphash:email:password" or "apphash:subnet_name"
            Returns: (success, user_data, password, message)
            """
            parts = auth_string
            #parse format: "hash:email:password"
            if len(parts) == 3:
                app_hash, email, password = parts
                success, user_data, passwd, message = self.authenticate_client_credentials(app_hash, email, password)
                if success:
                    #send success response
                    response = f"AUTH_SUCCESS"
                    conn.sendall(response.encode())
                    client_id = user_data['client_id']
                    logger.info(f"Client authenticated: {client_id}")

                    valid, subnet = self.validate_subnet(conn, client_id)
                    if not valid:
                        raise ValueError('Invalid Subnet')
                    else:
                        data = conn.recv(2048)
                        private_key = serialization.load_pem_private_key(data, password=passwd.encode())
                        client = db.execute_single(
                            """SELECT * from client WHERE client_id = %s""",
                            (client_id,)
                        )
                        if client:
                            success, public_key = self.update_subnet_key(
                                subnet=subnet,
                                fromaddr=fromaddr,
                                client=client,
                                private_key=private_key,
                            )
                            if success:
                                with open(self.authed_cert, "rb") as f:
                                    ca = f.read()
                                    bundle = public_key + ca
                                    conn.sendall(bundle)
                                    msg = conn.recv(1024).decode()
                                    if not msg == 'SAVED':
                                        self.clear_subnet_key(subnet, client)
                                        return (False, ())
                                    return (True, (client_id, public_key.decode()))
                                return (False, ())
                            else:
                                return (False, ())
                        else:
                            return (False, ())
                else:
                    #send failure response
                    conn.sendall(f"AUTH_FAILED|{message}".encode())
                    logger.warning(f"Tunnel authentication failed from {fromaddr}: {message}")
                    return (False, ())
            #parse format: pre_authed:hash:subnet_name:encrypted_id
            elif len(parts) == 4:
                pre_authed, app_hash, subnet_name, encrypted_id = parts
                if pre_authed == 'PRE_AUTHED':
                    return self.authenticate_subnet(
                        app_hash=app_hash,
                        subnet_name=subnet_name,
                        encrypted_id=base64.b64decode(encrypted_id)
                    )
            conn.sendall(f"AUTH_FAILED|Invalid authentication format".encode())
            logger.warning(f"Tunnel authentication failed from {fromaddr}")
            return (False, ())
        except Exception as e:
            try:
                conn.sendall(b"AUTH_FAILED|Server error")
            except:
                pass
            finally:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                    conn.close()
                    raise e
                except OSError as e:
                    logger.warning(f"Error during shutdown: {e}")


    def authenticate_subnet(self, app_hash, subnet_name: str, encrypted_id: bytes):

        with open(self.authed_key, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), self.authed_pass.encode())
        
        try:
            client_id = private_key.decrypt(
                encrypted_id,
                padding=padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=subnet_name.encode()
                )
            ).decode()
            
            try:
                db = get_db()

                subnet = db.execute_single(
                    """SELECT public_key from network_keys WHERE client_id = %s AND subnet_name = %s""",
                    (client_id, subnet_name,)
                )
                if not subnet == None:
                    public_key: str = base64.b64decode(subnet['public_key']).decode()
                    logger.debug(f'{client_id}: {subnet_name} Authenticated')
                    return (True, (client_id, public_key.rstrip()))
                return (False, ())
            except Exception as e:
                logger.error('Database Error')
                raise e
        except Exception as e:
            logger.warning('Invalid encrypted id provided')
            raise e


    def authenticate_client_credentials(self, apphash, email: str, password):
        try:
            #verify user credentials using our auth system
            db = get_db()
            
            #check credentials using same method as our login endpoint
            user_data = db.execute_single(
                """SELECT user_id, email, client_id, client_admin FROM users NATURAL JOIN client_users WHERE users.email = %s AND password_hash = crypt(%s, password_hash)""",
                (email.strip(), password)
            )
            
            if not user_data:
                return False, None, None, "Invalid credentials"
            
            if not user_data['client_admin']:
                return False, None, None, "This action can only be completed by an Administrator"
            
            logger.info(f"VPN authentication successful for {email}")
            return True, user_data, password, "Authentication successful"
            
        except Exception as e:
            logger.error(f"VPN authentication error: {e}")
            return False, None, None, f"Authentication failed: {e}"


    def update_subnet_key(self, subnet, fromaddr, client, private_key):
        try:
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, client['country']),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, client['province']),
                x509.NameAttribute(NameOID.LOCALITY_NAME, client['city']),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, client['client_name']),
                x509.NameAttribute(NameOID.COMMON_NAME, subnet),
            ])
            san_names = [
                x509.DNSName(str(fromaddr)),
            ]
            csr = x509.CertificateSigningRequestBuilder().subject_name(subject).add_extension(
                x509.SubjectAlternativeName(san_names),
                critical=False,
            ).sign(private_key, hashes.SHA256())


            public_key = None
            with open(self.authed_cert, "rb") as cert:
                ca_cert = x509.load_pem_x509_certificate(cert.read())
                with open(self.authed_key, "rb") as key:
                    ca_key = serialization.load_pem_private_key(key.read(), password=self.authed_pass.encode())
                    public_key = x509.CertificateBuilder() \
                        .subject_name(csr.subject) \
                            .issuer_name(ca_cert.subject) \
                                .public_key(csr.public_key()) \
                                    .serial_number(x509.random_serial_number()) \
                                        .not_valid_before(datetime.now(tz=timezone.utc)) \
                                            .not_valid_after(datetime.now(tz=timezone.utc) + timedelta(days=365)) \
                                                .sign(ca_key, hashes.SHA256()) \
                                                    .public_bytes(serialization.Encoding.PEM)

                    if public_key:
                        db = get_db()
                        success = db.execute_single(
                            """
                                UPDATE network_keys SET public_key = %s
                                WHERE subnet_name = %s AND client_id = %s
                                RETURNING public_key 
                            """,
                            (base64.b64encode(public_key).decode(), subnet, client['client_id'],)
                        )
                        if success:
                            success = success = db.execute_single(
                                """
                                    UPDATE network SET verified = %s, verification_date = CURRENT_TIMESTAMP
                                    WHERE subnet_name = %s AND client_id = %s
                                    RETURNING verified 
                                """,
                                (True, subnet, client['client_id'],)
                            )
                            if success:
                                return True, public_key
                    self.clear_subnet_key(subnet, client)
                    logger.error(f"Failed to save {subnet} public key")
                    return False, None
        except Exception as e:
            self.clear_subnet_key(subnet, client)
            logger.error(f"Failed to save {subnet} public key - {e}")
            return False, None


    def clear_subnet_key(self, subnet, client):
        try:
            db = get_db()
            db.execute_command(
                """
                    UPDATE network_keys SET public_key = %s
                    WHERE subnet_name = %s AND client_id = %s
                """,
                ('', subnet, client['client_id'])
            )
            db.execute_command(
                """
                    UPDATE network SET verified = %s, verification_date = %s
                    WHERE subnet_name = %s AND client_id = %s
                """,
                (False, None, subnet, client['client_id'])
            )
        except Exception as e:
            logger.error(f'Failed to clear {subnet} private key')


    def validate_subnet(self, conn: ssl.SSLSocket, client_id: str):
        try:
            db = get_db()
            subnet_list = db.execute_query(
                """SELECT subnet_name FROM network WHERE client_id = %s AND public_facing = FALSE""",
                (client_id,)
            )
            if not subnet_list:
                response = f"SUBNET_INVALID"
                conn.sendall(response.encode())
                return False, None
            else:
                logger.debug(f'Client Subnet List: {subnet_list}')
                response = f"SUBNET_LIST"
                for subnet in subnet_list:
                    name = subnet['subnet_name']
                    response += f'|{name}'
                conn.sendall(response.encode())

                data = conn.recv(1024)
                subnet: str = data.decode().strip()
                response = f"SUBNET_INVALID"
                for check in subnet_list:
                    name = check["subnet_name"]
                    if name == subnet:
                        with open(self.authed_cert, "rb") as f:
                            cert = x509.load_pem_x509_certificate(f.read())
                            public_key = cert.public_key()

                        encrypted_id = public_key.encrypt(client_id.encode(), padding=padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=subnet.encode()
                        ))
                        encoded_id = base64.b64encode(encrypted_id).decode()
                        response = f"SUBNET_VALID|{encoded_id}"
                        break
                conn.sendall(response.encode())
                return True, subnet
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


    def start_authed_tunnel(self, authed_socket: socket.socket, identity: tuple[str, bytes]):
        logger.info(f'loading {self.authed_cert}')
        logger.info(f'loading {self.authed_key}')

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=self.authed_cert, keyfile=self.authed_key, password=self.authed_pass)
        context.load_verify_locations(cadata=identity[1])
        logger.info(f"Authed tunnel listening on {authed_socket.getsockname()[0]}:{authed_socket.getsockname()[1]}")
        while True:
            newsocket, fromaddr = authed_socket.accept()
            logger.info(f"Connection from {fromaddr}")
            try:
                conn = context.wrap_socket(newsocket, server_side=True)
                try:
                    self.parse_command(conn, identity[0])
                except Exception as e:
                    logger.error(f"Authed tunnel error: {e}")
                    try:
                        conn.sendall(b"AUTH_FAILED|Server error")
                    except:
                        pass
                finally:
                    try:
                        conn.shutdown(socket.SHUT_RDWR)
                    except OSError as e:
                        logger.warning(f"Error during shutdown: {e}")
                    conn.close()
                    logger.info(f"Connection from {fromaddr} closed")
            except Exception as e:
                logger.error(f"Authed tunnel error: {e}")


    def fetch_scans(self, conn, subnet_name, client_id):
        try:
            db = get_db()
            pending_scans = db.execute_query(
                """SELECT sj.*, nt.subnet_name, nt.subnet_ip, nt.subnet_netmask, nt.public_facing
                    FROM scan_jobs sj
                    LEFT JOIN network nt ON sj.subnet_name = nt.subnet_name AND sj.client_id = nt.client_id
                    WHERE sj.status = 'pending' AND nt.subnet_name = %s AND nt.client_id = %s
                    ORDER BY sj.created_at ASC
                    """,
                (subnet_name, client_id)
            )
            if pending_scans:
                target_value = ""
                domain = db.execute_single(
                    """SELECT * FROM network NATURAL JOIN network_domains WHERE subnet_name = %s""",
                    (subnet_name,)
                )
                if domain:
                    target_value = domain['domain']

                scan_list = {}
                for scan in pending_scans:
                    if scan['subnet_netmask'] == "255.255.255.255":
                        target_value = scan['subnet_ip']
                    else:
                        subnet = ipaddress.ip_network(scan['subnet_ip'])
                        subnet.netmask = scan['subnet_netmask']
                        target_value = subnet.compressed 
                    
                    scan_list[scan['id']] = {
                        "report_id": scan['report_id'],
                        "target_value": target_value,
                        "scan_type": scan['scan_type']
                    }
                response = f'PENDING_SCANS|{scan_list}'
                conn.send(response.encode())
            else:
                conn.send(b'NONE_PENDING')
        except Exception as e:
            try:
                conn.send(b'SERVER_ERROR')
            except Exception:
                pass
            finally:
                raise e
            

    def start_handler(self):
        #use the database manager for connections
        try:
            db = get_db()
            if db.connect():
                logger.info("Database connection established for VPN server")
            else:
                logger.error("Failed to connect to database")
        except Exception as e:
            logger.error(f"Database connection error: {e}")
        
        auth_socket = socket.socket()
        auth_socket.bind(('0.0.0.0', self.auth_port))
        auth_socket.listen(5)
        atexit.register(auth_socket.close)


        authed_socket = socket.socket()
        authed_socket.bind(('0.0.0.0', self.authed_port))
        authed_socket.listen(5)
        atexit.register(authed_socket.close)


        auth_tunnel = Thread(target=self.start_auth_tunnel, args=(auth_socket, authed_socket))
        auth_tunnel.start()

#global scan worker instance
standalone_handler = None

def start_standalone_handler(auth_port: int, auth_cert, auth_key, auth_pass: str, authed_port: int, authed_cert, authed_key, authed_pass: str):
    #start the global scan worker
    global standalone_handler
    if standalone_handler is None:
        standalone_handler = StandaloneHandler(auth_port, auth_cert, auth_key, auth_pass, authed_port, authed_cert, authed_key, authed_pass)
        standalone_handler.start()
        return standalone_handler
    return standalone_handler

def stop_standalone_handler():
    #stop the global scan worker
    global standalone_handler
    if standalone_handler:
        standalone_handler.stop()
        standalone_handler = None

# Done by Austin Finch and Morales-Marroquin
