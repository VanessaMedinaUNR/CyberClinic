#Cyber Clinic Standalone Application - Secure Tunnel Handler
#CS 426 Team 13 - Spring 2026

import logging
import socket
import ssl
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TunnelHandler:
    def __init__(self, crt: str, host: str, port: int):
        self.crt = crt if crt else None
        self.host = host
        self.port = port
        self.conn: ssl.SSLSocket | None = None
        if crt:
            self.reconnect_tunnel()
    
    def start_tunnel(self, reconnect=0):
        logger.debug(self.crt)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(self.crt, os.path.dirname(self.crt))

        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logger.debug(f"Connecting to {self.host}:{self.port} with: {self.crt}")
        logger.info(f"Connecting to {self.host}")
        try:
            raw_socket.connect((self.host, self.port))
            conn = context.wrap_socket(raw_socket, server_hostname=self.host)
            self.conn = conn
        except TimeoutError as e:
            reconnect += 1
        except Exception as e:
            logger.error(e)
            reconnect = 6
        finally:
            if reconnect == 6:
                logger.error("Failed to establish tunnel after multiple attempts.")
                raise TimeoutError("Failed to establish tunnel after multiple attempts.")
        return reconnect
        
    def close_tunnel(self):
        try:
            self.conn.shutdown(socket.SHUT_RDWR)
        except OSError as e:
            logger.error(f"Error during shutdown: {e}")
        self.conn.close()


    def reconnect_tunnel(self):
        reconnect = self.start_tunnel()
        while reconnect > 0:
            if reconnect == 6:
                raise TimeoutError("Failed to establish tunnel after multiple attempts.")
            reconnect = self.start_tunnel(reconnect)