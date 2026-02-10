#Cyber Clinic Standalone Application - VPN Handler
#CS 425 Team 13 - Fall 2025

import shutil
import socket
import ssl
import os

class TunnelHandler:
    def __init__(self, crt, host, port):
        self.crt = crt
        self.host = host
        self.port = port
        self.conn = None
        self.reconnect_tunnel()
    
    def start_tunnel(self, reconnect=0):
        print(self.crt)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(self.crt, os.path.dirname(self.crt))

        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"Connecting to {self.host}:{self.port} with: {self.crt}")
        try:
            raw_socket.connect((self.host, self.port))
            conn = context.wrap_socket(raw_socket, server_hostname=self.host)
            self.conn = conn
        except TimeoutError as e:
            reconnect += 1
        except Exception as e:
            reconnect = 6
        finally:
            return reconnect
        
    def close_tunnel(self):
        try:
            self.conn.shutdown(socket.SHUT_RDWR)
        except OSError as e:
            print(f"Error during shutdown: {e}")
        self.conn.close()


    def reconnect_tunnel(self):
        reconnect = self.start_tunnel()
        while reconnect > 0:
            if reconnect == 6:
                raise TimeoutError
            reconnect = self.start_tunnel(reconnect)