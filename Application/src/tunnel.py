#Cyber Clinic Standalone Application - Secure Tunnel Handler
#
#    Copyright (C) 2026  Austin Finch
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    See <https://www.gnu.org/licenses/> for full license terms.

import logging
import socket
import ssl
import os

logger = logging.getLogger(__name__)

class TunnelHandler:
    def __init__(self, host: str, port: int, crt: str=None, key: str=None, ca: str=None):
        self.crt = crt
        self.host = host
        self.port = port
        self.key = key
        self.ca = ca
        self.conn: ssl.SSLSocket | None = None
        if crt:
            self.reconnect_tunnel()
    
    def start_tunnel(self, reconnect=0):
        logger.debug(self.crt)
        if (self.key is None or self.ca is None) and not self.crt is None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(self.crt)
            logger.debug(f"Connecting to {self.host}:{self.port} with: {self.crt}")
        elif self.key and self.ca and self.crt:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT, cafile=self.ca)
            context.load_cert_chain(certfile=self.crt, keyfile=self.key)
            context.load_verify_locations(self.ca)
            logger.debug(f"Connecting to {self.host}:{self.port} with: {self.ca}, {self.crt}, {self.key}")
            logger.debug(context.get_ca_certs())
        else:
            raise ValueError("Insufficient information to establish tunnel. Please provide either a certificate or a certificate, key, and CA.")

        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
            self.conn.send(b'CLOSE')
        except Exception as e:
            logger.warning(f"Error sending close signal: {e}")


    def reconnect_tunnel(self):
        reconnect = self.start_tunnel()
        while reconnect > 0:
            if reconnect == 6:
                raise TimeoutError("Failed to establish tunnel after multiple attempts.")
            reconnect = self.start_tunnel(reconnect)