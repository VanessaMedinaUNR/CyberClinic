#Cyber Clinic Standalone Application - VPN Handler
#CS 425 Team 13 - Fall 2025

import socket
import ssl

def vpn_client(crt, host, port):
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(crt)

    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_socket.connect((host, port))
    conn = context.wrap_socket(raw_socket, server_hostname=host)

    return conn