#Cyber Clinic Standalone Application - Main entry point
#CS 425 Team 13 - Fall 2025
from PyQt6.QtWidgets import QApplication
from storage import StorageHandler
from tunnel import TunnelHandler
from dotenv import load_dotenv
import hashlib
import keyring
import auth
import sys
import os


def compute_hash(filepath: str):
    hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            data = f.read()
            if not data:
                break
            hash.update(data)
    return hash.hexdigest()


def authenticate(app_hash, app_storage: StorageHandler, server_host, auth_port, authed_port, pre_authed=False):
    try:
        env = app_storage.fetch(os.path.join('config', '.env'))
        load_dotenv(env)
        subnet_name = os.getenv('SUBNET_NAME', None)
        if subnet_name is not None:
            auth_crt = app_storage.fetch(os.path.join('config', 'auth.crt'))
            auth_tunnel = TunnelHandler(auth_crt, server_host, auth_port)
            encrypted_id = keyring.get_password('CyberClinic', subnet_name)
            
            data = f'PRE_AUTHED|{app_hash}|{subnet_name}|{encrypted_id}'
            auth_tunnel.conn.send(data.encode('utf-8'))

            response = auth_tunnel.conn.recv().decode().split('|')
            success = response.pop(0).rstrip()
            if success == 'AUTH_SUCCESS':
                print('Authentication Success!')
                authed_crt = app_storage.fetch(os.path.join('config', 'bundle.crt'))
                authed_tunnel = TunnelHandler(authed_crt, server_host, authed_port)
                return authed_tunnel
    except Exception as e:
        raise e


if __name__ == '__main__':
    load_dotenv()

    file = os.path.abspath(__file__)
    APP_HASH = compute_hash(file)

    app_storage = StorageHandler()
    server_host = os.getenv('AUTH_HOST', '127.0.0.1')
    auth_port = os.getenv('AUTH_PORT', 6666)
    authed_port = os.getenv('AUTHED_PORT', 9999)

    try:
        authed_tunnel = authenticate(APP_HASH, app_storage, server_host, auth_port, authed_port)
        authed_tunnel.conn.send(('test').encode())
        authed_tunnel.close_tunnel()
    except Exception:
        app = QApplication(sys.argv) 
        auth_crt = app_storage.fetch(os.path.join('config', 'auth.crt'))
        login = auth.Auth_Form(app, APP_HASH, server_host, auth_port, auth_crt)
        login.show()
        app.exec()
        