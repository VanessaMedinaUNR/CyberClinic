#Cyber Clinic Standalone Application - Main entry point
#CS 425 Team 13 - Fall 2025
import sys
import os
import time
import auth
from dotenv import load_dotenv
from storage import StorageHandler
import platform
import hashlib
from PyQt6.QtWidgets import QApplication


def compute_hash(filepath: str):
    hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            data = f.read()
            if not data:
                break
            hash.update(data)
    return hash.hexdigest()


if __name__ == '__main__':
    load_dotenv()

    file = os.path.abspath(__file__)
    apphash = compute_hash(file)

    app_storage = StorageHandler()
    server_host = os.getenv('VPN_HOST', '127.0.0.1')
    server_port = os.getenv('VPN_PORT', 6666)

    user = os.environ.get('CYBERCLINIC_USER')
    if user:
        print("passwd")
    else:
        app = QApplication(sys.argv) 
        vpn_crt = app_storage.fetch(os.path.join('config', 'server.crt'))
        login = auth.Auth_Form(app, apphash, server_host, server_port, vpn_crt)
        login.show()
        app.exec()
