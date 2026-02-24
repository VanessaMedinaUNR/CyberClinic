#Cyber Clinic Standalone Application - Main entry point
#CS 426 Team 13 - Spring 2026

import ctypes
import subprocess
from subprocess import CompletedProcess
from apscheduler.schedulers.blocking import BlockingScheduler
import scan_handler as scanner
from PyQt6.QtWidgets import QApplication
from storage import StorageHandler
from tunnel import TunnelHandler
from dotenv import load_dotenv
import hashlib
import logging
import keyring
import auth
import sys
import os
from PyQt6.QtWidgets import (
    QApplication,
    QLabel,
    QDialog,
    QFormLayout,
    QPushButton
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def is_admin():
    try:
        return os.getuid() == 0  # Unix: check if root
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
class Alert(QDialog):
    def __init__(self, app, message):
        super().__init__()
        self.app = app

        layout = QFormLayout()

        self.setWindowTitle("CyberClinic - Alert")
        self.l = QLabel(message)
        self.l.setMargin(10)
        layout.addWidget(self.l)

        self.b = QPushButton("Ok")
        self.b.clicked.connect(self.close)
        layout.addWidget(self.b)

        self.setLayout(layout)
        self.show()


def compute_hash(filepath: str):
    hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            data = f.read()
            if not data:
                break
            hash.update(data)
    return hash.hexdigest()


def authenticate(app_hash, app_storage: StorageHandler, server_host, auth_port, authed_port):
    try:
        env = app_storage.fetch_ext(os.path.join('config', '.env'))
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
                logger.info('Authentication Success!')
                authed_crt = app_storage.fetch_ext(os.path.join('config', 'bundle.crt'))
                authed_tunnel = TunnelHandler(authed_crt, server_host, authed_port)
                return authed_tunnel, subnet_name
            else:
                raise ConnectionError
    except Exception as e:
        logger.error(e)
        raise e


def auto_run(app, app_hash, app_storage, server_host, auth_port, authed_port):
    check_tools(app)
    authed_tunnel, subnet_name = authenticate(app_hash, app_storage, server_host, auth_port, authed_port)
    pending_scans = scanner.fetch_scans(authed_tunnel, subnet_name)
    authed_tunnel.close_tunnel()
    
    results = scanner.execute_scans(pending_scans, app_storage)
    logger.debug(results)



def check_tools(app: QApplication):
    tools = scanner.check_tools()
    if tools['nmap'] == False:
        alert = Alert(app, "Please install nmap. The installer will start shortly.")
        alert.show()
        app.exec()
        match sys.platform:
            case 'win32':
                nmap_installer = app_storage.fetch(os.path.join('tools', 'nmap-7.98-setup.exe'))
            case 'linux':
                nmap_installer = app_storage.fetch(os.path.join('tools', 'nmap-7.98-1.x86_64.rpm'))
            case 'darwin':
                nmap_installer = app_storage.fetch(os.path.join('tools', 'nmap-7.98.dmg'))
        result: CompletedProcess = subprocess.run({nmap_installer})
        if result.returncode == 0:
            alert = Alert(app, "Installation Successful! Please re-run the app if it doesn not run automatically")
            alert.show()
            app.exec()
            return 1
        else:
            alert = Alert(app, "Installation Failed! Please try again.")
            alert.show()
            app.exec()
            return -1
    else:
        return 0



if __name__ == '__main__':
    app = QApplication(sys.argv)
    if not is_admin():
        alert = Alert(app, "Please re-run with administrative or root privileges")
        alert.show()
        app.exec()
        sys.exit()

    file = os.path.abspath(sys.executable)
    APP_HASH = compute_hash(file)

    app_storage = StorageHandler()
    server_host = '127.0.0.1'
    auth_port = 6666
    authed_port = 9999
    
    refresh = check_tools(app)
    if refresh != 0:
        if not "python" in file:
            subprocess.Popen(file, start_new_session=True)
        sys.exit()

    try:
        auto_run(app, APP_HASH, app_storage, server_host, auth_port, authed_port)
    except Exception as e:
        logger.error(e)
        auth_crt = app_storage.fetch(os.path.join('config', 'auth.crt'))
        login = auth.Auth_Form(app, APP_HASH, server_host, auth_port, auth_crt)
        login.show()
        app.exec()
        try:
            auto_run(app, APP_HASH, app_storage, server_host, auth_port, authed_port)
        except Exception:
            alert = Alert(app, "We encountered an error. Please re-launch the app.")
            alert.show()
            app.exec()
            sys.exit()
    finally:
        sched = BlockingScheduler()

        @sched.scheduled_job('interval', hours=1)
        def timed_job():
            auto_run(app, APP_HASH, app_storage, server_host, auth_port, authed_port)