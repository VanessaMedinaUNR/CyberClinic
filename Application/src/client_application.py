#Cyber Clinic Standalone Application - Main entry point
#CS 426 Team 13 - Spring 2026
from apscheduler.schedulers.blocking import BlockingScheduler
from storage_handler import StorageHandler
from subprocess import CompletedProcess
from tunnel import TunnelHandler
import scan_handler as scanner
from dotenv import load_dotenv
import subprocess
import hashlib
import logging
import keyring
import auth
import sys
import os
from PyQt6.QtWidgets import QApplication
from PyQt6.QtWidgets import (
    QApplication,
    QLabel,
    QDialog,
    QFormLayout,
    QPushButton
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
scans_running = False

def is_admin():
    try:
        return os.getuid() == 0  # Unix: check if root
    except AttributeError:
        import ctypes
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


def authenticate(app_hash, subnet_name, app_storage: StorageHandler, server_host, authed_port, auth_tunnel: TunnelHandler = None):
    if not auth_tunnel is None:
        encrypted_id = keyring.get_password('CyberClinic', subnet_name)
        data = f'AUTH|PRE_AUTHED|{app_hash}|{subnet_name}|{encrypted_id}'
        auth_tunnel.conn.send(data.encode('utf-8'))

        response = auth_tunnel.conn.recv().decode().split('|')
        logger.debug(response)
        success = response.pop(0).rstrip()
        if success == 'AUTH_SUCCESS':
            logger.info('Authentication Success!')
            return auth_tunnel
        else:
            auth_tunnel.close_tunnel()
            raise ConnectionError("Re-authentication failed, launching login form.")
    else:
        try:
            authed_crt = app_storage.fetch_ext(os.path.join('config', 'client.crt'))
            key = app_storage.fetch_ext(os.path.join('config', 'client.key'))
            ca = app_storage.fetch_ext(os.path.join('config', 'ca.crt'))
            authed_tunnel = TunnelHandler(server_host, authed_port, crt=authed_crt, key=key, ca=ca)
            authed_tunnel.conn.send(b'CHECK')
            data = authed_tunnel.conn.recv(1024)
            if data.decode() != 'TRUE':
                raise ConnectionError("Failed to connect to authenticated tunnel.")
            authed_tunnel.conn.send(b'CLOSE')
            return authed_tunnel
        except Exception as e:
            logger.error(f'Failed to connect to authenticated tunnel: {e}')
            raise ConnectionError("Pre-authentication failed.")


def auto_run(app: QApplication, app_hash, app_storage: StorageHandler, server_host, subnet_name, authed_port, auth_port: int = None):
    check_tools(app)
    try:
        authed_tunnel = authenticate(app_hash, subnet_name, app_storage, server_host, authed_port)
        pending_scans = scanner.fetch_scans(authed_tunnel, subnet_name)
        logger.debug(pending_scans)
        authed_tunnel.close_tunnel()

        for report_id, scans in pending_scans.items():
            pending_scans[report_id] = scanner.execute_scans(scans, app_storage)
            logger.debug(pending_scans)

        for report_id, scans in pending_scans.items():
            logger.debug(scans)
            scanner.send_scans(authed_tunnel, scans, app_storage)
    except ConnectionError as e:
        crt = app_storage.fetch(os.path.join('config', 'auth.crt'))
        auth_tunnel = TunnelHandler(server_host, auth_port, crt=crt)
        authed_tunnel = authenticate(app_hash, subnet_name, app_storage, server_host, authed_port, auth_tunnel=auth_tunnel)
        pending_scans = scanner.fetch_scans(authed_tunnel, subnet_name)
        logger.debug(pending_scans)
        authed_tunnel.close_tunnel()

        for report_id, scans in pending_scans.items():
            pending_scans[report_id] = scanner.execute_scans(scans, app_storage)
        logger.debug(pending_scans)
        
        for report_id, scans in pending_scans.items():
            logger.debug(scans)
            scanner.send_scans(authed_tunnel, scans, app_storage)
    except Exception as e:
        logger.error(f'Error during auto-run: {e}')
        alert = Alert(app, "An error occurred during the auto-run process. Please try again later. If the problem persists, please contact our support team.")
        alert.show()
        app.exec()



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
    server_host = 'cyberclinic.unr.edu'
    auth_port = 6666
    authed_port = 9999
    
    refresh = check_tools(app)
    if refresh != 0:
        if not "python" in file:
            subprocess.Popen(file, start_new_session=True)
        sys.exit()
    try:
        
        try:
            env = app_storage.fetch_ext(os.path.join('config', '.env'))
            load_dotenv(env)
        except FileNotFoundError as e:
            raise ConnectionError("No authentication information found, launching login form.")
        
        try:
            subnet_name = os.getenv('SUBNET_NAME', None)
            authed_tunnel = authenticate(
                app_hash=APP_HASH,
                subnet_name=subnet_name,
                app_storage=app_storage,
                server_host=server_host,
                auth_tunnel=None,
                authed_port=authed_port
            )
        except ConnectionError as e:
            logger.error(e)
            logger.info("Trying Re-authentication...")
            
            auth_crt = app_storage.fetch(os.path.join('config', 'auth.crt'))
            auth_tunnel = TunnelHandler(server_host, auth_port, crt=auth_crt)
            auth_tunnel.conn.send(b'CHECK')
            data = auth_tunnel.conn.recv(1024)
            if data.decode() != 'TRUE':
                raise TimeoutError("Failed to connect to authentication server.")
            
            authed_tunnel = authenticate(app_hash=APP_HASH, subnet_name=subnet_name, app_storage=app_storage, server_host=server_host, auth_tunnel=auth_tunnel, authed_port=authed_port)
        finally:
            if 'auth_tunnel' in locals() and auth_tunnel is not None:
                auth_tunnel.close_tunnel()
    except ConnectionError as e:
        logger.error(e)
        try:
            auth_crt = app_storage.fetch(os.path.join('config', 'auth.crt'))
            logger.info(auth_crt)
            login = auth.Auth_Form(
                app=app,
                apphash=APP_HASH,
                host=server_host,
                port=auth_port,
                cert=auth_crt,
                authed_port=authed_port
            )
            login.show()
            app.exec()
        except Exception as e:
            logger.error(f'Unhandled error: {e}')
            alert = Alert(app, "An error occurred while connecting to the authentication server. Please try again later. If the problem persists, please contact our support team.")
            alert.show()
            app.exec()
            sys.exit()
        finally:
            authed_tunnel = authenticate(app_hash=APP_HASH, subnet_name=subnet_name, app_storage=app_storage, server_host=server_host, authed_port=authed_port)
    except TimeoutError as e:
        logger.error(f'Unhandled error: {e}')
        alert = Alert(app, "An error occurred while connecting to the authentication server. Please try again later. If the problem persists, please contact our support team.")
        alert.show()
        app.exec()
        sys.exit()
    except Exception as e:
            logger.error(e)
            alert = Alert(app, "We encountered an unknown error. Please re-launch the app.")
            alert.show()
            app.exec()
            sys.exit()
    finally:
        try:
            env = app_storage.fetch_ext(os.path.join('config', '.env'))
            load_dotenv(env)
            subnet_name = os.getenv('SUBNET_NAME', None)
            auto_run(app, APP_HASH, app_storage, server_host, subnet_name, authed_port, auth_port=auth_port)

            sched = BlockingScheduler()
            
            @sched.scheduled_job('interval', hours=1)
            def run_periodically():
                global scans_running
                if not scans_running:
                    logger.info("Running scheduled job to check for pending scans...")
                    scans_running = True
                    try:
                        auto_run(app, APP_HASH, app_storage, server_host, subnet_name, authed_port, auth_port=auth_port)
                    except Exception as e:
                        logger.error(f'Error during scheduled job: {e}')
                    finally:
                        logger.info("All pending scans have finished executing.")
                        scans_running = False
                else:
                    logger.info("Previous scheduled job is still running, skipping this run.")
            
            sched.start()
        except Exception as e:
            logger.error(e)
            alert = Alert(app, "Failed to connect to server. Please try again later. If the problem persists, please contact our support team.")
            alert.show()
            app.exec()
            sys.exit()