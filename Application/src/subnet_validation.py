import os
import sys
import time
import socket
import keyring
import platform
import subprocess
from storage import StorageHandler
from tunnel import TunnelHandler
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from PyQt6.QtCore import pyqtSignal, QObject, QVariant
from PyQt6.QtWidgets import (
    QApplication,
    QLabel,
    QDialog,
    QFormLayout,
    QPushButton,
    QComboBox
)

class Subnet_Form(QDialog):
    def __init__(self, auth, subnet_list, auth_tunnel: TunnelHandler, passwd: str):
        super().__init__(auth)
        self.app: QApplication = auth.app
        self.passwd = passwd
        self.apphash = auth.apphash
        self.auth_tunnel = auth_tunnel

        self.setWindowTitle("CyberClinic Subnet Validation")

        layout = QFormLayout()

        self.l = QLabel("Please select this subnet from the list.")
        self.l.setMargin(10)

        self.h = QComboBox()
        self.h.addItems(subnet_list)

        self.s = QPushButton("Submit")
        self.s.clicked.connect(self.verify_host)

        self.b = QPushButton("Back")
        self.b.clicked.connect(self.go_back)

        widgets = [
            self.l,
            self.h,
            self.s,
            self.b
        ]

        for w in widgets:
            layout.addWidget(w)

        self.setLayout(layout)

    def verify_host(self):
        host_name = self.h.currentText()
        print(f'Hostname: {host_name}')
        send = f'{host_name}'
        try:
            self.auth_tunnel.conn.send(send.encode())
            data = self.auth_tunnel.conn.recv(1024)
            response = data.decode().strip().split('|')
            print(response)
            success = response.pop(0)
            match success:
                case 'SUBNET_INVALID':
                    return
                case 'SUBNET_VALID':
                    self.l.setText("Subnet verified! Finishing up...")
                    encrypted_id = response.pop(0)
                    print(encrypted_id)
                    self.app.processEvents()
                    self.keygen = Generate_Key(self, host_name, encrypted_id)
                    self.keygen.key_generated.connect(self.cleanup)  # Connect signal to slot
                    self.keygen.start()
                case _:
                    self.go_back()
        except Exception as e:
            print(f'{e}')
        
    def cleanup(self, results):
        if not results['success']:
            self.l.setText("Failed! Please try again")
            self.app.processEvents()
            time.sleep(1)
            self.go_back()
        self.auth_tunnel.close_tunnel()
        self.app.exit()

    def go_back(self):
        self.auth_tunnel.close_tunnel()
        self.parent().show()
        self.done(0)

    def closeEvent(self, event):
        self.auth_tunnel.close_tunnel()
        self.app.exit()

class Generate_Key(QObject):
    key_generated = pyqtSignal(QVariant, arguments=['result'])  # Define a signal to send data back
    def __init__(self, form: Subnet_Form, subnet_name, client_id):
        super().__init__()
        self.form = form
        self.subnet_name = subnet_name
        self.client_id = client_id

    def start(self):
        try:
            storage = StorageHandler()
            
            key: bytes = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            ).private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(self.form.passwd.encode()))
            storage.save(os.path.join('config', 'client.key'), key.decode('utf-8'))
            self.form.auth_tunnel.conn.send(key)
            
            crt = self.form.auth_tunnel.conn.recv(4096)
            print(crt.decode('utf-8'))
            storage.save(os.path.join('config', 'bundle.crt'), crt.decode('utf-8'))
            storage.save(os.path.join('config', '.env'), f'SUBNET_NAME={self.subnet_name}')
            keyring.set_password('CyberClinic', self.subnet_name, self.client_id)
            
            msg = 'NOT_SAVED'
            success = False
            try:
                storage.fetch(os.path.join('config', 'bundle.crt'))
                success = True
                success &= not (keyring.get_password('CyberClinic', self.subnet_name) == None)
            except Exception as e:
                print(f'Failed to save - {e}')
            finally:
                if success:
                    msg = 'SAVED'
                self.form.auth_tunnel.conn.send(msg.encode())
                self.key_generated.emit({"success": success}) # Emit the result when done
        except Exception as e:
            print(f'Failed to save - {e}')
            self.key_generated.emit({"success": False}) # Emit the result when done