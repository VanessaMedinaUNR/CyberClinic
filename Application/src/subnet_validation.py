#Cyber Clinic Standalone Application - Subnet Validation Form
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

import base64

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from storage_handler import StorageHandler
from tunnel import TunnelHandler
import logging
import keyring
import time
import os
from PyQt6.QtCore import pyqtSignal, QObject, QVariant
from PyQt6.QtWidgets import (
    QApplication,
    QLabel,
    QDialog,
    QFormLayout,
    QPushButton,
    QComboBox
)

logger = logging.getLogger(__name__)

class Subnet_Form(QDialog):
    def __init__(self, auth, subnet_list, auth_tunnel: TunnelHandler, authed_tunnel: TunnelHandler, passwd: str):
        super().__init__(auth)
        self.app: QApplication = auth.app
        self.passwd = passwd
        self.apphash = auth.apphash
        self.auth_tunnel = auth_tunnel
        self.authed_tunnel = authed_tunnel

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
        logger.debug(f'Hostname: {host_name}')
        send = f'{host_name}'
        try:
            self.auth_tunnel.conn.send(send.encode())
            data = self.auth_tunnel.conn.recv(1024)
            response = data.decode().strip().split('|')
            logger.debug(response)
            success = response.pop(0)
            match success:
                case 'SUBNET_INVALID':
                    return
                case 'SUBNET_VALID':
                    self.l.setText("Subnet verified! Finishing up...")
                    encrypted_id = response.pop(0)
                    logger.debug(encrypted_id)
                    self.app.processEvents()
                    self.keygen = Generate_Key(self, host_name, encrypted_id)
                    self.check_auth = Check_Auth(self.authed_tunnel)
                    self.check_auth.tunnel_checked.connect(self.cleanup)  # Connect signal to slot
                    self.keygen.key_generated.connect(self.check_auth.start)  # Connect signal to slot
                    self.keygen.start()
                case _:
                    self.go_back()
        except Exception as e:
            logger.error(f'{e}')
        
    def cleanup(self, results):
        if not results['success']:
            self.l.setText("Failed! Please try again")
            self.app.processEvents()
            time.sleep(1)
            self.go_back()
        self.auth_tunnel.close_tunnel()
        self.hide()
        self.app.quit()

    def go_back(self):
        self.auth_tunnel.close_tunnel()
        self.parent().show()
        self.done(0)

    def closeEvent(self, event):
        self.auth_tunnel.close_tunnel()
        self.app.exit()

class Check_Auth(QObject):
    tunnel_checked = pyqtSignal(QVariant, arguments=['result'])  # Define a signal to send data back
    def __init__(self, tunnel: TunnelHandler):
        super().__init__()
        self.tunnel = tunnel
    def start(self):
        try:
            self.tunnel.reconnect_tunnel()
            self.tunnel.conn.send(b'CHECK')
            response = self.tunnel.conn.recv(1024).decode()
            if response == 'TRUE':
                self.tunnel.conn.send(b'CLOSE')
                self.tunnel.close_tunnel()
                self.tunnel_checked.emit({"success": True}) # Emit the result when done
            else:
                self.tunnel.close_tunnel()
                self.tunnel_checked.emit({"success": False}) # Emit the result when done
        except Exception as e:
            logger.error(f'Failed to establish tunnel - {e}')
            self.tunnel_checked.emit({"success": False}) # Emit the result when done

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
            
            key: rsa.RSAPrivateKey = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            storage.save_ext(os.path.join('config', 'client.key'), pem)
            self.form.auth_tunnel.conn.send(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(self.form.passwd.encode())))
            
            data = self.form.auth_tunnel.conn.recv(4096)
            response = data.decode().split('|')
            logger.debug(response)
            crt = base64.b64decode(response[0])
            ca = base64.b64decode(response[1])
            storage.save_ext(os.path.join('config', 'ca.crt'), ca)
            storage.save_ext(os.path.join('config', 'client.crt'), crt)
            storage.save_ext(os.path.join('config', '.env'), f'SUBNET_NAME={self.subnet_name}')
            keyring.set_password('CyberClinic', self.subnet_name, self.client_id)
            
            msg = 'NOT_SAVED'
            success = False
            try:
                crt = storage.fetch_ext(os.path.join('config', 'client.crt'))
                ca = storage.fetch_ext(os.path.join('config', 'ca.crt'))
                key = storage.fetch_ext(os.path.join('config', 'client.key'))
                success = True
                success &= not (keyring.get_password('CyberClinic', self.subnet_name) == None)
            except Exception as e:
                logger.error(f'Failed to save - {e}')
            finally:
                if success:
                    msg = 'SAVED'
                    self.form.authed_tunnel.crt = crt
                    self.form.authed_tunnel.ca = ca
                    self.form.authed_tunnel.key = key
                self.form.auth_tunnel.conn.send(msg.encode())
                self.key_generated.emit({"success": success}) # Emit the result when done
                
        except Exception as e:
            logger.error(f'Failed to save - {e}')
            self.key_generated.emit({"success": False}) # Emit the result when done