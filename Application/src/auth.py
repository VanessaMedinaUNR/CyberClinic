import os
import sys
import time
import platform
import subprocess
from pathlib import Path
from subnet_validation import Subnet_Form
import keyring
from tunnel import TunnelHandler
from PyQt6.QtCore import pyqtSignal, QObject, QVariant
from PyQt6.QtWidgets import (
    QLabel,
    QLineEdit,
    QDialog,
    QFormLayout,
    QPushButton
)


class User_Auth(QObject):
    user_verified = pyqtSignal(QVariant, arguments=['result'])  # Define a signal to send data back
    
    def __init__(self, form, email, passwd):
        super().__init__()
        self.form = form
        self.email = email
        self.passwd = passwd
        self.apphash = form.apphash
        self.vpn_host = form.vpn_host
        self.vpn_port = form.vpn_port
        self.vpn_crt = form.vpn_crt


    def start(self, auth_tunnel):

        print(f"hash: {self.apphash}\n")
        print(f"{self.email}: {self.passwd}")
        send = f'{self.apphash}:{self.email}:{self.passwd}'

        try:
            auth_tunnel.conn.send(send.encode('latin-1'))
            data = auth_tunnel.conn.recv(1024)

            response = data.decode('latin-1').strip().split(':')
            success = response.pop(0)
            match success:
                case "AUTH_FAILED":
                    message = response.pop(0)
                    print(f"Received from server: {success}: {message}")
                    self.form.l.setText(message)
                    self.form.app.processEvents()
                    self.form.p.clear()
                    self.user_verified.emit({"success": False, "auth_tunnel": auth_tunnel}) # Emit the result when done
                case "AUTH_SUCCESS":
                    print(f"Received from server: {success}")

                    self.form.l.setText("User verification success!")
                    self.form.app.processEvents()
                    keyring.set_password("cyberclinic", self.email, self.passwd)
                    self.user_verified.emit({"success": True, "auth_tunnel": auth_tunnel})  
                case _:
                    auth_tunnel.close_tunnel()
                    raise ValueError
        except TimeoutError as e:
            print(f'{e}')
            self.form.l.setText("Connection error, please try again later")
            self.form.app.processEvents()
            time.sleep(5)
            self.user_verified.emit({"success": False, "auth_tunnel": auth_tunnel})
        except Exception as e:
            print(f'{e}')
            self.form.l.setText("User verification failed! If you continue to recieve this error, please contact our support team: ")
            self.form.app.processEvents()
            time.sleep(5)
            self.user_verified.emit({"success": False, "auth_tunnel": auth_tunnel})


class Auth_Form(QDialog):

    def __init__(self, app, apphash, host, port, cert):
        self.app = app
        self.apphash = apphash
        self.vpn_host = host
        self.vpn_port = port
        self.vpn_crt = cert
        super().__init__()

        self.setWindowTitle("CyberClinic Authentication")

        layout = QFormLayout()

        self.l = QLabel("Please enter your CyberClinic Email and Password.")
        self.l.setMargin(10)

        self.e = QLineEdit()
        self.e.setPlaceholderText("Email")
        self.p = QLineEdit()
        self.p.setPlaceholderText("Password")
        self.p.setEchoMode(QLineEdit.EchoMode.Password)

        self.s = QPushButton("Submit")
        self.s.setDefault(1)
        self.s.clicked.connect(self.verify_user)

        layout.addRow(self.l)
        layout.addRow("Email:", self.e)
        layout.addRow("Password", self.p)
        layout.addRow(self.s)

        self.setLayout(layout)


    def parse_user_auth(self, results):
        user_verified = results['success']
        self.auth_tunnel = results['auth_tunnel']
        if not user_verified:
            self.auth_tunnel.close_tunnel()
            return

        time.sleep(1)

        try:
            data = self.auth_tunnel.conn.recv(1024)
            names = data.decode('latin-1').strip().split(':')
            response = names.pop(0)
            if response == "SUBNET_INVALID":
                self.l.setText("Please add this subnet in the web portal first.")
                self.app.processEvents()
                return
            elif response == "SUBNET_LIST":
                self.l.setText("Please enter your CyberClinic Email and Password.")
                self.e.clear()
                self.p.clear()
                self.hide()
                validate_subnet = Subnet_Form(self, names, self.auth_tunnel)
                validate_subnet.show()

        except Exception as e:
            print(f'{e}')
            self.e.clear()
            self.p.clear()


    def verify_user(self):
        email = self.e.text()
        passwd = self.p.text()
        self.auth = User_Auth(self, email, passwd)
        self.auth.user_verified.connect(self.parse_user_auth)  # Connect signal to slot
        self.l.setText("Verifying...")
        self.app.processEvents()
        try:
            auth_tunnel = TunnelHandler(crt=self.vpn_crt, host=self.vpn_host, port=self.vpn_port)
            print("Got here")
            self.auth.start(auth_tunnel)
        except TimeoutError as e:
            print(f'{e}')
            self.l.setText("Connection error, please try again later")
            time.sleep(5)
        except Exception as e:
            print(f'{e}')
            self.l.setText("Unexpected error. Please contact support: [email].")
        