#Cyber Clinic Standalone Application - Main entry point
#CS 425 Team 13 - Fall 2025
import keyring
import sys
import os
import socket
import app
from dotenv import load_dotenv
import permission_handler as perms
import vpn_handler as vpn
import platform
import hashlib
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QApplication,
    QLabel,
    QLineEdit,
    QDialog,
    QFormLayout,
    QPushButton,
    QWidget
)

BUF_SIZE = 65536
apphash: str

class Form(QDialog):

    def __init__(self):
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

        widgets = [
            self.l,
            self.e,
            self.p,
            self.s
        ]

        for w in widgets:
            layout.addWidget(w)

        self.setLayout(layout)
        self.show()

    def verify_user(self):
        email = self.e.text()
        passwd = self.p.text()
        
        conn = vpn.vpn_client(crt, "localhost", int(vpn_port))

        send = f'{apphash}: {email}:{passwd}'
        try:
            conn.send(send.encode('latin-1'))
            data = conn.recv(1024)
            print(f"Received from server: {data}")
            if data:
                keyring.set_password("cyberclinic", email, passwd)
                app.save_user(email)
        finally:
            conn.close()

        print(f"hash: {apphash}\n")
        print(f"{email}: {passwd}")

        self.l.setText("Verifying...")


def compute_hash(filepath: str):
    hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            hash.update(data)
    return hash.hexdigest()


if __name__ == '__main__':
    if not app.admin():
        sys.exit("Please re-run with administrative privleges!")

    load_dotenv()

    file = os.path.abspath(__file__)
    apphash = compute_hash(file)
    
    vpn_crt = os.getenv('VPN_CRT', 'server.crt')
    vpn_host = os.getenv('VPN_HOST', 'localhost')
    vpn_port = os.getenv('VPN_PORT', '6666')
    crt = os.path.join(os.path.dirname(file), vpn_crt)

    user = os.environ.get('CYBERCLINIC_USER')
    if user:
        passwd = keyring.get_password("cyberclinic", user)
        print(passwd)
    else:
        app = QApplication(sys.argv)  
        w = Form()
        app.exec()
