#Cyber Clinic Standalone Application - Main entry point
#CS 425 Team 13 - Fall 2025
import keyring
import sys
import os
import time
import app
from dotenv import load_dotenv
import permission_handler as perms
import vpn_handler as vpn
import platform
import hashlib
from PyQt6.QtCore import Qt, pyqtSignal, QObject, QVariant
from PyQt6.QtWidgets import (
    QApplication,
    QLabel,
    QLineEdit,
    QDialog,
    QFormLayout,
    QPushButton,
    QComboBox
)

BUF_SIZE = 65536
apphash: str

class User_Auth(QObject):
    user_verified = pyqtSignal(QVariant, arguments=['result'])  # Define a signal to send data back
    
    def __init__(self, form, email, passwd):
        super().__init__()
        self.form = form
        self.email = email
        self.passwd = passwd

    def start(self):
        
        conn = vpn.vpn_client(crt, "localhost", int(vpn_port))

        print(f"hash: {apphash}\n")
        print(f"{self.email}: {self.passwd}")
        send = f'{apphash}:{self.email}:{self.passwd}'
        
        try:
            conn.send(send.encode('latin-1'))
            data = conn.recv(1024)

            parts = data.decode('latin-1').strip().split(':')
            match len(parts):
                case 2:
                    success, message = parts
                    print(f"Received from server: {success}: {message}")
                    self.form.l.setText(message)
                    self.form.p.clear()
                    time.sleep(5)
                    self.user_verified.emit({"success": False}) # Emit the result when done
                case 3:
                    success, client_id, email = parts
                    print(f"Received from server: {success}: {client_id} - {email}")

                    if success == "AUTH_SUCCESS":
                        self.form.l.setText("User verification success!")
                        keyring.set_password("cyberclinic", self.email, self.passwd)
                        time.sleep(5)
                        self.user_verified.emit({"success": True, "client_id": client_id, "email": email, "conn": conn})  
                case _:
                    self.form.l.setText("User verification failed! Please try again.")
                    self.form.p.clear()
                    time.sleep(5)
                    self.user_verified.emit({"success": False})
        except Exception as e:
            print(f'{e}')
            self.form.l.setText("Connection error, please try again later")
            time.sleep(5)
            self.user_verified.emit({"success": False})
        

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

        self.h = QComboBox()
        self.h.setVisible(False)

        self.s = QPushButton("Submit")
        self.s.setDefault(1)
        self.s.clicked.connect(self.verify_user)

        widgets = [
            self.l,
            self.e,
            self.p,
            self.h,
            self.s
        ]

        for w in widgets:
            layout.addWidget(w)

        self.setLayout(layout)
        self.show()


    def parse_user_auth(self, results):
        user_verified = results['success']
        if not user_verified:
            return
        
        self.client_id = results['client_id']
        self.conn = results['conn']

        try:
            data = self.conn.recv(1024)
            print(data)
            names = data.decode('latin-1').strip().split(':')
            response = names.pop(0)
            if response == "SUBNET_INVALID":
                self.l.setText("Please add a subnet in the web portal first.")
                return
            elif response == "SUBNET_LIST":
                self.h.addItems(names)

        except Exception as e:
            print(f'{e}')
        
        self.e.clear()
        self.p.clear()

        self.l.setText("Please enter the name of the subnet (Hint: this should be completed in the portal online first)")
        
        self.p.setVisible(False)
        self.e.setVisible(False)
        self.h.setVisible(True)
        
        self.s.clicked.disconnect(self.verify_user)
        self.s.clicked.connect(self.verify_host)


    def verify_host(self):
        host_name = self.h.text
        print(f'Hostname: {host_name}')
        send = f'{host_name}'
        try:
            self.conn.send(send.encode('latin-1'))
            data = self.conn.recv(1024)
            print(data)

        except Exception as e:
            print(f'{e}')


    def verify_user(self):
        email = self.e.text()
        passwd = self.p.text()
        self.auth = User_Auth(self, email, passwd)
        self.auth.user_verified.connect(self.parse_user_auth)  # Connect signal to slot
        self.l.setText("Verifying...")
        self.auth.start()


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
