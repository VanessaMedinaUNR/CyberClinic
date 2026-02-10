import os
import sys
import time
import platform
import subprocess
import socket
from pathlib import Path
import keyring
from PyQt6.QtCore import pyqtSignal, QObject, QVariant
from PyQt6.QtWidgets import (
    QLabel,
    QDialog,
    QFormLayout,
    QPushButton,
    QComboBox
)

class Subnet_Form(QDialog):
    def __init__(self, auth, subnet_list, auth_tunnel):
        super().__init__(auth)
        self.app = auth.app
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
            self.auth_tunnel.conn.send(send.encode('latin-1'))
            data = self.auth_tunnel.conn.recv(1024)
            response = data.decode('latin-1').strip().split(':')
            print(response)
            success = response.pop(0)
            match success:
                case 'SUBNET_INVALID':
                    return
                case 'SUBNET_VALID':
                    self.l.setText("Subnet verified! Finishing up...")
                    self.app.processEvents()
                    self.auth_tunnel.close_tunnel()
                case _:
                    self.go_back()

        except Exception as e:
            print(f'{e}')
    
    def go_back(self):
        self.auth_tunnel.close_tunnel()
        self.parent().show()
        self.done(0)

    def closeEvent(self, event):
        self.auth_tunnel.close_tunnel()
        self.app.exit()