#Cyber Clinic Standalone Application - Permission Handler
#CS 425 Team 13 - Fall 2025

# Code adapted from:
#   Avinash Tare, How to run Python code with admin privileges
#   dev.to, July 15 2025 
#   Available: https://dev.to/avinash_tare_6d6e81721bb6/how-to-run-python-code-with-admin-privileges-2b2a

import os
import ctypes
import sys
import subprocess


class StorageHandler:
    def __init__(self):
        """ Get absolute path to resource, works for dev and for PyInstaller """
        try:
            # PyInstaller creates a temp folder and stores path in _MEIPASS
            self.base_path = sys._MEIPASS
        except Exception:
            self.base_path = os.path.abspath(".")

    def fetch(self, relative_path):
        file = os.path.join(self.base_path, relative_path)
        if not os.path.exists(file):
            raise FileNotFoundError
        return file
    
    def save(self, relative_path, data):
        file = os.path.join(self.base_path, relative_path)
        parent = os.path.dirname(file)
        os.makedirs(parent, exist_ok=True)

        with open(file, 'w+') as f:
            f.write(data)

        if not os.path.exists(file):
            return False
        return True
