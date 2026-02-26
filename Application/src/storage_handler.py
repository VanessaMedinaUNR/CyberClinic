#Cyber Clinic Standalone Application - Storage Handler
#CS 426 Team 13 - Spring 2026

import os
import sys
class StorageHandler:
    def __init__(self):
        """ Get absolute path to resource, works for dev and for PyInstaller """
        try:
            # PyInstaller creates a temp folder and stores path in _MEIPASS
            self.base_path = sys._MEIPASS
        except Exception:
            self.base_path = os.path.abspath(".")
        finally:
            if os.name == 'nt':
                ext_path = os.path.expanduser("~/AppData/Local/CyberClinic")
                self.ext_path = os.path.abspath(ext_path)
            else:
                ext_path = os.path.expanduser("~.CyberClinic")
                self.ext_path = os.path.abspath(ext_path)

    def fetch(self, relative_path):
        file = os.path.join(self.base_path, relative_path)
        if not os.path.exists(file):
            raise FileNotFoundError(f"Internal file not found at {relative_path}")
        return file
    
    def fetch_ext(self, relative_path):
        file = os.path.join(self.ext_path, relative_path)
        if not os.path.exists(file):
            raise FileNotFoundError(f"External file not found at {file}")
        return file
    
    def save_ext(self, relative_path, data) -> bool:
        file = os.path.join(self.ext_path, relative_path)
        parent = os.path.dirname(file)
        os.makedirs(parent, exist_ok=True)

        with open(file, 'w+') as f:
            f.write(data)

        if not os.path.exists(file):
            return False
        return True
