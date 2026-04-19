#Cyber Clinic Standalone Application - Storage Handler
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
        if type(data) == str:
            data = data.encode('utf-8')
        with open(file, 'wb') as f:
            f.write(data)

        if not os.path.exists(file):
            return False
        return True
