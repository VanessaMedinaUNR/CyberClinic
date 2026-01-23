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

def is_admin(system: str):
    match system:
        case "Windows":
            try:
                return ctypes.windll.shell32.IsUserAnAdmin()
            except:
                return False
        case _:
            try:
                return os.geteuid() == 0
            except:
                return False
            
def request_admin_privileges(system: str):
    match system:
        case "Windows":
            try:
                result = ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, " ".join(sys.argv), None, 1
                )
                return result > 32  # Success if result > 32
            except Exception as e:
                print("Error:", str(e))
                return False
        case _:
            return prompt_sudo() != 0

def prompt_sudo():
    ret = 0
    if os.geteuid() != 0:
        msg = "[sudo] password for %u:"
        ret = subprocess.check_call("sudo -v -p '%s'" % msg, shell=True)
    return ret