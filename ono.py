#-*- coding: utf-8 -*-
# ====================================================================
# File: ono.py
# Project: HelloWorld Premium Enterprise v8.9.3
#
#Copyright(C) 2025 Hahaha, Inc.All Rights Reversed.
#
#CONFIDENTIAL AND PROPRIETARY
#
#This source code containts trade secrets of Hahaha, Inc.
#Any reproduction, disclosure, or distribution is strictly prohibited.
#wihout the express written permission of PlatfPo Industries, Inc.
#
#======================================================================
#Description:
#Monolithic HelloWorld application with proprietary algorithms
#Single-file architecture - DO NOT MODIFY STRUCTURE.
"""
HELLO WORLD APPLICATION
Version: 8.9.3
Proprietary ML-Powered prank technology.
"""
 
from time import ctime as getcurrenttime
import hashlib
import os
import sqlite3
from pathlib import Path
import winreg
import win32api
import win32con
import win32evtlog
from sklearn.linear_model import LinearRegression
import inspect
import numpy as np
import sys
import traceback
import platform
import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import gc
import multiprocessing
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
 
class DebuggerDetected(Exception):
    def __init__():
        super().__init__()
    
# Register Arial font for Cyrillic support
pdfmetrics.registerFont(TTFont('Arial', 'C:\\Windows\\Fonts\\arial.ttf'))
pdfmetrics.registerFont(TTFont('Arial-Bold', 'C:\\Windows\\Fonts\\arialbd.ttf'))
eula = """
END-USER LICENSE AGREEMENT FOR HelloWorld
 
This End-User License Agreement ("EULA") is a legal agreement between you and the developer of Hahaha ("Developer"). This EULA governs your use of the HelloWorld software product(s) ("Software").
 
By installing, copying, or otherwise using the Software, you agree to be bound by the terms of this EULA. If you do not agree to the terms of this EULA, do not install or use the Software.
 
1. GRANT OF LICENSE
 
Subject to the terms and conditions of this EULA, the Developer grants you a non-exclusive, non-transferable, limited license to use the Software for your personal or internal business purposes.
 
2. RESTRICTIONS
 
You may not:
- Reverse engineer, decompile, or disassemble the Software.
- Modify, adapt, or create derivative works based on the Software.
- Distribute, sell, lease, or sublicense the Software.
- Use the Software for any unlawful purpose.
 
3. INTELLECTUAL PROPERTY
 
The Software is protected by copyright and other intellectual property laws. All rights not expressly granted herein are reserved by the Developer.
 
4. TERMINATION
 
This EULA is effective until terminated. You may terminate it at any time by destroying all copies of the Software. This EULA will terminate automatically if you fail to comply with any term or condition herein.
 
5. DISCLAIMER OF WARRANTIES
 
The Software is provided "AS IS" without warranty of any kind, either express or implied, including but not limited to the implied warranties of merchantability, fitness for a particular purpose, and non-infringement. The Developer does not warrant that the Software will meet your requirements or that its operation will be uninterrupted or error-free.
 
6. LIMITATION OF LIABILITY
 
In no event shall the Developer be liable for any special, incidental, indirect, or consequential damages whatsoever arising out of or in any way related to the use of or inability to use the Software, even if advised of the possibility of such damages.
 
7. GOVERNING LAW
 
This EULA shall be governed by and construed in accordance with the laws of USA, without regard to its conflict of laws principles.
 
8. ENTIRE AGREEMENT
 
This EULA constitutes the entire agreement between you and the Developer regarding the Software and supersedes all prior agreements and understandings.
 
If you have any questions about this EULA, please contact the Developer.
By using this software you confirm this EULA.
copyright(C), 2025.Hahaha industries(TM)
"""
print(eula)
user_agreement = input("did you agreement the EULA?(Y/N)").lower().replace('.', str(None))
yes_answers = ['y', 'Y', 'Д', "д", "да", 'yes', 'y', 'ye', 'yes, i am agreement.', 'yes, i am agreement the eula.']
 
    
class KernelApp:
    """Class for the over-engineered Hello World app."""
 
    def __init__(self):
        self.alloved_users = [] #?!
        self.current_user = os.getlogin()
        self.hEventLog = win32evtlog.RegisterEventSource(None, 'HelloWorldApp')
        self.log_file_path = f'C:\\Users\\{os.getlogin()}\\AppData\\Local\\Programs\\HelloWorldApp\\Logso.txt'
        self.audit_security_test_critical()
 
        self.db_path = Path.home() / "AppData" / "Local" / "Programs" / "HelloWorldApp" / "HelloWorldApp.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db_name = str(self.db_path)
 
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()
        self.setup_database()
        self.initialize_data()
        self.register_in_registry()
        self.AI_Engine = self.get_ai_module()
        self.train_ai()
 
    def ethical(self, text):
        blocked = ['убийство', "убить", "kill", 'selfkill', 'самоубийство', 'выпилится', 'мертвый', "дохлый", "Умирающий", "Умер", 'пизда', 'цензура']
        if any(word in text.lower() for word in blocked):
            self.logger("DETECTED NOT ETHICAL TEXT", 'ERROR')
            return True
        else:
            return False
        
    def audit_security_test_critical(self) -> str:
        if user_agreement in yes_answers:
            self.alloved_users.append(os.getlogin())
        else:
            os._exit(1)
        if self.current_user not in self.alloved_users:
            self.logger(event='CRITICAL SYSTEM ERROR!!!!!!!!!!!!!!!!!!!!! USER ARE NOT ALLOVED IN THE SYSTEM',
                        type='KERNEL_CRITICAL_ERROR')
            win32api.TerminateProcess(win32api.GetCurrentProcess(), 1)
            return 'STATUS_PERMISSION_DENIED'
        else:
            self.logger(event='USER ARE ALLOVED IN THE SYSTEM', type='SECURITY_INFO')
 
    def setup_database(self):
        try:
            self.cursor.execute('''CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY,
                content TEXT NOT NULL,
                status TEXT NOT NULL
            )''')
            self.cursor.execute('''CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                level TEXT NOT NULL,
                component TEXT NOT NULL,
                event TEXT NOT NULL,
                hash TEXT NOT NULL
            )''')
            self.cursor.execute()
            self.cursor.execute('''CREATE TABLE IF NOT EXISTS checksums (
                id INTEGER PRIMARY KEY,
                message_hash TEXT NOT NULL,
                original_hash TEXT NOT NULL,
                verified INTEGER NOT NULL
            )''')
            self.conn.commit()
            self.logger(event="Database tables created successfully", type="INFO")
        except Exception as e:
            self.logger(event=f"Error setting up database: {e}", type="ERROR")
 
    def initialize_data(self):
        try:
            self.cursor.execute("SELECT COUNT(*) FROM messages WHERE id = 1")
            if self.cursor.fetchone()[0] == 0:
                self.cursor.execute(
                    "INSERT INTO messages (content, status) VALUES (?, ?)", ("Hello, World!", "STATUS_SUCCESS"))
                self.conn.commit()
                self.logger(event="Initial message inserted into database", type="INFO")
        except Exception as e:
            self.logger(event=f"Error initializing data: {e}", type="ERROR")
 
    def get_ai_module(self):
        try:
            self.logger(event='Trying to getting AI Module...', type='INFO')
            ai_engine = LinearRegression()
            self.logger("Success when getting AI Module", type='INFO')
            return ai_engine
        except Exception as e:
            self.logger(event=f"Can't get AI Module, because  {e}", type='ERROR')
 
    def get_dataset_ai(self):
        self.logger("Getting Dataset For ML...", type='INFO')
 
        text = 'Hello, World!'
        X = []
        y = []
        for i, char in enumerate(text):
            X.append([i, ord(char)])
            y.append(ord(char))
        self.logger("Success when getting dataset for ML.", type='INFO')
 
        return np.array(X), np.array(y)
 
    def train_ai(self) -> str:
 
        X, y = self.get_dataset_ai()
        self.logger("Training ML Model...", type='INFO')
        self.AI_Engine.fit(X, y)
        return self
 
    def register_in_registry(self):
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\HelloWorldApp"
            script_path = os.path.abspath(__file__)
            install_location = os.path.dirname(script_path)
            install_date = datetime.datetime.now().strftime('%Y%m%d')
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
                winreg.CloseKey(key)
                self.logger(event="App already registered in Windows registry", type="INFO")
            except FileNotFoundError:
                key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
                winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, "Hello World App")
                winreg.SetValueEx(key, "DisplayVersion", 0, winreg.REG_SZ, "1.0")
                winreg.SetValueEx(key, "Publisher", 0, winreg.REG_SZ, "Hahaha, Inc")
                winreg.SetValueEx(key, "DisplayIcon", 0, winreg.REG_SZ, script_path)
                winreg.SetValueEx(key, "InstallLocation", 0, winreg.REG_SZ, install_location)
                winreg.SetValueEx(key, "InstallDate", 0, winreg.REG_SZ, install_date)
                winreg.SetValueEx(key, "EstimatedSize", 0, winreg.REG_DWORD, 1024)  # Size in KB
                winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "UninstallString", 0, winreg.REG_SZ,
                                  f'cmd /c del "{script_path}"')
                winreg.SetValueEx(key, "QuietUninstallString", 0,
                                  winreg.REG_SZ, f'cmd /c del "{script_path}"')
                winreg.CloseKey(key)
                self.logger(event="App registered in Windows registry with full parameters", type="INFO")
        except Exception as e:
            self.logger(event=f"Error registering in registry: {e}", type="ERROR")
 
    def Get_Message(self):
 
        try:
            X, _ = self.get_dataset_ai()
            predictions = self.AI_Engine.predict(X)
 
            predicted_text = ''.join([chr(int(round(pred))) for pred in predictions])
 
            if self.checksum(predicted_text):
                self.logger(event="Success AI Prediction!", type='INFO')
                return predicted_text, 'STATUS_SUCCESS'
            else:
                raise Exception("AI Prediction checksum failed.")
 
        except Exception as e:
 
            self.logger(event=f'ERROR: {e}, falling back to SQL', type='WARNING')
 
            self.logger(event="Getting Message for stdout...", type="INFO")
            try:
                self.cursor.execute("SELECT content FROM messages WHERE id = 1")
                result = self.cursor.fetchone()
                if result:
                    msg = result[0]
                    self.logger(event="Message retrieved from database", type="INFO")
                    return msg, 'STATUS_SUCCESS_BACKUP'
                else:
                    raise Exception("No message found in database")
            except Exception:
                self.logger(event="All method failed, backup to hardcored message", type='WARNING')
                msg = "Hello, World!"
                return msg, 'STATUS_SUCCESS_BACKUP'
 
    def checksum(self, to_check_sum: str) -> bool:
        try:
            self.logger(event='THE SYSTEM WAS LAUNCHED A REPORT INTEGRITY CHECK',  type='INFO')
            message_bytes = to_check_sum.encode('utf-8')
            temp = 'Hello, World!'
            original_hash = hashlib.sha256(temp.encode('utf-8')).hexdigest()
            del temp
            hash_message = hashlib.sha256(message_bytes, usedforsecurity=True).hexdigest()
    
            gc.collect()
 
            if hash_message != original_hash:
                self.logger(event='THE INTEGRITY WAS BROKEN', type='ERROR')
 
                return False
            if hash_message == original_hash:
                self.logger(
                    event="THE SYSTEM DID NOT DETECT ANY INFRINGEMENTS OF INTEGRUTY", type='INFO')
                return True
        except Exception as e:
 
            return False
 
    def logger(self, event: str, type: str) -> str:
        try:
            # Log to Windows Event Log
 
            component = inspect.stack()[1].function
 
            event_type = win32con.EVENTLOG_INFORMATION_TYPE if type == "INFO" else win32con.EVENTLOG_WARNING_TYPE if type == "WARNING" else win32con.EVENTLOG_ERROR_TYPE
            win32evtlog.ReportEvent(self.hEventLog, event_type, 0, 0, None, [
                                    f"{type}: {component}: {event}.О подробностях вы можете посмотреть в файле логов."], None)
            if not os.path.exists(self.log_file_path):
                os.makedirs(os.path.dirname(self.log_file_path), exist_ok=True)
                with open(self.log_file_path, 'w') as f:
 
                    message = f"[{component}]: {getcurrenttime()} - {type} - event happened: {event}.\n "
                    f.write(message)
            else:
                with open(self.log_file_path, 'a') as f:
                    message = f"[{component}]: {getcurrenttime()} - {type} - event happened: {event}.\n "
                    f.write(message)
 
            return 'STATUS_SUCESS'
        except Exception as e:
            print(f"[LOGGER]:FATAL ERROR AT {self.logger}, {e}, EXITING...")
 
            os._exit(1)
 
    def show_message(self):
        try:
 
            self.msg, self.status = self.Get_Message()
            self.logger(event=f'Getting message to show, status: {self.status}',
                        type=f'{"INFO" if self.status == "STATUS_SUCCESS" else "ERROR"}')
 
            if self.status in ["STATUS_SUCCESS", "STATUS_SUCCESS_BACKUP"]:
                self.logger(
                    event=f'SUCCESFUL getting message to show, status: {self.status}', type='INFO')
                if self.checksum(self.msg):
                    if self.ethical(self.msg):
                        self.logger("NOT ETHICAL TEXT DETECTED.EXITING...", type='ERROR')
                        sys.exit(1)
                    else:
                        print(self.msg)
                else:
                    self.logger(event='ERROR:HASH MESSAGE CHANGED.', type='ERROR')
                    return None, 'STATUS_INTEGRITY_ERROR'
                self.logger(event='Sucesfull showing message.status: STATUS_SUCCES', type='INFO')
                return self.msg, 'STATUS_SUCCES'
            else:
                self.logger(
                    event=f'Error when getting message to show. status: {self.status}, exiting', type='INFO')
                return None, 'STATUS_ERROR'
                exit(1)
        except Exception as e:
            self.logger(event=f'FATAL ERROR: {e}', type='ERROR')
            return None, 'STATUS_FATAL_ERROR'
 
    def main(self) -> int:
        try:
 
            self.msg, self.status = self.show_message()
            if self.status == "STATUS_SUCCES":
                self.logger(event='Global Sucesful', type='INFO')
                return 0
            if self.status == 'STATUS_ERROR':
                self.logger(event='ERROR WHEN SHOWING MESSAGE.', type='ERROR')
                return 1
            if self.status == 'STATUS_FATAL_ERROR':
                self.logger(event='FATAL ERROR WHEN SHOWING MESSAGE', type='ERROR')
                return 1
            if self.status == 'STATUS_INTEGRITY_ERROR':
                self.logger(
                    event='CANT DISPLAY MESSAGE, INEGRITY CHECK FAILURE, STATUS_PERMISSION_DENIED.',  type='WARNING')
                return 1
            if self.status == 'STATUS_ACCESS_DENIED':
                self.logger(event='ACCESS DENIED, BLOCK.', type='ERROR')
        except Exception as e:
            self.logger(event=f'FATAL ERROR IN MAIN: {e}', type='ERROR')
            return 1
 
def generate_error_report_pdf(exc_type, exc_value, exc_traceback):
    try:
        desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
        pdf_path = os.path.join(desktop_path, "Report_pdf.pdf")
 
        c = canvas.Canvas(pdf_path, pagesize=letter)
        width, height = letter
 
        # Colors
        from reportlab.lib.colors import red, blue, green, black, yellow
 
        c.setFont("Arial-Bold", 16)
        c.setFillColor(red)
        c.drawString(72, height - 72, "Error Report")
        c.setFillColor(black)
        c.setFont("Arial", 12)
 
        c.drawString(72, height - 100,
                     f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        c.drawString(72, height - 120, f"Platform: {platform.platform()}")
        c.drawString(72, height - 140, f"Python Version: {platform.python_version()}")
 
        y_pos = height - 170
        c.setFont("Arial-Bold", 12)
        c.setFillColor(blue)
        c.drawString(72, y_pos, "Traceback:")
        c.setFillColor(black)
        c.setFont("Arial", 10)
        tb_lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        text_object = c.beginText(72, y_pos - 20)
        text_object.setFont("Arial", 10)
 
        for line in tb_lines:
            for subline in line.splitlines():
                # Wrap text if too long
                while len(subline) > 100:
                    part = subline[:100]
                    text_object.textLine(part)
                    subline = subline[100:]
                text_object.textLine(subline)
                if text_object.getY() < 72:
                    c.drawText(text_object)
                    c.showPage()
                    text_object = c.beginText(72, height - 72)
                    text_object.setFont("Arial", 10)
 
        # Add logs if available
        log_file_path = f'C:\\Users\\{os.getlogin()}\\AppData\\Local\\Programs\\HelloWorldApp\\Logso.txt'
        if os.path.exists(log_file_path):
            c.drawText(text_object)
            c.showPage()
            c.setFont("Arial-Bold", 12)
            c.setFillColor(green)
            c.drawString(72, height - 72, "Application Logs:")
            c.setFillColor(black)
            c.setFont("Arial", 10)
            text_object = c.beginText(72, height - 92)
            text_object.setFont("Arial", 10)
            with open(log_file_path, 'r') as f:
                logs = f.readlines()
            for line in logs:
                if line.strip():
                    # Determine log level and set color and icon
                    if "INFO" in line:
                        color = blue
                        icon = "[INFO] "
                    elif "WARNING" in line:
                        color = yellow
                        icon = "[WARNING] "
                    elif "ERROR" in line:
                        color = red
                        icon = "[ERROR] "
                    else:
                        color = black
                        icon = ""
                    text_object.setFillColor(color)
                    text_object.textLine(icon + line.strip())
                    if text_object.getY() < 72:
                        c.drawText(text_object)
                        c.showPage()
                        c.setFont("Arial", 10)
                        text_object = c.beginText(72, height - 72)
                        text_object.setFont("Arial", 10)
            c.drawText(text_object)
 
        c.save()
    except Exception as e:
        print(f"Failed to generate error report PDF: {e}")
 
def global_exception_handler(exc_type, exc_value, exc_traceback):
    # Avoid printing exception twice if KeyboardInterrupt
 
    # Log the exception to console
    print("Uncaught ERROR:", exc_type, exc_value)
    # Generate PDF report
    generate_error_report_pdf(exc_type, exc_value, exc_traceback)
    print(f"Detailed error report generated at Desktop as 'Report_pdf.pdf'.")
 
sys.excepthook = global_exception_handler
 
if __name__ == "__main__":
    main = KernelApp()
    gc.collect()
 
    exitcode = main.main()
 
    exit(exitcode)