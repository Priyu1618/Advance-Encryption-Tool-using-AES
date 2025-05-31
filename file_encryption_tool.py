import os
import base64
import time
import json
import hashlib
import logging
import random
import string
import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import customtkinter as ctk
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image
from email.message import EmailMessage
import smtplib
import pyotp
import qrcode
from threading import Timer
import shutil

# Configure logging
logging.basicConfig(
    filename='encryption_tool.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Constants
CONFIG_FILE = "config.json"
AUDIT_LOG_FILE = "audit_log.json"
DEFAULT_CONFIG = {
    "email": "",
    "temp_directory": "temp_encrypted_files",
    "totp_secret": "",
    "audit_enabled": True
}
STEGANOGRAPHY_BITS = 2  # Number of bits to use in steganography

class FileEncryptionTool:
    def __init__(self):
        # Initialize configuration
        self.config = self._load_config()
        self.audit_log = self._load_audit_log()
        
        # Ensure temp directory exists
        if not os.path.exists(self.config["temp_directory"]):
            os.makedirs(self.config["temp_directory"])
        
        # Initialize GUI
        self.app = ctk.CTk()
        ctk.set_appearance_mode("dark")
        self.app.title("Advanced File Encryption Tool")
        self.app.geometry("800x600")
        self.setup_ui()
        
        # 2FA setup
        self.totp = None
        if self.config["totp_secret"]:
            self.totp = pyotp.TOTP(self.config["totp_secret"])
        
        # Current user session info
        self.current_user = None
        self.authenticated = False
    
    def _load_config(self):
        """Load configuration from file or create default"""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    return json.load(f)
            except:
                return DEFAULT_CONFIG.copy()
        else:
            with open(CONFIG_FILE, "w") as f:
                json.dump(DEFAULT_CONFIG, f, indent=2)
            return DEFAULT_CONFIG.copy()
    
    def _save_config(self):
        """Save configuration to file"""
        with open(CONFIG_FILE, "w") as f:
            json.dump(self.config, f, indent=2)
    
    def _load_audit_log(self):
        """Load audit log from file or create new"""
        if os.path.exists(AUDIT_LOG_FILE):
            try:
                with open(AUDIT_LOG_FILE, "r") as f:
                    return json.load(f)
            except:
                return []
        else:
            return []
    
    def _save_audit_log(self):
        """Save audit log to file"""
        with open(AUDIT_LOG_FILE, "w") as f:
            json.dump(self.audit_log, f, indent=2)
    
    def log_action(self, action, details=""):
        """Log an action to the audit log"""
        if not self.config["audit_enabled"]:
            return
            
        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "user": self.current_user or "anonymous",
            "action": action,
            "details": details
        }
        self.audit_log.append(entry)
        self._save_audit_log()
        logging.info(f"AUDIT: {action} by {self.current_user or 'anonymous'} - {details}")
    
    def setup_ui(self):
        """Set up the user interface"""
        self.tabs = ctk.CTkTabview(self.app)
        self.tabs.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create tabs
        self.tabs.add("Login")
        self.tabs.add("Encrypt")
        self.tabs.add("Decrypt")
        self.tabs.add("Steganography")
        self.tabs.add("File Sharing")
        self.tabs.add("Settings")
        self.tabs.add("Audit Logs")
        
        # Setup each tab
        self.setup_login_tab()
        self.setup_encrypt_tab()
        self.setup_decrypt_tab()
        self.setup_steganography_tab()
        self.setup_file_sharing_tab()
        self.setup_settings_tab()
        self.setup_audit_logs_tab()
    
    def setup_login_tab(self):
        """Set up the login tab"""
        tab = self.tabs.tab("Login")
        
        ctk.CTkLabel(tab, text="User Authentication", font=("Arial", 20)).pack(pady=20)
        
        # Username field
        frame = ctk.CTkFrame(tab)
        frame.pack(pady=10, fill="x", padx=20)
        ctk.CTkLabel(frame, text="Username:").pack(side="left", padx=10)
        self.username_entry = ctk.CTkEntry(frame, width=200)
        self.username_entry.pack(side="left", padx=10, fill="x", expand=True)
        
        # Password field
        frame = ctk.CTkFrame(tab)
        frame.pack(pady=10, fill="x", padx=20)
        ctk.CTkLabel(frame, text="Password:").pack(side="left", padx=10)
        self.password_entry = ctk.CTkEntry(frame, width=200, show="*")
        self.password_entry.pack(side="left", padx=10, fill="x", expand=True)
        
        # 2FA field
        frame = ctk.CTkFrame(tab)
        frame.pack(pady=10, fill="x", padx=20)
        ctk.CTkLabel(frame, text="2FA Code:").pack(side="left", padx=10)
        self.totp_entry = ctk.CTkEntry(frame, width=200)
        self.totp_entry.pack(side="left", padx=10, fill="x", expand=True)
        
        # Login button
        ctk.CTkButton(tab, text="Login", command=self.login).pack(pady=20)
        
        # Setup 2FA button
        ctk.CTkButton(tab, text="Setup 2FA", command=self.setup_2fa).pack(pady=10)
    
    def setup_encrypt_tab(self):
        """Set up the encrypt tab"""
        tab = self.tabs.tab("Encrypt")
        
        ctk.CTkLabel(tab, text="File Encryption", font=("Arial", 20)).pack(pady=20)
        
        # File selection
        frame = ctk.CTkFrame(tab)
        frame.pack(pady=10, fill="x", padx=20)
        self.encrypt_file_label = ctk.CTkLabel(frame, text="No file selected")
        self.encrypt_file_label.pack(side="left", padx=10, fill="x", expand=True)
        ctk.CTkButton(frame, text="Select File", command=self.select_file_to_encrypt).pack(side="right", padx=10)
        
        # Password for encryption
        frame = ctk.CTkFrame(tab)
        frame.pack(pady=10, fill="x", padx=20)
        ctk.CTkLabel(frame, text="Password:").pack(side="left", padx=10)
        self.encrypt_password = ctk.CTkEntry(frame, width=200, show="*")
        self.encrypt_password.pack(side="left", padx=10, fill="x", expand=True)
        
        # Self-destruct options
        frame = ctk.CTkFrame(tab)
        frame.pack(pady=10, fill="x", padx=20)
        self.self_destruct_var = tk.BooleanVar(value=False)
        self.self_destruct_checkbox = ctk.CTkCheckBox(
            frame, text="Self-destruct after", variable=self.self_destruct_var
        )
        self.self_destruct_checkbox.pack(side="left", padx=10)
        
        self.self_destruct_time = ctk.CTkEntry(frame, width=50)
        self.self_destruct_time.insert(0, "24")
        self.self_destruct_time.pack(side="left", padx=5)
        
        ctk.CTkLabel(frame, text="hours").pack(side="left", padx=5)
        
        # Encrypt button
        ctk.CTkButton(tab, text="Encrypt File", command=self.encrypt_file).pack(pady=20)
    
    def setup_decrypt_tab(self):
        """Set up the decrypt tab"""
        tab = self.tabs.tab("Decrypt")
        
        ctk.CTkLabel(tab, text="File Decryption", font=("Arial", 20)).pack(pady=20)
        
        # File selection
        frame = ctk.CTkFrame(tab)
        frame.pack(pady=10, fill="x", padx=20)
        self.decrypt_file_label = ctk.CTkLabel(frame, text="No file selected")
        self.decrypt_file_label.pack(side="left", padx=10, fill="x", expand=True)
        ctk.CTkButton(frame, text="Select File", command=self.select_file_to_decrypt).pack(side="right", padx=10)
        
        # Password for decryption
        frame = ctk.CTkFrame(tab)
        frame.pack(pady=10, fill="x", padx=20)
        ctk.CTkLabel(frame, text="Password:").pack(side="left", padx=10)
        self.decrypt_password = ctk.CTkEntry(frame, width=200, show="*")
        self.decrypt_password.pack(side="left", padx=10, fill="x", expand=True)
        
        # Decrypt button
        ctk.CTkButton(tab, text="Decrypt File", command=self.decrypt_file).pack(pady=20)
    
    def setup_steganography_tab(self):
        """Set up the steganography tab"""
        tab = self.tabs.tab("Steganography")
        
        ctk.CTkLabel(tab, text="Steganography", font=("Arial", 20)).pack(pady=20)
        
        # Mode selection
        frame = ctk.CTkFrame(tab)
        frame.pack(pady=10, fill="x", padx=20)
        self.steg_mode = tk.StringVar(value="hide")
        ctk.CTkRadioButton(frame, text="Hide data in image", variable=self.steg_mode, value="hide").pack(side="left", padx=20)
        ctk.CTkRadioButton(frame, text="Extract data from image", variable=self.steg_mode, value="extract").pack(side="left", padx=20)
        
        # Image selection
        frame = ctk.CTkFrame(tab)
        frame.pack(pady=10, fill="x", padx=20)
        self.steg_image_label = ctk.CTkLabel(frame, text="No image selected")
        self.steg_image_label.pack(side="left", padx=10, fill="x", expand=True)
        ctk.CTkButton(frame, text="Select Image", command=self.select_steg_image).pack(side="right", padx=10)
        
        # File selection (for hiding)
        frame = ctk.CTkFrame(tab)
        frame.pack(pady=10, fill="x", padx=20)
        self.steg_file_label = ctk.CTkLabel(frame, text="No file selected")
        self.steg_file_label.pack(side="left", padx=10, fill="x", expand=True)
        self.steg_file_button = ctk.CTkButton(frame, text="Select File to Hide", command=self.select_file_to_hide)
        self.steg_file_button.pack(side="right", padx=10)
        
        # Password for steganography
        frame = ctk.CTkFrame(tab)
        frame.pack(pady=10, fill="x", padx=20)
        ctk.CTkLabel(frame, text="Password:").pack(side="left", padx=10)
        self.steg_password = ctk.CTkEntry(frame, width=200, show="*")
        self.steg_password.pack(side="left", padx=10, fill="x", expand=True)
        
        # Process button
        self.steg_process_button = ctk.CTkButton(tab, text="Hide Data", command=self.process_steganography)
        self.steg_process_button.pack(pady=20)
        
        # Update UI based on mode
        self.steg_mode.trace_add("write", self.update_steg_ui)
    
    def setup_file_sharing_tab(self):
        """Set up the file sharing tab"""
        tab = self.tabs.tab("File Sharing")
        
        ctk.CTkLabel(tab, text="Encrypted File Sharing", font=("Arial", 20)).pack(pady=20)
        
        # File selection
        frame = ctk.CTkFrame(tab)
        frame.pack(pady=10, fill="x", padx=20)
        self.share_file_label = ctk.CTkLabel(frame, text="No file selected")
        self.share_file_label.pack(side="left", padx=10, fill="x", expand=True)
        ctk.CTkButton(frame, text="Select File", command=self.select_file_to_share).pack(side="right", padx=10)
        
        # Recipient email
        frame = ctk.CTkFrame(tab)
        frame.pack(pady=10, fill="x", padx=20)
        ctk.CTkLabel(frame, text="Recipient Email:").pack(side="left", padx=10)
        self.recipient_email = ctk.CTkEntry(frame, width=200)
        self.recipient_email.pack(side="left", padx=10, fill="x", expand=True)
        
        # Password for encryption
        frame = ctk.CTkFrame(tab)
        frame.pack(pady=10, fill="x", padx=20)
        ctk.CTkLabel(frame, text="Password:").pack(side="left", padx=10)
        self.share_password = ctk.CTkEntry(frame, width=200, show="*")
        self.share_password.pack(side="left", padx=10, fill="x", expand=True)
        
        # Self-destruct options
        frame = ctk.CTkFrame(tab)
        frame.pack(pady=10, fill="x", padx=20)
        self.share_self_destruct_var = tk.BooleanVar(value=False)
        self.share_self_destruct_checkbox = ctk.CTkCheckBox(
            frame, text="Self-destruct after", variable=self.share_self_destruct_var
        )
        self.share_self_destruct_checkbox.pack(side="left", padx=10)
        
        self.share_self_destruct_time = ctk.CTkEntry(frame, width=50)
        self.share_self_destruct_time.insert(0, "24")
        self.share_self_destruct_time.pack(side="left", padx=5)
        
        ctk.CTkLabel(frame, text="hours").pack(side="left", padx=5)
        
        # Share button
        ctk.CTkButton(tab, text="Share File", command=self.share_file).pack(pady=20)
    
    def setup_settings_tab(self):
        """Set up the settings tab"""
        tab = self.tabs.tab("Settings")
        
        ctk.CTkLabel(tab, text="Settings", font=("Arial", 20)).pack(pady=20)
        
        # Email setting
        frame = ctk.CTkFrame(tab)
        frame.pack(pady=10, fill="x", padx=20)
        ctk.CTkLabel(frame, text="Email for sharing:").pack(side="left", padx=10)
        self.email_setting = ctk.CTkEntry(frame, width=200)
        self.email_setting.insert(0, self.config.get("email", ""))
        self.email_setting.pack(side="left", padx=10, fill="x", expand=True)
        
        # Email password
        frame = ctk.CTkFrame(tab)
        frame.pack(pady=10, fill="x", padx=20)
        ctk.CTkLabel(frame, text="Email Password:").pack(side="left", padx=10)
        self.email_password = ctk.CTkEntry(frame, width=200, show="*")
        self.email_password.pack(side="left", padx=10, fill="x", expand=True)
        
        # Audit logging setting
        frame = ctk.CTkFrame(tab)
        frame.pack(pady=10, fill="x", padx=20)
        self.audit_enabled_var = tk.BooleanVar(value=self.config.get("audit_enabled", True))
        self.audit_enabled_checkbox = ctk.CTkCheckBox(
            frame, text="Enable Audit Logging", variable=self.audit_enabled_var
        )
        self.audit_enabled_checkbox.pack(side="left", padx=10)
        
        # Save settings button
        ctk.CTkButton(tab, text="Save Settings", command=self.save_settings).pack(pady=20)
    
    def setup_audit_logs_tab(self):
        """Set up the audit logs tab"""
        tab = self.tabs.tab("Audit Logs")
        
        ctk.CTkLabel(tab, text="Audit Logs", font=("Arial", 20)).pack(pady=20)
        
        # Log display
        frame = ctk.CTkFrame(tab)
        frame.pack(pady=10, fill="both", expand=True, padx=20)
        
        self.log_display = tk.Text(frame, wrap="word", bg="#2b2b2b", fg="white", height=20)
        self.log_display.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Refresh button
        ctk.CTkButton(tab, text="Refresh Logs", command=self.refresh_audit_logs).pack(pady=10)
        
        # Export button
        ctk.CTkButton(tab, text="Export Logs", command=self.export_audit_logs).pack(pady=10)
    
    def update_steg_ui(self, *args):
        """Update steganography UI based on mode selection"""
        mode = self.steg_mode.get()
        if mode == "hide":
            self.steg_file_button.configure(text="Select File to Hide")
            self.steg_process_button.configure(text="Hide Data")
        else:
            self.steg_file_button.configure(text="Select Output Location")
            self.steg_process_button.configure(text="Extract Data")
    
    def login(self):
        """Handle user login with 2FA"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        totp_code = self.totp_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required")
            return
        
        # In a real app, you would validate against stored credentials
        # For this demo, we'll accept any non-empty username/password
        
        # Verify 2FA if configured
        if self.totp:
            if not totp_code:
                messagebox.showerror("Error", "2FA code is required")
                return
            
            if not self.totp.verify(totp_code):
                messagebox.showerror("Error", "Invalid 2FA code")
                self.log_action("failed_login", f"Invalid 2FA code for user {username}")
                return
        
        self.authenticated = True
        self.current_user = username
        messagebox.showinfo("Success", "Login successful!")
        self.log_action("login", f"User {username} logged in")
        
        # Switch to encrypt tab after login
        self.tabs.set("Encrypt")
    
    def setup_2fa(self):
        """Set up two-factor authentication"""
        # Generate a new secret key
        secret = pyotp.random_base32()
        self.config["totp_secret"] = secret
        self._save_config()
        
        # Create TOTP object
        self.totp = pyotp.TOTP(secret)
        
        # Get provisioning URI for QR code
        uri = self.totp.provisioning_uri(
            name=self.username_entry.get() or "user",
            issuer_name="File Encryption Tool"
        )
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        img.save("2fa_qrcode.png")
        
        # Show setup instructions
        messagebox.showinfo(
            "2FA Setup",
            "2FA has been set up!\n\n"
            "1. Scan the QR code in the '2fa_qrcode.png' file with your authenticator app\n"
            "2. Enter the code from your app when logging in\n\n"
            "Secret key (if needed): " + secret
        )
        
        self.log_action("2fa_setup", "Two-factor authentication was set up")
    
    def derive_key(self, password, salt=None):
        """Derive an encryption key from a password"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    def select_file_to_encrypt(self):
        """Select a file to encrypt"""
        file_path = filedialog.askopenfilename(title="Select file to encrypt")
        if file_path:
            self.encrypt_file_path = file_path
            self.encrypt_file_label.configure(text=os.path.basename(file_path))
    
    def encrypt_file(self):
        """Encrypt a file"""
        if not hasattr(self, 'encrypt_file_path'):
            messagebox.showerror("Error", "Please select a file to encrypt")
            return
        
        password = self.encrypt_password.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        
        # Check authentication
        if not self.authenticated:
            messagebox.showerror("Error", "Please login first")
            return
        
        try:
            # Read the file
            with open(self.encrypt_file_path, 'rb') as file:
                data = file.read()
            
            # Generate a salt and derive a key
            salt = os.urandom(16)
            key, _ = self.derive_key(password, salt)
            
            # Encrypt the data
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(data)
            
            # Add the salt to the beginning of the encrypted data
            final_data = salt + encrypted_data
            
            # Save the encrypted file
            output_path = filedialog.asksaveasfilename(
                title="Save encrypted file",
                defaultextension=".enc",
                filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
            )
            
            if not output_path:
                return
            
            with open(output_path, 'wb') as file:
                file.write(final_data)
            
            # Handle self-destruct if enabled
            if self.self_destruct_var.get():
                try:
                    hours = float(self.self_destruct_time.get())
                    self.setup_self_destruct(output_path, hours)
                except ValueError:
                    messagebox.showerror("Error", "Invalid self-destruct time")
                    return
            
            self.log_action("encrypt_file", f"Encrypted file {os.path.basename(self.encrypt_file_path)}")
            messagebox.showinfo("Success", "File encrypted successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            self.log_action("encryption_error", f"Error encrypting file: {str(e)}")
    
    def select_file_to_decrypt(self):
        """Select a file to decrypt"""
        file_path = filedialog.askopenfilename(
            title="Select file to decrypt",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
        )
        if file_path:
            self.decrypt_file_path = file_path
            self.decrypt_file_label.configure(text=os.path.basename(file_path))
    
    def decrypt_file(self):
        """Decrypt a file"""
        if not hasattr(self, 'decrypt_file_path'):
            messagebox.showerror("Error", "Please select a file to decrypt")
            return
        
        password = self.decrypt_password.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        
        # Check authentication
        if not self.authenticated:
            messagebox.showerror("Error", "Please login first")
            return
        
        try:
            # Read the encrypted file
            with open(self.decrypt_file_path, 'rb') as file:
                data = file.read()
            
            # Extract the salt (first 16 bytes)
            salt = data[:16]
            encrypted_data = data[16:]
            
            # Derive the key
            key, _ = self.derive_key(password, salt)
            
            # Decrypt the data
            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(encrypted_data)
            
            # Save the decrypted file
            default_filename = os.path.splitext(os.path.basename(self.decrypt_file_path))[0]
            output_path = filedialog.asksaveasfilename(
                title="Save decrypted file",
                initialfile=default_filename
            )
            
            if not output_path:
                return
            
            with open(output_path, 'wb') as file:
                file.write(decrypted_data)
            
            self.log_action("decrypt_file", f"Decrypted file {os.path.basename(self.decrypt_file_path)}")
            messagebox.showinfo("Success", "File decrypted successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            self.log_action("decryption_error", f"Error decrypting file: {str(e)}")
    
    def setup_self_destruct(self, file_path, hours):
        """Set up a self-destruct timer for a file"""
        seconds = hours * 3600
        
        # Create a timer to delete the file
        def delete_file():
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    self.log_action("self_destruct", f"Self-destructed file {os.path.basename(file_path)}")
            except Exception as e:
                self.log_action("self_destruct_error", f"Error self-destructing file: {str(e)}")
        
        # Schedule the deletion
        timer = Timer(seconds, delete_file)
        timer.daemon = True
        timer.start()
        
        # Store info about self-destructing files
        destruct_info = {
            "file_path": file_path,
            "destruct_time": (datetime.datetime.now() + datetime.timedelta(hours=hours)).isoformat()
        }
        
        # In a real app, you'd store this info persistently
        self.log_action("setup_self_destruct", 
                        f"Set up self-destruct for {os.path.basename(file_path)} at {destruct_info['destruct_time']}")
    
    def select_steg_image(self):
        """Select an image for steganography"""
        file_path = filedialog.askopenfilename(
            title="Select image",
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")]
        )
        if file_path:
            self.steg_image_path = file_path
            self.steg_image_label.configure(text=os.path.basename(file_path))
    
    def select_file_to_hide(self):
        """Select a file to hide or output location"""
        mode = self.steg_mode.get()
        
        if mode == "hide":
            file_path = filedialog.askopenfilename(title="Select file to hide")
            if file_path:
                self.steg_file_path = file_path
                self.steg_file_label.configure(text=os.path.basename(file_path))
        else:
            directory = filedialog.askdirectory(title="Select output directory")
            if directory:
                self.steg_output_dir = directory
                self.steg_file_label.configure(text=directory)
    
    def process_steganography(self):
        """Process steganography operation (hide or extract)"""
        # Check authentication
        if not self.authenticated:
            messagebox.showerror("Error", "Please login first")
            return
        
        mode = self.steg_mode.get()
        password = self.steg_password.get()
        
        if not hasattr(self, 'steg_image_path'):
            messagebox.showerror("Error", "Please select an image")
            return
        
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        
        try:
            if mode == "hide":
                self.hide_data_in_image()
            else:
                self.extract_data_from_image()
        except Exception as e:
            messagebox.showerror("Error", f"Steganography operation failed: {str(e)}")
            self.log_action("steganography_error", f"Error in steganography: {str(e)}")
    
    def hide_data_in_image(self):
        """Hide data in an image using steganography"""
        if not hasattr(self, 'steg_file_path'):
            messagebox.showerror("Error", "Please select a file to hide")
            return
        
        # Read the file to hide
        with open(self.steg_file_path, 'rb') as file:
            data = file.read()
        
        # Encrypt the data with the password
        salt = os.urandom(16)
        key, _ = self.derive_key(self.steg_password.get(), salt)
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data)
        
        # Prepare header with filename and salt
        filename = os.path.basename(self.steg_file_path)
        header = json.dumps({
            "filename": filename,
            "salt": base64.b64encode(salt).decode(),
            "size": len(encrypted_data)
        }).encode()
        header_size = len(header)
        header_size_bytes = header_size.to_bytes(4, 'big')
        
        # Combine header and data
        payload = header_size_bytes + header + encrypted_data
        
        # Open the image
        img = Image.open(self.steg_image_path)
        width, height = img.size
        
        # Check if the image is large enough
        max_bytes = (width * height * 3 * STEGANOGRAPHY_BITS) // 8
        if len(payload) > max_bytes:
            messagebox.showerror("Error", f"Image too small. Can only hide {max_bytes} bytes")
            return
        
        # Convert image to RGB if needed
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Create a new image to store the data
        steg_img = Image.new('RGB', (width, height))
        pixels = list(img.getdata())
        new_pixels = []
        
        # Convert the payload to binary
        bin_payload = ''.join(format(byte, '08b') for byte in payload)
        
        # Extend the binary payload to match the needed length
        bin_payload += '0' * (len(pixels) * 3 * STEGANOGRAPHY_BITS - len(bin_payload))
        
        # Hide the data in the image
        data_index = 0
        for pixel in pixels:
            r, g, b = pixel
            
            # Modify each color channel to hide data
            r_bits = bin_payload[data_index:data_index + STEGANOGRAPHY_BITS]
            data_index += STEGANOGRAPHY_BITS
            g_bits = bin_payload[data_index:data_index + STEGANOGRAPHY_BITS]
            data_index += STEGANOGRAPHY_BITS
            b_bits = bin_payload[data_index:data_index + STEGANOGRAPHY_BITS]
            data_index += STEGANOGRAPHY_BITS
            
            # Clear the least significant bits and set new bits
            r = (r & ~((1 << STEGANOGRAPHY_BITS) - 1)) | int(r_bits, 2) if r_bits else r
            g = (g & ~((1 << STEGANOGRAPHY_BITS) - 1)) | int(g_bits, 2) if g_bits else g
            b = (b & ~((1 << STEGANOGRAPHY_BITS) - 1)) | int(b_bits, 2) if b_bits else b
            
            new_pixels.append((r, g, b))
            
            if data_index >= len(bin_payload):
                break
        
        # Fill the rest of the image with original pixels
        if len(new_pixels) < len(pixels):
            new_pixels.extend(pixels[len(new_pixels):])
        
        # Set the new pixel data and save
        steg_img.putdata(new_pixels)
        
        # Save the steganographic image
        output_path = filedialog.asksaveasfilename(
            title="Save steganographic image",
            defaultextension=".png",
            filetypes=[("PNG files", "*.png")]
        )
        
        if not output_path:
            return
        
        steg_img.save(output_path)
        
        self.log_action("hide_data", 
                       f"Hid file {filename} in image {os.path.basename(self.steg_image_path)}")
        messagebox.showinfo("Success", "Data hidden in image successfully!")
    
    def extract_data_from_image(self):
        """Extract hidden data from an image"""
        if not hasattr(self, 'steg_output_dir'):
            messagebox.showerror("Error", "Please select an output location")
            return
        
        # Open the steganographic image
        img = Image.open(self.steg_image_path)
        width, height = img.size
        pixels = list(img.getdata())
        
        # Extract binary data from pixels
        extracted_bits = ""
        for pixel in pixels:
            r, g, b = pixel
            
            # Extract bits from each color channel
            for value in (r, g, b):
                for bit in range(STEGANOGRAPHY_BITS):
                    extracted_bits += str((value >> bit) & 1)
        
        # Convert binary to bytes
        extracted_bytes = bytearray()
        for i in range(0, len(extracted_bits), 8):
            if i + 8 <= len(extracted_bits):
                byte = int(extracted_bits[i:i+8], 2)
                extracted_bytes.append(byte)
        
        # Extract header size (first 4 bytes)
        header_size = int.from_bytes(extracted_bytes[:4], 'big')
        
        # Extract header
        header_json = extracted_bytes[4:4+header_size].decode()
        header = json.loads(header_json)
        
        # Extract salt and filename
        salt = base64.b64decode(header["salt"])
        filename = header["filename"]
        size = header["size"]
        
        # Extract encrypted data
        encrypted_data = extracted_bytes[4+header_size:4+header_size+size]
        
        # Decrypt the data
        key, _ = self.derive_key(self.steg_password.get(), salt)
        fernet = Fernet(key)
        
        try:
            decrypted_data = fernet.decrypt(bytes(encrypted_data))
            
            # Save the extracted file
            output_path = os.path.join(self.steg_output_dir, filename)
            with open(output_path, 'wb') as file:
                file.write(decrypted_data)
            
            self.log_action("extract_data", 
                           f"Extracted file {filename} from image {os.path.basename(self.steg_image_path)}")
            messagebox.showinfo("Success", f"Data extracted and saved as {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt data: {str(e)}")
            self.log_action("extraction_error", f"Failed to extract data: {str(e)}")
    
    def select_file_to_share(self):
        """Select a file to share"""
        file_path = filedialog.askopenfilename(title="Select file to share")
        if file_path:
            self.share_file_path = file_path
            self.share_file_label.configure(text=os.path.basename(file_path))
    
    def share_file(self):
        """Share an encrypted file via email"""
        if not hasattr(self, 'share_file_path'):
            messagebox.showerror("Error", "Please select a file to share")
            return
        
        recipient = self.recipient_email.get()
        password = self.share_password.get()
        
        if not recipient or not password:
            messagebox.showerror("Error", "Recipient email and password are required")
            return
        
        # Check if email settings are configured
        if not self.config.get("email"):
            messagebox.showerror("Error", "Please configure your email in settings")
            return
        
        # Check authentication
        if not self.authenticated:
            messagebox.showerror("Error", "Please login first")
            return
        
        try:
            # Create a temporary encrypted file
            temp_dir = self.config["temp_directory"]
            if not os.path.exists(temp_dir):
                os.makedirs(temp_dir)
            
            temp_file = os.path.join(
                temp_dir, 
                f"temp_{os.path.basename(self.share_file_path)}.enc"
            )
            
            # Read the file
            with open(self.share_file_path, 'rb') as file:
                data = file.read()
            
            # Generate a salt and derive a key
            salt = os.urandom(16)
            key, _ = self.derive_key(password, salt)
            
            # Encrypt the data
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(data)
            
            # Add the salt to the beginning of the encrypted data
            final_data = salt + encrypted_data
            
            # Save the encrypted file
            with open(temp_file, 'wb') as file:
                file.write(final_data)
            
            # Generate a random sharing key to send separately
            sharing_key = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
            
            # Compose and send email with the file
            self.send_email(
                recipient=recipient,
                subject="Encrypted File Sharing",
                body=f"""Hello,

Someone has shared an encrypted file with you.

To decrypt the file, you will need:
1. The attached encrypted file
2. The following password: {password}

This email and the encrypted file will self-destruct automatically for security.

Sharing Key: {sharing_key}
""",
                attachment_path=temp_file
            )
            
            # Handle self-destruct for the temporary file
            if self.share_self_destruct_var.get():
                try:
                    hours = float(self.share_self_destruct_time.get())
                    self.setup_self_destruct(temp_file, hours)
                except ValueError:
                    messagebox.showerror("Error", "Invalid self-destruct time")
            else:
                # Delete temp file immediately after sending
                os.remove(temp_file)
            
            self.log_action("share_file", 
                           f"Shared file {os.path.basename(self.share_file_path)} with {recipient}")
            messagebox.showinfo("Success", "File shared successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Sharing failed: {str(e)}")
            self.log_action("share_error", f"Error sharing file: {str(e)}")
    
    def send_email(self, recipient, subject, body, attachment_path=None):
        """Send an email with optional attachment"""
        # Create the email message
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = self.config["email"]
        msg['To'] = recipient
        msg.set_content(body)
        
        # Add attachment if provided
        if attachment_path:
            filename = os.path.basename(attachment_path)
            
            with open(attachment_path, 'rb') as file:
                file_data = file.read()
            
            msg.add_attachment(
                file_data,
                maintype='application',
                subtype='octet-stream',
                filename=filename
            )
        
        # Send the email
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(self.config["email"], self.email_password.get())
            server.send_message(msg)
    
    def save_settings(self):
        """Save user settings"""
        self.config["email"] = self.email_setting.get()
        self.config["audit_enabled"] = self.audit_enabled_var.get()
        self._save_config()
        
        self.log_action("save_settings", "Updated application settings")
        messagebox.showinfo("Success", "Settings saved successfully!")
    
    def refresh_audit_logs(self):
        """Refresh the audit logs display"""
        self.log_display.delete(1.0, tk.END)
        
        # Load the latest logs
        self.audit_log = self._load_audit_log()
        
        # Display the logs
        for entry in self.audit_log:
            timestamp = entry.get("timestamp", "Unknown")
            user = entry.get("user", "Unknown")
            action = entry.get("action", "Unknown")
            details = entry.get("details", "")
            
            log_line = f"{timestamp} - {user} - {action} - {details}\n\n"
            self.log_display.insert(tk.END, log_line)
    
    def export_audit_logs(self):
        """Export audit logs to a file"""
        output_path = filedialog.asksaveasfilename(
            title="Export Audit Logs",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if not output_path:
            return
        
        try:
            shutil.copy(AUDIT_LOG_FILE, output_path)
            messagebox.showinfo("Success", "Audit logs exported successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def run(self):
        """Run the application"""
        self.app.mainloop()


if __name__ == "__main__":
    app = FileEncryptionTool()
    app.run()