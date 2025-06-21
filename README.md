#Security Footage Searcher V.3.21

import os
import sys
import sqlite3
import bcrypt
import json
import hashlib
import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
from cryptography.fernet import Fernet
import shutil
import threading
import schedule
import re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import time
import traceback
import math

CURRENT_USER = None
home_path = os.path.expanduser("~")
DEFAULT_PATH = os.path.join(home_path, "SecurityCamera")
CONFIG_FILE = os.path.expanduser("~/.security_config.json")

# Expanded list of obj categories based on the detection code
# Others is for unknown categories during test phase
OBJECT_CATEGORIES = [
    "Person", 
    "Vehicle", 
    "Cat", 
    "Dog", 
    "Bicycle", 
    "Other"
]

class SecurityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Security Footage Searcher By ARIK COOL")
        # Set initial login window size
        self.root.geometry("800x800")
        self.root.configure(bg="#f0f0f0")
        
        # Store references to wastefull collection
        self.thumbnail_images = []
        
        try:
            self.initialize_system()
            
            if self.check_existing_user():
                self.show_login_screen()
            else:
                self.show_create_account_screen()
        except Exception as e:
            messagebox.showerror("Initialization Error", f"Error initializing application: {str(e)}")
            print(f"Initialization error: {str(e)}")
            print(traceback.format_exc())
    
    def save_decrypted_video(self, file_path, filename):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT encryption_keys.key_value, videos.original_filename 
                FROM videos 
                JOIN encryption_keys ON videos.encryption_key_id = encryption_keys.id
                WHERE videos.file_path = ?
            """, (file_path,))
            
            result = cursor.fetchone()
            conn.close()
            
            if not result:
                messagebox.showerror("Error", "Could not find encryption key for this video")
                return
            
            key, original_filename = result
            
            # Use the default style for file dialog
            save_path = filedialog.asksaveasfilename(
                initialfile=original_filename,
                defaultextension=".mp4",
                filetypes=[("Video files", "*.mp4"), ("All files", "*.*")]
            )
            
            if not save_path:
                return
            
            # Show decryption status with a simple label (no progress bar)
            progress_window = tk.Toplevel(self.root)
            progress_window.title("Saving Decrypted Video")
            progress_window.geometry("350x80")
            progress_window.transient(self.root)
            progress_window.resizable(False, False)
            progress_window.configure(bg="white")
            
            # Center the progress window
            progress_window.geometry("+{}+{}".format(
                self.root.winfo_rootx() + (self.root.winfo_width() // 2 - 175),
                self.root.winfo_rooty() + (self.root.winfo_height() // 2 - 40)
            ))
            
            progress_label = tk.Label(
                progress_window,
                text="Decrypting and saving video, please wait...",
                font=("Arial", 12),
                pady=20,
                bg="white"
            )
            progress_label.pack(fill="both", expand=True)
            
            # Update UI
            self.root.update_idletasks()
            
            try:
                self.decrypt_file(file_path, save_path, key)
                progress_window.destroy()
                messagebox.showinfo("Success", "Video saved successfully!")
            except Exception as e:
                progress_window.destroy()
                raise e
            
        except Exception as e:
            messagebox.showerror("Save Error", f"An error occurred: {str(e)}")
            print(f"Save decrypted video error: {str(e)}")
            print(traceback.format_exc())
    
    def decrypt_file(self, input_path, output_path, key):
        try:
            # Check if key is JSON format
            try:
                key_data = json.loads(key)
                
                if "type" in key_data and key_data["type"] == "aes":
                    # Use AES decryption for the new format
                    try:
                        key_bytes = base64.b64decode(key_data["key"])
                        iv_bytes = base64.b64decode(key_data["iv"])
                        
                        with open(input_path, 'rb') as f:
                            # Read the full file content
                            data = f.read()
                            
                            # The IV is stored at the beginning of the file
                            iv_from_file = data[:16]
                            encrypted_data = data[16:]
                        
                        # Create the cipher with the file IV
                        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_from_file), backend=default_backend())
                        decryptor = cipher.decryptor()
                        
                        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
                        
                        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
                        decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
                        
                        with open(output_path, 'wb') as f:
                            f.write(decrypted_data)
                        
                        return output_path
                    except Exception as aes_error:
                        print(f"AES decryption error: {str(aes_error)}")
                        print(traceback.format_exc())
                        raise aes_error
                else:
                    # Try Fernet decryption as fallback
                    raise ValueError("Not an AES key")
            except (json.JSONDecodeError, ValueError):
                # Try Fernet decryption (legacy format)
                try:
                    cipher = Fernet(key.encode('utf-8'))
                    
                    with open(input_path, 'rb') as f:
                        encrypted_data = f.read()
                    
                    decrypted_data = cipher.decrypt(encrypted_data)
                    
                    with open(output_path, 'wb') as f:
                        f.write(decrypted_data)
                    
                    return output_path
                except Exception as fernet_error:
                    print(f"Fernet decryption error: {str(fernet_error)}")
                    print(traceback.format_exc())
                    
                    # Try AES decryption as a last resort
                    try:
                        with open(input_path, 'rb') as f:
                            data = f.read()
                            iv = data[:16]
                            encrypted_data = data[16:]
                        
                        # Try with a standard AES decryption using the key directly
                        key_bytes = base64.b64decode(key)
                        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
                        decryptor = cipher.decryptor()
                        
                        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
                        
                        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
                        decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
                        
                        with open(output_path, 'wb') as f:
                            f.write(decrypted_data)
                        
                        return output_path
                    except Exception as last_error:
                        # If all decryption methods fail
                        raise Exception(f"Failed to decrypt: Fernet error: {str(fernet_error)}, Last error: {str(last_error)}")
        except Exception as e:
            print(f"Decryption failed: {str(e)}")
            print(traceback.format_exc())
            raise e
    
    def logout(self):
        # Unbind the Enter key event
        self.root.unbind("<Return>")
        
        # Clear the quick buffer
        for filename in os.listdir(self.folders['quick_buffer']):
            file_path = os.path.join(self.folders['quick_buffer'], filename)
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path)
            except Exception as e:
                print(f"Error clearing quick buffer: {str(e)}")
                print(traceback.format_exc())
        
        global CURRENT_USER
        CURRENT_USER = None
        
        self.show_login_screen()
    
    def log_error(self, title, message):
        messagebox.showerror(title, message)


    
    def initialize_system(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    self.base_path = config.get('base_path', DEFAULT_PATH)
            else:
                self.base_path = DEFAULT_PATH
            
            self.folders = {
                'main': self.base_path,
                'encrypted_videos': os.path.join(self.base_path, 'EncryptedVideos'),
                'quick_buffer': os.path.join(self.base_path, 'QuickBuffer'),
                'metadata': os.path.join(self.base_path, 'MetaData'),
                'user_data': os.path.join(self.base_path, 'UserData'),
                'thumbnails': os.path.join(self.base_path, 'Thumbnails')
            }
            
            for folder in self.folders.values():
                if not os.path.exists(folder):
                    try:
                        os.makedirs(folder)
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to create folder structure: {str(e)}")
                        sys.exit(1)
            
            self.db_path = os.path.join(self.folders['metadata'], 'security_footage.db')
            self.initialize_database()
        except Exception as e:
            print(f"System initialization error: {str(e)}")
            print(traceback.format_exc())
            raise e
    
    def initialize_database(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS videos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                encryption_key_id TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                detected_objects TEXT,
                thumbnail_path TEXT
            )
            ''')
            
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS encryption_keys (
                id TEXT PRIMARY KEY,
                key_value TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            conn.commit()
        except Exception as e:
            messagebox.showerror("Database Error", f"Failed to initialize database: {str(e)}")
            print(f"Database initialization error: {str(e)}")
            print(traceback.format_exc())
            sys.exit(1)
        finally:
            conn.close()
    
    def check_existing_user(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            count = cursor.fetchone()[0]
            conn.close()
            return count > 0
        except Exception as e:
            print(f"User check error: {str(e)}")
            print(traceback.format_exc())
            return False
    
    def clear_frame(self):
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def show_login_screen(self):
        # Keep login screen at 800x800
        self.root.geometry("700x600")
        self.clear_frame()
        
        login_frame = tk.Frame(self.root, bg="#f0f0f0", padx=20, pady=20)
        login_frame.pack(expand=True)
        
        # White background box
        bg_box = tk.Frame(login_frame, bg="white", padx=20, pady=20)
        bg_box.pack(expand=True)
        
        title_label = tk.Label(
            bg_box, 
            text="Security Footage Searcher BY ARIK COOL", 
            font=("Arial", 18, "bold"),
            bg="white", 
            fg="#333333"
        )
        title_label.pack(pady=20)
        
        username_label = tk.Label(
            bg_box, 
            text="Username:", 
            font=("Arial", 14),
            bg="white", 
            fg="#333333"
        )
        username_label.pack(anchor="w", pady=(10, 5))
        
        self.username_entry = tk.Entry(bg_box, font=("Arial", 14), width=30)
        self.username_entry.pack(pady=(0, 10), ipady=5)
        
        password_label = tk.Label(
            bg_box, 
            text="Password:", 
            font=("Arial", 14),
            bg="white", 
            fg="#333333"
        )
        password_label.pack(anchor="w", pady=(10, 5))
        
        self.password_entry = tk.Entry(bg_box, font=("Arial", 14), width=30, show="*")
        self.password_entry.pack(pady=(0, 20), ipady=5)
        # Bind Enter key to login function
        self.password_entry.bind("<Return>", lambda event: self.validate_login())
        
        login_button = tk.Button(
            bg_box,
            text="Login",
            font=("Arial", 14, "bold"),
            bg="#4CAF50",
            fg="white",
            padx=20,
            pady=10,
            command=self.validate_login
        )
        login_button.pack(pady=10)
        
        # Set focus to username entry
        self.username_entry.focus_set()
    
    def show_create_account_screen(self):
        # Keep account creation screen at 800x800
        self.root.geometry("800x800")
        self.clear_frame()
        
        create_account_frame = tk.Frame(self.root, bg="#f0f0f0", padx=20, pady=20)
        create_account_frame.pack(expand=True)
        
        # White background box
        bg_box = tk.Frame(create_account_frame, bg="white", padx=20, pady=20)
        bg_box.pack(expand=True)
        
        title_label = tk.Label(
            bg_box, 
            text="Create Account", 
            font=("Arial", 24, "bold"),
            bg="white", 
            fg="#333333"
        )
        title_label.pack(pady=20)
        
        username_label = tk.Label(
            bg_box, 
            text="Username (at least 5 characters):", 
            font=("Arial", 14),
            bg="white", 
            fg="#333333"
        )
        username_label.pack(anchor="w", pady=(10, 5))
        
        self.username_entry_ca = tk.Entry(bg_box, font=("Arial", 14), width=30)
        self.username_entry_ca.pack(pady=(0, 10), ipady=5)
        
        password_label = tk.Label(
            bg_box, 
            text="Password (at least 8 characters with numbers and special chars):", 
            font=("Arial", 14),
            bg="white", 
            fg="#333333"
        )
        password_label.pack(anchor="w", pady=(10, 5))
        
        self.password_entry_ca = tk.Entry(bg_box, font=("Arial", 14), width=30, show="*")
        self.password_entry_ca.pack(pady=(0, 10), ipady=5)
        
        confirm_password_label = tk.Label(
            bg_box, 
            text="Confirm Password:", 
            font=("Arial", 14),
            bg="white", 
            fg="#333333"
        )
        confirm_password_label.pack(anchor="w", pady=(10, 5))
        
        self.confirm_password_entry_ca = tk.Entry(bg_box, font=("Arial", 14), width=30, show="*")
        self.confirm_password_entry_ca.pack(pady=(0, 20), ipady=5)
        # Bind Enter key to create account function
        self.confirm_password_entry_ca.bind("<Return>", lambda event: self.validate_create_account())
        
        create_account_button = tk.Button(
            bg_box,
            text="Create Account",
            font=("Arial", 14, "bold"),
            bg="#4CAF50",
            fg="white",
            padx=20,
            pady=10,
            command=self.validate_create_account
        )
        create_account_button.pack(pady=10)
        
        # Set focus to username entry
        self.username_entry_ca.focus_set()
    
    def validate_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            self.log_error("Login Error", "Username and password are required")
            return
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            conn.close()
            
            if result and bcrypt.checkpw(password.encode('utf-8'), result[0].encode('utf-8')):
                global CURRENT_USER
                CURRENT_USER = username
                self.show_home_screen()
            else:
                self.log_error("Login Error", "Invalid username or password")
        except Exception as e:
            self.log_error("Login Error", f"An error occurred: {str(e)}")
            print(f"Login error: {str(e)}")
            print(traceback.format_exc())
    
    def validate_create_account(self):
        username = self.username_entry_ca.get()
        password = self.password_entry_ca.get()
        confirm_password = self.confirm_password_entry_ca.get()
        
        if len(username) < 5:
            self.log_error("Account Creation Error", "Username must be at least 5 characters")
            return
        
        if len(password) < 8:
            self.log_error("Account Creation Error", "Password must be at least 8 characters")
            return
        
        if not any(char.isdigit() for char in password):
            self.log_error("Account Creation Error", "Password must contain at least one number")
            return
        
        if not any(char in "!@#$%^&*()_+-=[]{};':\"\\|,.<>/?" for char in password):
            self.log_error("Account Creation Error", "Password must contain at least one special character")
            return
        
        if password != confirm_password:
            self.log_error("Account Creation Error", "Passwords do not match")
            return
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
            if cursor.fetchone()[0] > 0:
                self.log_error("Account Creation Error", "Username already exists")
                conn.close()
                return
            
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", 
                          (username, hashed_password))
            conn.commit()
            conn.close()
            
            global CURRENT_USER
            CURRENT_USER = username
            
            self.show_storage_location_screen()
            
        except Exception as e:
            self.log_error("Account Creation Error", f"An error occurred: {str(e)}")
            print(f"Account creation error: {str(e)}")
            print(traceback.format_exc())
    
    def show_storage_location_screen(self):
        # Keep storage location screen at 800x800
        self.root.geometry("800x800")
        self.clear_frame()
        
        location_frame = tk.Frame(self.root, bg="#f0f0f0", padx=20, pady=20)
        location_frame.pack(expand=True)
        
        title_label = tk.Label(
            location_frame, 
            text="Set Storage Location", 
            font=("Arial", 24, "bold"),
            bg="#f0f0f0", 
            fg="#333333"
        )
        title_label.pack(pady=20)
        
        info_label = tk.Label(
            location_frame, 
            text="Select a location to store security footage files or use the default location.",
            font=("Arial", 14),
            bg="#f0f0f0", 
            fg="#333333",
            wraplength=500
        )
        info_label.pack(pady=10)
        
        location_var = tk.StringVar(value=self.base_path)
        
        location_frame_inner = tk.Frame(location_frame, bg="#f0f0f0")
        location_frame_inner.pack(fill="x", pady=10)
        
        location_entry = tk.Entry(
            location_frame_inner, 
            font=("Arial", 14), 
            width=40, 
            textvariable=location_var
        )
        location_entry.pack(side="left", padx=(0, 10), ipady=5)
        # Bind Enter key to validate storage location
        location_entry.bind("<Return>", lambda event: self.validate_storage_location(location_var.get()))
        
        browse_button = tk.Button(
            location_frame_inner,
            text="Browse",
            font=("Arial", 12),
            command=lambda: self.browse_directory(location_var)
        )
        browse_button.pack(side="left")
        
        buttons_frame = tk.Frame(location_frame, bg="#f0f0f0")
        buttons_frame.pack(pady=20)
        
        default_button = tk.Button(
            buttons_frame,
            text="Use Default",
            font=("Arial", 14),
            padx=15,
            pady=8,
            command=lambda: self.set_storage_location(DEFAULT_PATH)
        )
        default_button.pack(side="left", padx=10)
        
        confirm_button = tk.Button(
            buttons_frame,
            text="Confirm Location",
            font=("Arial", 14, "bold"),
            bg="#4CAF50",
            fg="white",
            padx=15,
            pady=8,
            command=lambda: self.validate_storage_location(location_var.get())
        )
        confirm_button.pack(side="left", padx=10)
        
        # Set focus to location entry
        location_entry.focus_set()
    
    def browse_directory(self, location_var):
        directory = filedialog.askdirectory(initialdir=location_var.get())
        if directory:
            location_var.set(directory)
    
    def validate_storage_location(self, path):
        if not path:
            self.log_error("Error", "Please select a storage location")
            return
        
        if not os.path.exists(path):
            try:
                os.makedirs(path)
            except Exception as e:
                self.log_error("Error", f"Cannot create directory: {str(e)}")
                return
        
        try:
            test_file = os.path.join(path, ".test_write")
            with open(test_file, 'w') as f:
                f.write("test")
            os.remove(test_file)
        except Exception as e:
            self.log_error("Error", f"Cannot write to selected directory: {str(e)}")
            return
        
        self.set_storage_location(path)
    
    def set_storage_location(self, path):
        try:
            self.base_path = path
            
            self.folders = {
                'main': self.base_path,
                'encrypted_videos': os.path.join(self.base_path, 'EncryptedVideos'),
                'quick_buffer': os.path.join(self.base_path, 'QuickBuffer'),
                'metadata': os.path.join(self.base_path, 'MetaData'),
                'user_data': os.path.join(self.base_path, 'UserData'),
                'thumbnails': os.path.join(self.base_path, 'Thumbnails')
            }
            
            for folder in self.folders.values():
                if not os.path.exists(folder):
                    os.makedirs(folder)
            
            with open(CONFIG_FILE, 'w') as f:
                json.dump({'base_path': self.base_path}, f)
            
            old_db_path = self.db_path
            self.db_path = os.path.join(self.folders['metadata'], 'security_footage.db')
            
            if old_db_path != self.db_path and os.path.exists(old_db_path):
                shutil.copy2(old_db_path, self.db_path)
            
            messagebox.showinfo("Success", "Storage location set successfully!")
            self.show_home_screen()
            
        except Exception as e:
            self.log_error("Error", f"Failed to set storage location: {str(e)}")
            print(f"Storage location error: {str(e)}")
            print(traceback.format_exc())
    
    def show_home_screen(self):
        # Resize to larger window for main application (1500x1000)
        self.root.geometry("1450x880")
        self.clear_frame()
        self.thumbnail_images = []
        
        header_frame = tk.Frame(self.root, bg="#D20A00", height=80)
        header_frame.pack(fill="x")
        header_frame.pack_propagate(False)
        
        content_frame = tk.Frame(self.root, bg="#f0f0f0")
        content_frame.pack(fill="both", expand=True)
        
        title_label = tk.Label(
            header_frame, 
            text="Security Footage Searcher BY ARIK COOL", 
            font=("Arial", 24, "bold"),
            bg="#D20A00", 
            fg="white"
        )
        title_label.pack(side="left", padx=20, pady=20)
        
        logout_button = tk.Button(
            header_frame,
            text="Logout",
            font=("Arial", 14),
            bg="#f44336",
            fg="white",
            command=self.logout
        )
        logout_button.pack(side="right", padx=20, pady=20)
        
        search_frame = tk.Frame(content_frame, bg="#f0f0f0", padx=20, pady=20)
        search_frame.pack(fill="x")
        
        search_title = tk.Label(
            search_frame, 
            text="Search Security Footage", 
            font=("Arial", 20, "bold"),
            bg="#f0f0f0", 
            fg="#333333"
        )
        search_title.grid(row=0, column=0, columnspan=7, sticky="w", pady=(0, 20))
        
        # Create a row for date selection
        date_frame = tk.Frame(search_frame, bg="#f0f0f0")
        date_frame.grid(row=1, column=0, columnspan=7, sticky="w", pady=5)
        
        date_label = tk.Label(
            date_frame, 
            text="Date:", 
            font=("Arial", 14),
            bg="#f0f0f0", 
            fg="#333333"
        )
        date_label.pack(side="left", padx=(0, 10))
        
        today = datetime.date.today()
        
        day_label = tk.Label(date_frame, text="Day:", bg="#f0f0f0", font=("Arial", 14))
        day_label.pack(side="left", padx=(0, 5))
        
        self.day_var = tk.StringVar(value=str(today.day))
        self.day_spinbox = tk.Spinbox(date_frame, from_=1, to=31, width=5, textvariable=self.day_var, font=("Arial", 14))
        self.day_spinbox.pack(side="left", padx=(0, 10))
        
        month_label = tk.Label(date_frame, text="Month:", bg="#f0f0f0", font=("Arial", 14))
        month_label.pack(side="left", padx=(0, 5))
        
        self.month_var = tk.StringVar(value=str(today.month))
        self.month_spinbox = tk.Spinbox(date_frame, from_=1, to=12, width=5, textvariable=self.month_var, font=("Arial", 14))
        self.month_spinbox.pack(side="left", padx=(0, 10))
        
        year_label = tk.Label(date_frame, text="Year:", bg="#f0f0f0", font=("Arial", 14))
        year_label.pack(side="left", padx=(0, 5))
        
        self.year_var = tk.StringVar(value=str(today.year))
        self.year_spinbox = tk.Spinbox(date_frame, from_=2020, to=2100, width=8, textvariable=self.year_var, font=("Arial", 14))
        self.year_spinbox.pack(side="left", padx=(0, 10))
        
        # Move search button to the right
        search_button = tk.Button(
            date_frame,
            text="Search",
            font=("Arial", 14, "bold"),
            bg="#4CAF50",
            fg="white",
            padx=25,
            pady=8,
            command=self.search_videos
        )
        search_button.pack(side="right", padx=(20, 0))
        
        # Create a row for object filters
        filter_frame = tk.Frame(search_frame, bg="#f0f0f0")
        filter_frame.grid(row=2, column=0, columnspan=7, sticky="w", pady=10)
        
        objects_label = tk.Label(
            filter_frame, 
            text="Objects Detected:", 
            font=("Arial", 14),
            bg="#f0f0f0", 
            fg="#333333"
        )
        objects_label.pack(side="left", padx=(0, 10))
        
        # Use the expanded list of object categories
        self.object_vars = {}
        
        for obj in OBJECT_CATEGORIES:
            # Set default to True (checked) for all object filters
            var = tk.BooleanVar(value=False)
            self.object_vars[obj] = var
            check = tk.Checkbutton(filter_frame, text=obj, variable=var, bg="#f0f0f0", font=("Arial", 14))
            check.pack(side="left", padx=10)
        
        # Bind Enter key to search function
        self.root.bind("<Return>", lambda event: self.search_videos())
        
        results_frame = tk.Frame(content_frame, bg="white", padx=20, pady=20)
        results_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        results_label = tk.Label(
            results_frame, 
            text="Search Results", 
            font=("Arial", 18, "bold"),
            bg="white", 
            fg="#333333"
        )
        results_label.pack(anchor="w", pady=(0, 10))
        
        # Modern scrollable frame for results with simple grey scrollbar
        scrollable_frame = tk.Frame(results_frame)
        scrollable_frame.pack(fill="both", expand=True)
        
        # Create a canvas with a simple scrollbar (like Chrome)
        self.results_canvas = tk.Canvas(scrollable_frame, bg="white", highlightthickness=0)
        self.results_canvas.pack(side="left", fill="both", expand=True)
        
        # Simple grey scrollbar style
        scrollbar_style = ttk.Style()
        scrollbar_style.configure("Simple.Vertical.TScrollbar", 
                                 background="#c1c1c1", 
                                 troughcolor="#f1f1f1", 
                                 borderwidth=0,
                                 relief="flat",
                                 arrowsize=12)
        
        scrollbar = ttk.Scrollbar(scrollable_frame, orient="vertical", 
                                  command=self.results_canvas.yview,
                                  style="Simple.Vertical.TScrollbar")
        scrollbar.pack(side="right", fill="y")
        
        self.results_canvas.configure(yscrollcommand=scrollbar.set)
        
        self.results_container = tk.Frame(self.results_canvas, bg="white")
        self.results_canvas.create_window((0, 0), window=self.results_container, anchor="nw")
        
        # Configure the canvas to adjust with the frame
        self.results_container.bind("<Configure>", lambda e: self.results_canvas.configure(
            scrollregion=self.results_canvas.bbox("all"),
            width=e.width
        ))
        
        # Add mouse wheel scrolling
        self.results_canvas.bind_all("<MouseWheel>", lambda e: self.results_canvas.yview_scroll(int(-1*(e.delta/120)), "units"))
        
        # Automatically display all videos for today when the home screen loads
        self.search_videos()
    
    def search_videos(self):
        try:
            # Clear previous results
            for widget in self.results_container.winfo_children():
                widget.destroy()
            
            # Clear thumbnail references
            self.thumbnail_images = []
            
            day = self.day_spinbox.get()
            month = self.month_spinbox.get()
            year = self.year_spinbox.get()
            
            try:
                search_date = datetime.date(int(year), int(month), int(day))
                date_str = search_date.strftime("%Y-%m-%d")
            except ValueError:
                messagebox.showerror("Invalid Date", "Please enter a valid date")
                return
            
            conn = sqlite3.connect(self.db_path)
            # Enable regular expressions for SQLite
            conn.create_function("REGEXP", 2, lambda x, y: 1 if re.search(x, y) else 0)
            cursor = conn.cursor()
            
            # Query that works with both the old format and new JSON metadata format
            query = """
            SELECT id, filename, file_path, created_at, detected_objects, thumbnail_path 
            FROM videos 
            WHERE DATE(created_at) = ?
            """
            params = [date_str]
            
            selected_objects = [obj for obj, selected in self.object_vars.items() if selected.get()]
            if selected_objects:
                object_conditions = []
                for obj in selected_objects:
                    # Handle different patterns for various object types
                    if obj == "Vehicle":
                        # Handle both "Vehicle" and "Vehicle (specific type)"
                        object_conditions.append(f"""(
                            detected_objects LIKE '%{obj}%' OR 
                            detected_objects LIKE '%"standardized_label": "Vehicle%' OR
                            detected_objects REGEXP '"label"[^}}]+"Vehicle\\s+\\([^)]+\\)"'
                        )""")
                    elif obj == "Cat" or obj == "Dog":
                        # Look for specific animal types and general Animal category
                        object_conditions.append(f"""(
                            detected_objects LIKE '%{obj}%' OR 
                            detected_objects LIKE '%"original_label": "{obj}"%' OR
                            detected_objects REGEXP '"label"[^}}]+"Animal\\s+\\({obj}\\)"'
                        )""")
                    elif obj == "Bicycle":
                        # Look for bicycle specifically
                        object_conditions.append(f"""(
                            detected_objects LIKE '%{obj}%' OR 
                            detected_objects LIKE '%"original_label": "{obj}"%' OR
                            detected_objects REGEXP '"label"[^}}]+"Vehicle\\s+\\({obj}\\)"'
                        )""")
                        
                        
                        '''
                    elif obj == "Luggage":
                        # Look for luggage items
                        object_conditions.append(f"""(
                            detected_objects LIKE '%{obj}%' OR 
                            detected_objects LIKE '%"standardized_label": "Luggage%' OR
                            detected_objects REGEXP '"label"[^}}]+"Luggage\\s+\\([^)]+\\)"'
                        )""")
                        
                        '''
                    
                    else:
                        # General case for other object types
                        object_conditions.append(f"""(
                            detected_objects LIKE '%{obj}%' OR 
                            detected_objects LIKE '%"label": "{obj}"%' OR
                            detected_objects LIKE '%"standardized_label": "{obj}"%'
                        )""")

                query += " AND (" + " AND ".join(object_conditions) + ")"
            
            cursor.execute(query, params)
            results = cursor.fetchall()
            conn.close()
            
            if not results:
                no_results_label = tk.Label(
                    self.results_container, 
                    text="No videos match your search criteria.", 
                    font=("Arial", 14),
                    bg="white", 
                    fg="#666666",
                    padx=20,
                    pady=40
                )
                no_results_label.pack(fill="both", expand=True)
                return
            
            # Create a grid layout for results (2 items per row)
            grid_frame = tk.Frame(self.results_container, bg="white")
            grid_frame.pack(fill="both", expand=True)
            
            # Calculate items per row (2) and total rows needed
            items_per_row = 2
            total_rows = math.ceil(len(results) / items_per_row)
            
            # Configure grid columns to have equal width
            for i in range(items_per_row):
                grid_frame.columnconfigure(i, weight=1)
            
            # Add results to the grid
            for i, (id, filename, file_path, created_at, detected_objects, thumbnail_path) in enumerate(results):
                # Calculate row and column for grid layout
                row = i // items_per_row
                col = i % items_per_row
                
                # Create a frame for each result with more space
                result_frame = tk.Frame(grid_frame, bg="white", padx=20, pady=20)  # Increased padding
                result_frame.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")
                result_frame.config(highlightbackground="#ddd", highlightthickness=1)
                
                display_name = os.path.splitext(os.path.basename(filename))[0]
                
                timestamp = datetime.datetime.strptime(created_at, "%Y-%m-%d %H:%M:%S")
                time_str = timestamp.strftime("%H:%M:%S")
                
                # Create a container for thumbnail and info side by side
                content_frame = tk.Frame(result_frame, bg="white")
                content_frame.pack(fill="both", expand=True, padx=5, pady=5)
                
                # Fixed thumbnail loading with larger thumbnails
                thumb_loaded = False
                
                # Find the thumbnail file
                thumb_filename = None
                thumb_path = None
                
                # First try: exact file path from database
                if thumbnail_path and os.path.exists(thumbnail_path):
                    thumb_path = thumbnail_path
                
                # Second try: Get the base name from the video filename
                if not thumb_path:
                    base_name = os.path.splitext(os.path.basename(filename))[0]
                    thumb_filename = f"{base_name}_thumb.jpg"
                    possible_path = os.path.join(self.folders['thumbnails'], thumb_filename)
                    
                    if os.path.exists(possible_path):
                        thumb_path = possible_path
                
                # Third try: Look for files in the thumbnails directory with similar patterns
                if not thumb_path:
                    for file in os.listdir(self.folders['thumbnails']):
                        if file.startswith(base_name) and file.endswith('.jpg'):
                            thumb_path = os.path.join(self.folders['thumbnails'], file)
                            break
                
                if thumb_path:
                    try:
                        # Using the successful loading method with larger size
                        img = Image.open(thumb_path).convert('RGB')
                        img = img.resize((300, 180), Image.Resampling.LANCZOS)  # Increased size
                        photo = ImageTk.PhotoImage(img)
                        
                        # Save reference to prevent garbage collection
                        self.thumbnail_images.append(photo)
                        
                        # Create and place the thumbnail
                        thumbnail_label = tk.Label(content_frame, image=photo, bg="white")
                        thumbnail_label.grid(row=0, column=0, rowspan=3, padx=(0, 20))  # Increased padding
                        thumb_loaded = True
                    except Exception as e:
                        print(f"Error loading thumbnail {thumb_path}: {str(e)}")
                
                # Create a placeholder if no thumbnail was loaded
                if not thumb_loaded:
                    placeholder = tk.Frame(content_frame, width=300, height=180, bg="#f0f0f0")  # Increased size
                    placeholder.grid(row=0, column=0, rowspan=3, padx=(0, 20))
                    
                    # Add a camera icon or text to the placeholder
                    placeholder_label = tk.Label(
                        placeholder, 
                        text="No Thumbnail",
                        font=("Arial", 12),  # Larger font
                        bg="#f0f0f0", 
                        fg="#666666"
                    )
                    placeholder_label.place(relx=0.5, rely=0.5, anchor="center")
                
                # Video information with more space
                info_frame = tk.Frame(content_frame, bg="white", height=180)  # Match thumbnail height
                info_frame.grid(row=0, column=1, sticky="nw")
                
                filename_label = tk.Label(
                    info_frame, 
                    text=display_name, 
                    font=("Arial", 14, "bold"),
                    bg="white", 
                    fg="#333333",
                    anchor="w"
                )
                filename_label.pack(anchor="w")
                
                time_label = tk.Label(
                    info_frame, 
                    text=f"Time: {time_str}", 
                    font=("Arial", 12),
                    bg="white", 
                    fg="#666666",
                    anchor="w"
                )
                time_label.pack(anchor="w")
                
                # Parse and display detected objects from metadata with more space
                if detected_objects:
                    try:
                        # Try to parse as JSON first (new format)
                        metadata = json.loads(detected_objects)
                        
                        # Check if it's the new metadata format with object_types
                        if isinstance(metadata, dict) and "object_types" in metadata:
                            objects_list = metadata["object_types"]
                            objects_text = "Objects: " + ", ".join(objects_list)
                        # Check if it's a list of detection records (old format)
                        elif isinstance(metadata, list):
                            # Extract unique labels from the detection records
                            labels = []
                            for detection in metadata:
                                if isinstance(detection, dict) and "label" in detection:
                                    if detection["label"] not in labels:
                                        labels.append(detection["label"])
                            objects_text = "Objects: " + ", ".join(labels)
                        else:
                            # Fallback for other JSON formats
                            objects_text = "Objects: " + str(metadata)
                    except (json.JSONDecodeError, TypeError):
                        # Fall back to simple text display for legacy format
                        objects_text = "Objects: " + detected_objects
                    
                    objects_label = tk.Label(
                        info_frame, 
                        text=objects_text, 
                        font=("Arial", 12),
                        bg="white", 
                        fg="#666666",
                        anchor="w",
                        wraplength=300,
                        width=30,
                        height = 4,  # Increased from 350 to 400 for more text
                        justify="left"  # Ensure text is left-aligned
                    )
                    objects_label.pack(anchor="w", fill="x", pady=(5, 0))  # Added padding
                
                # Action buttons
                button_frame = tk.Frame(content_frame, bg="white")
                button_frame.grid(row=2, column=1, sticky="sw", pady=(10, 0))
                
                # Modern styled buttons
                play_button = tk.Button(
                    button_frame,
                    text="Play",
                    font=("Arial", 12, "bold"),
                    bg="#4CAF50",
                    fg="white",
                    padx=15,
                    pady=5,
                    relief=tk.FLAT,
                    command=lambda path=file_path: self.play_video(path)
                )
                play_button.pack(side="left", padx=(0, 10))
                
                save_button = tk.Button(
                    button_frame,
                    text="Save",
                    font=("Arial", 12),
                    bg="#2196F3",
                    fg="white",
                    padx=15,
                    pady=5,
                    relief=tk.FLAT,
                    command=lambda path=file_path, name=filename: self.save_decrypted_video(path, name)
                )
                save_button.pack(side="left")
    
        except Exception as e:
            print(f"Search error details: {str(e)}")
            print(traceback.format_exc())
            messagebox.showerror("Search Error", f"An error occurred: {str(e)}")
    
    def play_video(self, file_path):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT encryption_keys.key_value 
                FROM videos 
                JOIN encryption_keys ON videos.encryption_key_id = encryption_keys.id
                WHERE videos.file_path = ?
            """, (file_path,))
            
            result = cursor.fetchone()
            conn.close()
            
            if not result:
                messagebox.showerror("Error", "Could not find encryption key for this video")
                return
            
            key = result[0]
            
            out_filename = os.path.basename(file_path)
            out_path = os.path.join(self.folders['quick_buffer'], out_filename.replace('.enc', '.mp4'))
            
            # Show decryption status with a simple label (no progress bar)
            progress_window = tk.Toplevel(self.root)
            progress_window.title("Decrypting Video")
            progress_window.geometry("350x80")
            progress_window.transient(self.root)
            progress_window.resizable(False, False)
            progress_window.configure(bg="white")
            
            # Center the progress window on the main window
            progress_window.geometry("+{}+{}".format(
                self.root.winfo_rootx() + (self.root.winfo_width() // 2 - 175),
                self.root.winfo_rooty() + (self.root.winfo_height() // 2 - 40)
            ))
            
            progress_label = tk.Label(
                progress_window,
                text="Decrypting video, please wait...",
                font=("Arial", 12),
                pady=20,
                bg="white"
            )
            progress_label.pack(fill="both", expand=True)
            
            # Update UI
            self.root.update_idletasks()
            
            # Decrypt the file
            try:
                self.decrypt_file(file_path, out_path, key)
                progress_window.destroy()
                
                # Play the video
                if sys.platform == "win32":
                    os.startfile(out_path)
                elif sys.platform == "darwin":
                    os.system(f"open '{out_path}'")
                else:
                    os.system(f"xdg-open '{out_path}'")
            except Exception as e:
                progress_window.destroy()
                raise e
            
        except Exception as e:
            messagebox.showerror("Playback Error", f"An error occurred: {str(e)}")
            print(f"Play video error: {str(e)}")
            print(traceback.format_exc())
            
            
def main():
    try:
        root = tk.Tk()
        # Set a modern theme if available
        try:
            style = ttk.Style()
            if "clam" in style.theme_names():
                style.theme_use("clam")
            
            # Configure modern styles for widgets
            style.configure("TButton", font=("Arial", 12), padding=5)
            style.configure("TEntry", font=("Arial", 12), padding=5)
        except Exception as e:
            print(f"Could not set theme: {str(e)}")
        
        app = SecurityApp(root)
        root.mainloop()
    except Exception as e:
        print(f"Application error: {str(e)}")
        print(traceback.format_exc())
        messagebox.showerror("Fatal Error", f"The application encountered a fatal error and needs to close: {str(e)}")

if __name__ == "__main__":
    main()
