import os
import sys
import sqlite3
import bcrypt
import json
import hashlib
import time
import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import cv2
from cryptography.fernet import Fernet
import shutil
import threading
import schedule
from ultralytics import YOLO  # Import YOLOv8

# Global variables
CURRENT_USER = None
DEFAULT_PATH = "/home/SecurityCamera"  # Adjust for your OS if needed
CONFIG_FILE = os.path.expanduser("~/.security_config.json")

class SecurityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Security Footage Searcher")
        self.root.geometry("800x600")
        self.root.configure(bg="#f0f0f0")

        # Load YOLO model
        self.yolo_model = YOLO("yolov8n.pt")  # Use nano model for speed; change to yolov8m.pt or yolov8l.pt for better accuracy

        # Initialize database and folder structure
        self.initialize_system()
        
        if self.check_existing_user():
            self.show_login_screen()
        else:
            self.show_create_account_screen()

    def initialize_system(self):
        """Initialize the system, create necessary folders and database"""
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
            'user_data': os.path.join(self.base_path, 'UserData')
        }
        
        for folder in self.folders.values():
            os.makedirs(folder, exist_ok=True)
        
        self.db_path = os.path.join(self.folders['metadata'], 'security_footage.db')
        self.initialize_database()
        self.start_scheduled_tasks()

    def initialize_database(self):
        """Initialize the SQLite database with necessary tables"""
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
        conn.close()

    def check_existing_user(self):
        """Check if any user exists in the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0

    def clear_frame(self):
        """Clear all widgets from the main frame"""
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_login_screen(self):
        """Display the login screen"""
        self.clear_frame()
        login_frame = tk.Frame(self.root, bg="#f0f0f0", padx=20, pady=20)
        login_frame.pack(expand=True)
        
        tk.Label(login_frame, text="Security Footage Searcher", font=("Arial", 20, "bold"),
                bg="#f0f0f0", fg="#333333").pack(pady=20)
        
        tk.Label(login_frame, text="Username:", font=("Arial", 12), bg="#f0f0f0", 
                fg="#333333").pack(anchor="w", pady=(10, 5))
        username_entry = tk.Entry(login_frame, font=("Arial", 12), width=30)
        username_entry.pack(pady=(0, 10), ipady=5)
        
        tk.Label(login_frame, text="Password:", font=("Arial", 12), bg="#f0f0f0", 
                fg="#333333").pack(anchor="w", pady=(10, 5))
        password_entry = tk.Entry(login_frame, font=("Arial", 12), width=30, show="*")
        password_entry.pack(pady=(0, 20), ipady=5)
        
        tk.Button(login_frame, text="Login", font=("Arial", 12, "bold"), bg="#4CAF50", fg="white",
                 padx=20, pady=10, command=lambda: self.validate_login(username_entry.get(), 
                 password_entry.get())).pack(pady=10)

    def show_create_account_screen(self):
        """Display the create account screen"""
        self.clear_frame()
        create_account_frame = tk.Frame(self.root, bg="#f0f0f0", padx=20, pady=20)
        create_account_frame.pack(expand=True)
        
        tk.Label(create_account_frame, text="Create Account", font=("Arial", 20, "bold"),
                bg="#f0f0f0", fg="#333333").pack(pady=20)
        
        tk.Label(create_account_frame, text="Username (at least 5 characters):", 
                font=("Arial", 12), bg="#f0f0f0", fg="#333333").pack(anchor="w", pady=(10, 5))
        username_entry = tk.Entry(create_account_frame, font=("Arial", 12), width=30)
        username_entry.pack(pady=(0, 10), ipady=5)
        
        tk.Label(create_account_frame, text="Password (at least 8 characters with numbers and special chars):",
                font=("Arial", 12), bg="#f0f0f0", fg="#333333").pack(anchor="w", pady=(10, 5))
        password_entry = tk.Entry(create_account_frame, font=("Arial", 12), width=30, show="*")
        password_entry.pack(pady=(0, 10), ipady=5)
        
        tk.Label(create_account_frame, text="Confirm Password:", font=("Arial", 12),
                bg="#f0f0f0", fg="#333333").pack(anchor="w", pady=(10, 5))
        confirm_password_entry = tk.Entry(create_account_frame, font=("Arial", 12), width=30, show="*")
        confirm_password_entry.pack(pady=(0, 20), ipady=5)
        
        tk.Button(create_account_frame, text="Create Account", font=("Arial", 12, "bold"),
                 bg="#4CAF50", fg="white", padx=20, pady=10,
                 command=lambda: self.validate_create_account(username_entry.get(),
                 password_entry.get(), confirm_password_entry.get())).pack(pady=10)

    def validate_login(self, username, password):
        """Validate login credentials"""
        if not username or not password:
            messagebox.showerror("Login Error", "Username and password are required")
            return
        
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
            messagebox.showerror("Login Error", "Invalid username or password")

    def validate_create_account(self, username, password, confirm_password):
        """Validate and create a new account"""
        if len(username) < 5 or len(password) < 8 or not any(char.isdigit() for char in password) or \
           not any(char in "!@#$%^&*()_+-=[]{};':\"\\|,.<>/?" for char in password) or \
           password != confirm_password:
            messagebox.showerror("Account Creation Error", "Please check all requirements")
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", (username,))
        if cursor.fetchone()[0] > 0:
            messagebox.showerror("Account Creation Error", "Username already exists")
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

    def show_storage_location_screen(self):
        """Show screen to select storage location"""
        self.clear_frame()
        location_frame = tk.Frame(self.root, bg="#f0f0f0", padx=20, pady=20)
        location_frame.pack(expand=True)
        
        tk.Label(location_frame, text="Set Storage Location", font=("Arial", 20, "bold"),
                bg="#f0f0f0", fg="#333333").pack(pady=20)
        
        tk.Label(location_frame, text="Select a location to store security footage files or use default.",
                font=("Arial", 12), bg="#f0f0f0", fg="#333333", wraplength=500).pack(pady=10)
        
        location_var = tk.StringVar(value=self.base_path)
        location_frame_inner = tk.Frame(location_frame, bg="#f0f0f0")
        location_frame_inner.pack(fill="x", pady=10)
        
        tk.Entry(location_frame_inner, font=("Arial", 12), width=40, 
                textvariable=location_var).pack(side="left", padx=(0, 10), ipady=5)
        tk.Button(location_frame_inner, text="Browse", font=("Arial", 10),
                 command=lambda: self.browse_directory(location_var)).pack(side="left")
        
        buttons_frame = tk.Frame(location_frame, bg="#f0f0f0")
        buttons_frame.pack(pady=20)
        tk.Button(buttons_frame, text="Use Default", font=("Arial", 12), padx=15, pady=8,
                 command=lambda: self.set_storage_location(DEFAULT_PATH)).pack(side="left", padx=10)
        tk.Button(buttons_frame, text="Confirm Location", font=("Arial", 12, "bold"), bg="#4CAF50",
                 fg="white", padx=15, pady=8, command=lambda: self.validate_storage_location(
                 location_var.get())).pack(side="left", padx=10)

    def browse_directory(self, location_var):
        """Open directory browser"""
        directory = filedialog.askdirectory(initialdir=location_var.get())
        if directory:
            location_var.set(directory)

    def validate_storage_location(self, path):
        """Validate selected storage location"""
        if not path or not os.access(path, os.W_OK):
            messagebox.showerror("Error", "Invalid or unwritable storage location")
            return
        self.set_storage_location(path)

    def set_storage_location(self, path):
        """Set the storage location and create folder structure"""
        self.base_path = path
        self.folders = {
            'main': self.base_path,
            'encrypted_videos': os.path.join(self.base_path, 'EncryptedVideos'),
            'quick_buffer': os.path.join(self.base_path, 'QuickBuffer'),
            'metadata': os.path.join(self.base_path, 'MetaData'),
            'user_data': os.path.join(self.base_path, 'UserData')
        }
        
        for folder in self.folders.values():
            os.makedirs(folder, exist_ok=True)
        
        with open(CONFIG_FILE, 'w') as f:
            json.dump({'base_path': self.base_path}, f)
        
        old_db_path = self.db_path
        self.db_path = os.path.join(self.folders['metadata'], 'security_footage.db')
        if old_db_path != self.db_path and os.path.exists(old_db_path):
            shutil.copy2(old_db_path, self.db_path)
        
        messagebox.showinfo("Success", "Storage location set successfully!")
        self.show_home_screen()

    def show_home_screen(self):
        """Display the main home screen"""
        self.clear_frame()
        
        header_frame = tk.Frame(self.root, bg="#333333", height=80)
        header_frame.pack(fill="x")
        header_frame.pack_propagate(False)
        
        content_frame = tk.Frame(self.root, bg="#f0f0f0")
        content_frame.pack(fill="both", expand=True)
        
        tk.Label(header_frame, text="Security Footage Searcher", font=("Arial", 18, "bold"),
                bg="#333333", fg="white").pack(side="left", padx=20, pady=20)
        
        tk.Button(header_frame, text="Logout", font=("Arial", 10), bg="#f44336", fg="white",
                 command=self.logout).pack(side="right", padx=20, pady=20)
        
        tk.Button(header_frame, text="Start Camera", font=("Arial", 10), bg="#2196F3", fg="white",
                 command=lambda: threading.Thread(target=self.start_camera_recording, 
                 daemon=True).start()).pack(side="right", padx=10, pady=20)
        
        search_frame = tk.Frame(content_frame, bg="#f0f0f0", padx=20, pady=20)
        search_frame.pack(fill="x")
        
        tk.Label(search_frame, text="Search Security Footage", font=("Arial", 16, "bold"),
                bg="#f0f0f0", fg="#333333").grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 20))
        
        today = datetime.date.today()
        
        tk.Label(search_frame, text="Date:", font=("Arial", 12), bg="#f0f0f0", 
                fg="#333333").grid(row=1, column=0, sticky="w", padx=(0, 10), pady=10)
        
        day_var = tk.StringVar(value=str(today.day))
        tk.Label(search_frame, text="Day:", bg="#f0f0f0").grid(row=1, column=1, sticky="w", padx=(0, 5))
        tk.Spinbox(search_frame, from_=1, to=31, width=5, textvariable=day_var).grid(row=1, column=2, 
                sticky="w", padx=(0, 10))
        
        month_var = tk.StringVar(value=str(today.month))
        tk.Label(search_frame, text="Month:", bg="#f0f0f0").grid(row=1, column=3, sticky="w", padx=(0, 5))
        tk.Spinbox(search_frame, from_=1, to=12, width=5, textvariable=month_var).grid(row=1, column=4, 
                sticky="w", padx=(0, 10))
        
        year_var = tk.StringVar(value=str(today.year))
        tk.Label(search_frame, text="Year:", bg="#f0f0f0").grid(row=1, column=5, sticky="w", padx=(0, 5))
        tk.Spinbox(search_frame, from_=2020, to=2100, width=8, textvariable=year_var).grid(row=1, column=6, 
                sticky="w", padx=(0, 10))
        
        tk.Label(search_frame, text="Objects Detected:", font=("Arial", 12), bg="#f0f0f0",
                fg="#333333").grid(row=2, column=0, sticky="w", padx=(0, 10), pady=10)
        
        objects_frame = tk.Frame(search_frame, bg="#f0f0f0")
        objects_frame.grid(row=2, column=1, columnspan=6, sticky="w")
        
        object_vars = {}
        common_objects = ["Person", "Car", "Animal", "Package", "Other"]
        for i, obj in enumerate(common_objects):
            var = tk.BooleanVar(value=False)
            object_vars[obj] = var
            tk.Checkbutton(objects_frame, text=obj, variable=var, bg="#f0f0f0").grid(row=0, column=i, padx=10)
        
        tk.Button(search_frame, text="Search", font=("Arial", 12, "bold"), bg="#4CAF50", fg="white",
                 padx=20, pady=5, command=lambda: self.search_videos(day_var.get(), month_var.get(),
                 year_var.get(), {obj: var.get() for obj, var in object_vars.items()})).grid(row=3, 
                 column=0, columnspan=7, pady=20)
        
        results_frame = tk.Frame(content_frame, bg="white", padx=20, pady=20)
        results_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        tk.Label(results_frame, text="Search Results", font=("Arial", 14, "bold"), bg="white",
                fg="#333333").pack(anchor="w", pady=(0, 10))
        
        canvas_frame = tk.Frame(results_frame)
        canvas_frame.pack(fill="both", expand=True)
        
        scrollbar = tk.Scrollbar(canvas_frame)
        scrollbar.pack(side="right", fill="y")
        
        self.results_canvas = tk.Canvas(canvas_frame, bg="white", yscrollcommand=scrollbar.set)
        self.results_canvas.pack(side="left", fill="both", expand=True)
        
        scrollbar.config(command=self.results_canvas.yview)
        
        self.results_container = tk.Frame(self.results_canvas, bg="white")
        self.results_canvas.create_window((0, 0), window=self.results_container, anchor="nw")
        
        self.results_container.bind("<Configure>", lambda e: self.results_canvas.configure(
            scrollregion=self.results_canvas.bbox("all"), width=e.width))

    def search_videos(self, day, month, year, objects):
        """Search for videos based on date and objects"""
        for widget in self.results_container.winfo_children():
            widget.destroy()
        
        try:
            search_date = datetime.date(int(year), int(month), int(day))
            date_str = search_date.strftime("%Y-%m-%d")
        except ValueError:
            messagebox.showerror("Invalid Date", "Please enter a valid date")
            return
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = "SELECT id, filename, file_path, created_at, detected_objects, thumbnail_path FROM videos WHERE date(created_at) = ?"
        params = [date_str]
        
        selected_objects = [obj for obj, selected in objects.items() if selected]
        if selected_objects:
            object_conditions = [f"detected_objects LIKE '%{obj}%'" for obj in selected_objects]
            query += " AND (" + " OR ".join(object_conditions) + ")"
        
        cursor.execute(query, params)
        results = cursor.fetchall()
        conn.close()
        
        if not results:
            tk.Label(self.results_container, text="No videos match your search criteria.", 
                    font=("Arial", 12), bg="white", fg="#666666", padx=20, pady=40).pack()
            return
        
        for i, (id, filename, file_path, created_at, detected_objects, thumbnail_path) in enumerate(results):
            result_frame = tk.Frame(self.results_container, bg="white", padx=10, pady=10)
            result_frame.pack(fill="x", pady=5)
            result_frame.config(highlightbackground="#ddd", highlightthickness=1)
            
            display_name = os.path.splitext(os.path.basename(filename))[0]
            timestamp = datetime.datetime.strptime(created_at, "%Y-%m-%d %H:%M:%S")
            time_str = timestamp.strftime("%H:%M:%S")
            
            info_frame = tk.Frame(result_frame, bg="white")
            info_frame.pack(side="left", fill="both", expand=True, padx=10)
            
            tk.Label(info_frame, text=display_name, font=("Arial", 12, "bold"), bg="white",
                    fg="#333333", anchor="w").pack(anchor="w")
            tk.Label(info_frame, text=f"Time: {time_str}", font=("Arial", 10), bg="white",
                    fg="#666666", anchor="w").pack(anchor="w")
            
            if detected_objects:
                tk.Label(info_frame, text=f"Objects: {detected_objects}", font=("Arial", 10),
                        bg="white", fg="#666666", anchor="w").pack(anchor="w")
            
            button_frame = tk.Frame(result_frame, bg="white")
            button_frame.pack(side="right", padx=10)
            tk.Button(button_frame, text="Play", font=("Arial", 10), bg="#4CAF50", fg="white",
                     command=lambda path=file_path: self.play_video(path)).pack(side="top", pady=5)
            tk.Button(button_frame, text="Save Decrypted", font=("Arial", 10),
                     command=lambda path=file_path, name=filename: self.save_decrypted_video(path, 
                     name)).pack(side="top", pady=5)

    def play_video(self, file_path):
        """Decrypt and play a video"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT encryption_keys.key_value FROM videos JOIN encryption_keys ON videos.encryption_key_id = encryption_keys.id WHERE videos.file_path = ?", (file_path,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            messagebox.showerror("Error", "Could not find encryption key for this video")
            return
        
        key = result[0]
        out_filename = os.path.basename(file_path)
        out_path = os.path.join(self.folders['quick_buffer'], out_filename)
        
        self.decrypt_file(file_path, out_path, key)
        
        if sys.platform == "win32":
            os.startfile(out_path)
        elif sys.platform == "darwin":
            os.system(f"open {out_path}")
        else:
            os.system(f"xdg-open {out_path}")

    def save_decrypted_video(self, file_path, filename):
        """Save a decrypted copy of the video"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT encryption_keys.key_value, videos.original_filename FROM videos JOIN encryption_keys ON videos.encryption_key_id = encryption_keys.id WHERE videos.file_path = ?", (file_path,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            messagebox.showerror("Error", "Could not find encryption key for this video")
            return
        
        key, original_filename = result
        
        save_path = filedialog.asksaveasfilename(initialfile=original_filename,
                                                defaultextension=".mp4",
                                                filetypes=[("Video files", "*.mp4"), ("All files", "*.*")])
        if save_path:
            self.decrypt_file(file_path, save_path, key)
            messagebox.showinfo("Success", "Video saved successfully!")

    def encrypt_file(self, input_path, output_path=None, key=None):
        """Encrypt a file using Fernet symmetric encryption"""
        if output_path is None:
            file_name = os.path.basename(input_path)
            output_path = os.path.join(self.folders['encrypted_videos'], file_name)
        
        if key is None:
            key = Fernet.generate_key().decode('utf-8')
            key_id = hashlib.sha256(key.encode('utf-8')).hexdigest()
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO encryption_keys (id, key_value) VALUES (?, ?)", (key_id, key))
            conn.commit()
            conn.close()
        else:
            key_id = hashlib.sha256(key.encode('utf-8')).hexdigest()
        
        cipher = Fernet(key.encode('utf-8'))
        with open(input_path, 'rb') as f:
            data = f.read()
        encrypted_data = cipher.encrypt(data)
        with open(output_path, 'wb') as f:
            f.write(encrypted_data)
        
        return output_path, key_id

    def decrypt_file(self, input_path, output_path, key):
        """Decrypt a file using Fernet symmetric encryption"""
        cipher = Fernet(key.encode('utf-8'))
        with open(input_path, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = cipher.decrypt(encrypted_data)
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        return output_path

    def add_video_to_database(self, original_path, encrypted_path, key_id, detected_objects=None, thumbnail_path=None):
        """Add encrypted video metadata to the database"""
        original_filename = os.path.basename(original_path)
        encrypted_filename = os.path.basename(encrypted_path)
        file_size = os.path.getsize(encrypted_path)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO videos (filename, original_filename, encryption_key_id, file_path, file_size, detected_objects, thumbnail_path) VALUES (?, ?, ?, ?, ?, ?, ?)",
                      (encrypted_filename, original_filename, key_id, encrypted_path, file_size, detected_objects, thumbnail_path))
        conn.commit()
        conn.close()

    def detect_objects(self, frame):
        """Perform object detection using YOLOv8"""
        # Convert frame to RGB (YOLO expects RGB, OpenCV uses BGR)
        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        
        # Run YOLOv8 inference
        results = self.yolo_model(rgb_frame, verbose=False)  # Set verbose=False to reduce logging
        
        # Process results
        max_confidence = 0.0
        detected_object = None
        
        for result in results:
            for box in result.boxes:
                confidence = float(box.conf)  # Confidence score
                class_id = int(box.cls)  # Class ID
                class_name = self.yolo_model.names[class_id]  # Get class name from model
                
                # Map YOLO class names to your common objects
                mapped_name = self.map_yolo_class(class_name)
                
                if confidence > max_confidence:
                    max_confidence = confidence
                    detected_object = mapped_name
        
        return (max_confidence, detected_object)

    def map_yolo_class(self, class_name):
        """Map YOLO class names to your application's common objects"""
        mapping = {
            'person': 'Person',
            'car': 'Car',
            'truck': 'Car',  # Treat trucks as cars
            'dog': 'Animal',
            'cat': 'Animal',
            'bird': 'Animal',
            'bicycle': 'Other',
            'motorcycle': 'Other',
            'backpack': 'Package',
            'suitcase': 'Package'
            # Add more mappings as needed
        }
        return mapping.get(class_name.lower(), 'Other') if class_name else None

    def start_camera_recording(self):
        """Start the camera recording with object detection"""
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            messagebox.showerror("Camera Error", "Could not open camera")
            return

        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        frame_width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        frame_height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        
        recording = False
        writer = None
        detection_start_time = None
        recording_start_time = None
        thumbnail_path = None
        detected_objects = set()

        while True:
            ret, frame = cap.read()
            if not ret:
                break

            current_time = time.time()
            confidence, object_name = self.detect_objects(frame)
            detection_threshold = 0.70

            if confidence > detection_threshold:
                if not recording:
                    detection_start_time = current_time
                    timestamp = datetime.datetime.now().strftime("%d/%m/%y-%H/%M/%S")
                    filename = f"security_{timestamp}.mp4"
                    output_path = os.path.join(self.folders['quick_buffer'], filename)
                    writer = cv2.VideoWriter(output_path, fourcc, 20.0, (frame_width, frame_height))
                    recording = True
                    recording_start_time = current_time
                    
                    thumbnail_filename = f"thumb_{timestamp}.jpg"
                    thumbnail_path = os.path.join(self.folders['metadata'], thumbnail_filename)
                    cv2.imwrite(thumbnail_path, frame)

                detected_objects.add(object_name)
                cv2.putText(frame, f"{object_name}: {confidence:.2f}", (10, 30), 
                           cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)

            if recording:
                writer.write(frame)
                
                if confidence > detection_threshold:
                    detection_start_time = current_time
                
                time_since_detection = current_time - detection_start_time
                recording_duration = current_time - recording_start_time
                
                if time_since_detection >= 3 and recording_duration >= 23:
                    writer.release()
                    self.process_recorded_video(output_path, thumbnail_path, detected_objects)
                    recording = False
                    detected_objects.clear()
                    thumbnail_path = None
                
                if recording_duration >= 300:
                    writer.release()
                    self.process_recorded_video(output_path, thumbnail_path, detected_objects)
                    recording = False
                    detected_objects.clear()
                    thumbnail_path = None

            cv2.imshow('Security Camera', frame)
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break

        if recording and writer is not None:
            writer.release()
        cap.release()
        cv2.destroyAllWindows()

    def process_recorded_video(self, video_path, thumbnail_path, detected_objects):
        """Process and store the recorded video"""
        encrypted_path, key_id = self.encrypt_file(video_path)
        objects_str = ",".join(detected_objects) if detected_objects else None
        self.add_video_to_database(video_path, encrypted_path, key_id, objects_str, thumbnail_path)
        if os.path.exists(video_path):
            os.remove(video_path)

    def start_scheduled_tasks(self):
        """Start scheduled tasks like storage maintenance"""
        schedule.every().day.at("00:00").do(self.perform_storage_maintenance)
        scheduler_thread = threading.Thread(target=self.run_scheduled_tasks, daemon=True)
        scheduler_thread.start()

    def run_scheduled_tasks(self):
        """Run the scheduler in a loop"""
        while True:
            schedule.run_pending()
            time.sleep(60)

    def perform_storage_maintenance(self):
        """Perform storage maintenance to keep disk usage under control"""
        total, used, free = shutil.disk_usage(self.base_path)
        usage_percent = (used / total) * 100
        
        if usage_percent > 90:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT id, file_path FROM videos ORDER BY created_at ASC LIMIT 50")
            videos_to_delete = cursor.fetchall()
            
            for video_id, file_path in videos_to_delete:
                if os.path.exists(file_path):
                    os.remove(file_path)
                cursor.execute("DELETE FROM videos WHERE id = ?", (video_id,))
            
            conn.commit()
            conn.close()

    def logout(self):
        """Logout and clear QuickBuffer"""
        for filename in os.listdir(self.folders['quick_buffer']):
            file_path = os.path.join(self.folders['quick_buffer'], filename)
            if os.path.isfile(file_path):
                os.remove(file_path)
        
        global CURRENT_USER
        CURRENT_USER = None
        self.show_login_screen()

def main():
    root = tk.Tk()
    app = SecurityApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
