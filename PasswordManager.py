import tkinter as tk
from tkinter import simpledialog, messagebox, ttk
import os
import sys
import webbrowser
from cryptography.fernet import Fernet

PASSWORD_FILE = "passwords.txt"
MASTER_PASSWORD_FILE = "master_password.txt"
KEY_FILE = "key.key"

# Function to generate a new encryption key
def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)
    return key

# Function to load the encryption key
def load_key():
    return open(KEY_FILE, 'rb').read()

# Function to encrypt a text
def encrypt_text(text, key):
    f = Fernet(key)
    return f.encrypt(text.encode()).decode()

# Function to decrypt a text
def decrypt_text(encrypted_text, key):
    f = Fernet(key)
    return f.decrypt(encrypted_text.encode()).decode()

# Function to set up a master password
def setup_master_password():
    master_password = simpledialog.askstring("Setup", "Create a master password:", show='*')
    if master_password:
        # Encrypt the master password before saving
        key = load_key() if os.path.exists(KEY_FILE) else generate_key()
        encrypted_master_password = encrypt_text(master_password, key)
        with open(MASTER_PASSWORD_FILE, 'w') as f:
            f.write(encrypted_master_password)
        messagebox.showinfo("Success", "Master password set successfully!")

# Function to verify the master password
def verify_master_password():
    if os.path.exists(MASTER_PASSWORD_FILE):
        # Load the key for decryption
        key = load_key()
        with open(MASTER_PASSWORD_FILE, 'r') as f:
            encrypted_master_password = f.read()
        master_password = simpledialog.askstring("Authentication", "Enter master password:", show='*')
        try:
            # Decrypt the master password for verification
            if master_password == decrypt_text(encrypted_master_password, key):
                return True
            else:
                messagebox.showerror("Error", "Invalid master password!")
                return False
        except Exception as e:
            messagebox.showerror("Error", f"Decryption error: {e}")
            return False
    else:
        return False  # Indicate that the master password file does not exist

# Function to add a password
def add():
    username = entryName.get()
    password = entryPassword.get()
    if username and password:
        key = load_key()
        encrypted_username = encrypt_text(username, key)
        encrypted_password = encrypt_text(password, key)
        with open(PASSWORD_FILE, 'a') as f:
            f.write(f"{encrypted_username} {encrypted_password}\n")
        messagebox.showinfo("Success", "Password added!")
    else:
        messagebox.showerror("Error", "Please enter both fields")

# Function to get a password
def get():
    username = entryName.get()
    passwords = {}
    try:
        with open(PASSWORD_FILE, 'r') as f:
            for line in f:
                enc_username, enc_password = line.split(' ')
                passwords[enc_username] = enc_password.strip()
    except FileNotFoundError:
        messagebox.showerror("Error", "Password file not found!")

    if passwords:
        key = load_key()
        for enc_username, enc_password in passwords.items():
            if username == decrypt_text(enc_username, key):
                decrypted_password = decrypt_text(enc_password, key)
                messagebox.showinfo("Password", f"Password for {username} is {decrypted_password}")
                return
        messagebox.showinfo("Password", "No such username exists!")

# Function to list all passwords in a Treeview
def getlist():
    passwords = {}
    try:
        with open(PASSWORD_FILE, 'r') as f:
            for line in f:
                enc_username, enc_password = line.split(' ')
                passwords[enc_username] = enc_password.strip()
    except FileNotFoundError:
        messagebox.showerror("Error", "Password file not found!")

    if passwords:
        key = load_key()
        
        # Create a new window for displaying the passwords in a spreadsheet-like view
        list_window = tk.Toplevel(app)
        list_window.title("List of Passwords")
        
        tree = ttk.Treeview(list_window, columns=("Username", "Password"), show="headings")
        tree.heading("Username", text="Username")
        tree.heading("Password", text="Password")

        for enc_username, enc_password in passwords.items():
            decrypted_username = decrypt_text(enc_username, key)
            decrypted_password = decrypt_text(enc_password, key)
            tree.insert("", tk.END, values=(decrypted_username, decrypted_password))

        tree.pack(fill=tk.BOTH, expand=True)

    else:
        messagebox.showinfo("Passwords", "No passwords found!")

# Function to delete a password
def delete():
    username = entryName.get()
    temp_passwords = []

    try:
        with open(PASSWORD_FILE, 'r') as f:
            for line in f:
                enc_username, enc_password = line.split(' ')
                if username != decrypt_text(enc_username, load_key()):
                    temp_passwords.append(f"{enc_username} {enc_password.strip()}")
        with open(PASSWORD_FILE, 'w') as f:
            for line in temp_passwords:
                f.write(line + '\n')

        messagebox.showinfo("Success", f"User {username} deleted successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Error deleting user {username}: {e}")

# Function to reset the application
def reset_app():
    confirm = messagebox.askyesno("Reset", "Are you sure you want to reset the application? This will delete all data.")
    if confirm:
        try:
            if os.path.exists(PASSWORD_FILE):
                os.remove(PASSWORD_FILE)
            if os.path.exists(MASTER_PASSWORD_FILE):
                os.remove(MASTER_PASSWORD_FILE)
            if os.path.exists(KEY_FILE):
                os.remove(KEY_FILE)
            messagebox.showinfo("Success", "Application reset successfully!")
            app.quit()  # Close the application gracefully
            setup_master_password()  # Prompt to create a new master password after resetting
            restart_app()  # Restart the app after resetting
        except Exception as e:
            messagebox.showerror("Error", f"Error resetting application: {e}")

# Function to restart the application
def restart_app():
    app.destroy()  # Destroy the current instance of the app
    os.execl(sys.executable, sys.executable, *sys.argv)  # Restart the application

# Function to open the feedback URL
def open_feedback():
    webbrowser.open("https://github.com/prcln")

# Function to change the color theme of the application
def change_color_theme(color):
    style.configure("TFrame", background=color)
    style.configure("TLabel", background=color)
    style.configure("TButton", background=color)

# Main application code
app = tk.Tk()
app.geometry("700x500")
app.title("Your TrustWorthy Password Manager")

if not os.path.exists(KEY_FILE):
    key = generate_key()  # Generate a key on first run

if not verify_master_password():
    setup_master_password()  # Automatically prompt for a new master password if none exists

style = ttk.Style()

# Creating frames for better organization
frame_inputs = ttk.Frame(app, padding="10")
frame_inputs.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

frame_buttons = ttk.Frame(app, padding="10")
frame_buttons.grid(row=1, column=0, padx=10, pady=10, sticky="ew")

frame_reset = ttk.Frame(app, padding="10")
frame_reset.grid(row=2, column=0, padx=10, pady=10, sticky="ew")

frame_feedback = ttk.Frame(app, padding="10")
frame_feedback.grid(row=3, column=0, padx=10, pady=10, sticky="ew")

# Username block
labelName = ttk.Label(frame_inputs, text="Username:")
labelName.grid(row=0, column=0, padx=5, pady=5, sticky="e")
entryName = ttk.Entry(frame_inputs)
entryName.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

# Password block
labelPassword = ttk.Label(frame_inputs, text="Password:")
labelPassword.grid(row=1, column=0, padx=5, pady=5, sticky="e")
entryPassword = ttk.Entry(frame_inputs, show='*')  # Hide password input
entryPassword.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

# Add button
buttonAdd = ttk.Button(frame_buttons, text="Add", command=add)
buttonAdd.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

# Get button
buttonGet = ttk.Button(frame_buttons, text="Get", command=get)
buttonGet.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

# List Button
buttonList = ttk.Button(frame_buttons, text="List", command=getlist)
buttonList.grid(row=0, column=2, padx=5, pady=5, sticky="ew")

# Delete button
buttonDelete = ttk.Button(frame_buttons, text="Delete", command=delete)
buttonDelete.grid(row=0, column=3, padx=5, pady=5, sticky="ew")

# Reset button
buttonReset = ttk.Button(frame_reset, text="Reset", command=reset_app)
buttonReset.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

# Feedback button
buttonFeedback = ttk.Button(frame_feedback, text="Feedback", command=open_feedback)
buttonFeedback.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

# Color theme selection
color_options = ["Light Blue", "Light Green", "Light Yellow", "Light Grey", "Jar", "Pink", "White"]
selected_color = tk.StringVar(value=color_options[0])

def update_color_theme(event):
    color = selected_color.get()
    color_map = {
        "Light Blue": "#ADD8E6",
        "Light Green": "#90EE90",
        "Light Yellow": "#FFFFE0",
        "Light Grey": "#D3D3D3",
        "Jar": "#000000",
        "Pink": "#FFC0CB",
        "White": "#FFFFFF",
    }
    change_color_theme(color_map[color])

labelColor = ttk.Label(frame_inputs, text="Color Theme:")
labelColor.grid(row=2, column=0, padx=5, pady=5, sticky="e")
color_menu = ttk.Combobox(frame_inputs, textvariable=selected_color, values=color_options)
color_menu.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
color_menu.bind("<<ComboboxSelected>>", update_color_theme)

# Adjust the column configurations to make them responsive
frame_inputs.columnconfigure(1, weight=1)
frame_buttons.columnconfigure((0, 1, 2, 3), weight=1)
frame_reset.columnconfigure(0, weight=1)
frame_feedback.columnconfigure(0, weight=1)

app.mainloop()
