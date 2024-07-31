import tkinter as tk
from tkinter import simpledialog, messagebox, ttk
import os
import sys  # Import the sys module
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

# Function to encrypt a password
def encrypt_password(password, key):
    f = Fernet(key)
    return f.encrypt(password.encode()).decode()

# Function to decrypt a password
def decrypt_password(encrypted_password, key):
    f = Fernet(key)
    return f.decrypt(encrypted_password.encode()).decode()

# Function to set up a master password
def setup_master_password():
    master_password = simpledialog.askstring("Setup", "Create a master password:", show='*')
    if master_password:
        # Encrypt the master password before saving
        key = load_key() if os.path.exists(KEY_FILE) else generate_key()
        encrypted_master_password = encrypt_password(master_password, key)
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
            if master_password == decrypt_password(encrypted_master_password, key):
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
        encrypted_password = encrypt_password(password, key)
        with open(PASSWORD_FILE, 'a') as f:
            f.write(f"{username} {encrypted_password}\n")
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
                user, enc_password = line.split(' ')
                passwords[user] = enc_password.strip()
    except FileNotFoundError:
        messagebox.showerror("Error", "Password file not found!")

    if username in passwords:
        key = load_key()
        decrypted_password = decrypt_password(passwords[username], key)
        messagebox.showinfo("Password", f"Password for {username} is {decrypted_password}")
    else:
        messagebox.showinfo("Password", "No such username exists!")

# Function to list all passwords in a Treeview
def getlist():
    passwords = {}
    try:
        with open(PASSWORD_FILE, 'r') as f:
            for line in f:
                user, enc_password = line.split(' ')
                passwords[user] = enc_password.strip()
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

        for user, enc_password in passwords.items():
            decrypted_password = decrypt_password(enc_password, key)
            tree.insert("", tk.END, values=(user, decrypted_password))

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
                user, enc_password = line.split(' ')
                if user != username:
                    temp_passwords.append(f"{user} {enc_password.strip()}")
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

# Main application code
app = tk.Tk()
app.geometry("560x320")
app.title("Password Manager")

if not os.path.exists(KEY_FILE):
    key = generate_key()  # Generate a key on first run

if not verify_master_password():
    setup_master_password()  # Automatically prompt for a new master password if none exists

# Username block
labelName = tk.Label(app, text="USERNAME:")
labelName.grid(row=0, column=0, padx=15, pady=15)
entryName = tk.Entry(app)
entryName.grid(row=0, column=1, padx=15, pady=15)

# Password block
labelPassword = tk.Label(app, text="PASSWORD:")
labelPassword.grid(row=1, column=0, padx=10, pady=5)
entryPassword = tk.Entry(app, show='*')  # Hide password input
entryPassword.grid(row=1, column=1, padx=10, pady=5)

# Add button
buttonAdd = tk.Button(app, text="Add", command=add)
buttonAdd.grid(row=2, column=0, padx=15, pady=8, sticky="we")

# Get button
buttonGet = tk.Button(app, text="Get", command=get)
buttonGet.grid(row=2, column=1, padx=15, pady=8, sticky="we")

# List Button
buttonList = tk.Button(app, text="List", command=getlist)
buttonList.grid(row=3, column=0, padx=15, pady=8, sticky="we")

# Delete button
buttonDelete = tk.Button(app, text="Delete", command=delete)
buttonDelete.grid(row=3, column=1, padx=15, pady=8, sticky="we")

# Reset button
buttonReset = tk.Button(app, text="Reset", command=reset_app)
buttonReset.grid(row=4, column=0, padx=15, pady=8, columnspan=2, sticky="we")

app.mainloop()
