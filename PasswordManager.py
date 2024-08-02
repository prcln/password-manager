import tkinter as tk
from tkinter import simpledialog, messagebox, ttk
import os
import sys
import webbrowser
import random
import string
from cryptography.fernet import Fernet

PASSWORD_FILE = "passwords.txt"
KEY_FILE = "key.key"
MASTER_PASSWORD_FILE = "master.key"

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

# Function to generate a random strong password
def generate_random_password():
    characters = string.ascii_letters + string.digits + string.punctuation
    random_password = ''.join(random.choice(characters) for i in range(12))
    return random_password

# Function to measure password strength
def measure_password_strength(password):
    length_score = len(password) >= 8
    digit_score = any(char.isdigit() for char in password)
    upper_score = any(char.isupper() for char in password)
    lower_score = any(char.islower() for char in password)
    symbol_score = any(char in string.punctuation for char in password)
    
    score = sum([length_score, digit_score, upper_score, lower_score, symbol_score])
    return score

# Function to add a password
def add():
    website = entryWebsite.get()
    username = entryName.get()
    password = entryPassword.get()
    if not password:
        password = generate_random_password()
        entryPassword.insert(0, password)
    if website and username and password:
        key = load_key()
        encrypted_website = encrypt_text(website, key)
        encrypted_username = encrypt_text(username, key)
        encrypted_password = encrypt_text(password, key)
        with open(PASSWORD_FILE, 'a') as f:
            f.write(f"{encrypted_website} {encrypted_username} {encrypted_password}\n")
        messagebox.showinfo("Success", "Password added!")
    else:
        messagebox.showerror("Error", "Please enter all fields")

# Function to get a password
def get():
    website = entryWebsite.get()
    username = entryName.get()
    passwords = {}
    try:
        with open(PASSWORD_FILE, 'r') as f:
            for line in f:
                enc_website, enc_username, enc_password = line.split(' ')
                passwords[(enc_website, enc_username)] = enc_password.strip()
    except FileNotFoundError:
        messagebox.showerror("Error", "Password file not found!")

    if passwords:
        key = load_key()
        for (enc_website, enc_username), enc_password in passwords.items():
            if website == decrypt_text(enc_website, key) and username == decrypt_text(enc_username, key):
                decrypted_password = decrypt_text(enc_password, key)
                password_safeness = measure_password_strength(decrypted_password)
                messagebox.showinfo("Password", f"Password for {username} at {website} is {decrypted_password}\nPassword safeness score: {password_safeness}/5")
                return
        messagebox.showinfo("Password", "No such username exists!")

# Function to copy a password
def copy_password(password):
    app.clipboard_clear()
    app.clipboard_append(password)
    messagebox.showinfo("Copied", "Password copied to clipboard!")

# Function to delete a password from the list popup
def delete_from_list(item):
    item_values = tree.item(item, 'values')
    website = item_values[0]
    username = item_values[1]
    delete_password(website, username)
    tree.delete(item)

# Function to list all passwords in a Treeview
def getlist():
    passwords = {}
    try:
        with open(PASSWORD_FILE, 'r') as f:
            for line in f:
                enc_website, enc_username, enc_password = line.split(' ')
                passwords[(enc_website, enc_username)] = enc_password.strip()
    except FileNotFoundError:
        messagebox.showerror("Error", "Password file not found!")

    if passwords:
        key = load_key()
        
        # Create a new window for displaying the passwords in a spreadsheet-like view
        list_window = tk.Toplevel(app)
        list_window.title("List of Passwords")
        
        global tree
        tree = ttk.Treeview(list_window, columns=("Website", "Username", "Password"), show="headings")
        tree.heading("Website", text="Website")
        tree.heading("Username", text="Username")
        tree.heading("Password", text="Password")

        for (enc_website, enc_username), enc_password in passwords.items():
            decrypted_website = decrypt_text(enc_website, key)
            decrypted_username = decrypt_text(enc_username, key)
            decrypted_password = decrypt_text(enc_password, key)
            tree.insert("", tk.END, values=(decrypted_website, decrypted_username, decrypted_password))

        tree.pack(fill=tk.BOTH, expand=True)

        # Adding right-click menu
        menu = tk.Menu(tree, tearoff=0)
        menu.add_command(label="Copy Password", command=lambda: copy_password(tree.item(tree.selection()[0], 'values')[2]))
        menu.add_command(label="Delete", command=lambda: delete_from_list(tree.selection()[0]))

        def show_menu(event):
            item = tree.identify_row(event.y)
            if item:
                tree.selection_set(item)
                menu.post(event.x_root, event.y_root)

        tree.bind("<Button-3>", show_menu)
    else:
        messagebox.showinfo("Passwords", "No passwords found!")

# Function to delete a password
def delete_password(website, username):
    temp_passwords = []

    try:
        with open(PASSWORD_FILE, 'r') as f:
            for line in f:
                enc_website, enc_username, enc_password = line.split(' ')
                if website != decrypt_text(enc_website, load_key()) or username != decrypt_text(enc_username, load_key()):
                    temp_passwords.append(f"{enc_website} {enc_username} {enc_password.strip()}")
        with open(PASSWORD_FILE, 'w') as f:
            for line in temp_passwords:
                f.write(line + '\n')

        messagebox.showinfo("Success", f"User {username} at {website} deleted successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Error deleting user {username} at {website}: {e}")

# Function to delete a password
def delete():
    website = entryWebsite.get()
    username = entryName.get()
    delete_password(website, username)

# Function to reset the application
def reset_app():
    confirm = messagebox.askyesno("Reset", "Are you sure you want to reset the application? This will delete all data.")
    if confirm:
        try:
            if os.path.exists(PASSWORD_FILE):
                os.remove(PASSWORD_FILE)
            if os.path.exists(KEY_FILE):
                os.remove(KEY_FILE)
            if os.path.exists(MASTER_PASSWORD_FILE):
                os.remove(MASTER_PASSWORD_FILE)
            messagebox.showinfo("Success", "Application reset successfully!")
            app.quit()  # Close the application gracefully
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

# Function to decrypt a text
def decrypt_text(encrypted_text, key):
    f = Fernet(key)
    return f.decrypt(encrypted_text).decode()  # Removed .encode()

# Function to check master password
def check_master_password():
    if os.path.exists(MASTER_PASSWORD_FILE):
        key = load_key()
        with open(MASTER_PASSWORD_FILE, 'rb') as f:
            encrypted_master_password = f.read()  # Read as bytes
        master_password = simpledialog.askstring("Master Password", "Enter master password:", show='*')
        if master_password and master_password == decrypt_text(encrypted_master_password, key):
            return True
        else:
            messagebox.showerror("Error", "Incorrect master password")
            return False
    else:
        key = load_key()
        master_password = simpledialog.askstring("Set Master Password", "Set a master password:", show='*')
        if master_password:
            encrypted_master_password = encrypt_text(master_password, key)
            with open(MASTER_PASSWORD_FILE, 'wb') as f:
                f.write(encrypted_master_password.encode())  # Use .encode() here for saving
            messagebox.showinfo("Success", "Master password set successfully!")
            return True
        else:
            messagebox.showerror("Error", "Master password cannot be empty")
            return False


# Function to generate a new password
def generate_new_password():
    new_password = generate_random_password()
    entryPassword.delete(0, tk.END)
    entryPassword.insert(0, new_password)

# Main application code
app = tk.Tk()
app.geometry("700x500")
app.title("Your TrustWorthy Password Manager")

if not os.path.exists(KEY_FILE):
    key = generate_key()  # Generate a key on first run

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

# Website/App block
labelWebsite = ttk.Label(frame_inputs, text="Website/App:")
labelWebsite.grid(row=0, column=0, padx=5, pady=5, sticky="e")
entryWebsite = ttk.Entry(frame_inputs)
entryWebsite.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

# Username block
labelName = ttk.Label(frame_inputs, text="Username:")
labelName.grid(row=1, column=0, padx=5, pady=5, sticky="e")
entryName = ttk.Entry(frame_inputs)
entryName.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

# Password block
labelPassword = ttk.Label(frame_inputs, text="Password:")
labelPassword.grid(row=2, column=0, padx=5, pady=5, sticky="e")
entryPassword = ttk.Entry(frame_inputs, show='*')  # Hide password input
entryPassword.grid(row=2, column=1, padx=5, pady=5, sticky="ew")

# Password strength progress bar
progress_bar = ttk.Progressbar(frame_inputs, orient="horizontal", length=200, mode="determinate")
progress_bar.grid(row=3, column=1, padx=5, pady=5, sticky="ew")

# Function to update progress bar
def update_progress_bar(event):
    password = entryPassword.get()
    score = measure_password_strength(password)
    progress_bar['value'] = (score / 5) * 100

entryPassword.bind("<KeyRelease>", update_progress_bar)

# Generate random password button
buttonGenerate = ttk.Button(frame_buttons, text="Generate Random Password", command=generate_new_password)
buttonGenerate.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

# Add button
buttonAdd = ttk.Button(frame_buttons, text="Add", command=add)
buttonAdd.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

# Get button
buttonGet = ttk.Button(frame_buttons, text="Get", command=get)
buttonGet.grid(row=0, column=2, padx=5, pady=5, sticky="ew")

# List button
buttonList = ttk.Button(frame_buttons, text="List", command=getlist)
buttonList.grid(row=0, column=3, padx=5, pady=5, sticky="ew")

# Delete button
buttonDelete = ttk.Button(frame_buttons, text="Delete", command=delete)
buttonDelete.grid(row=0, column=4, padx=5, pady=5, sticky="ew")

# Reset button
buttonReset = ttk.Button(frame_reset, text="Reset Application", command=reset_app)
buttonReset.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

# Feedback button
buttonFeedback = ttk.Button(frame_feedback, text="Feedback", command=open_feedback)
buttonFeedback.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

# Color theme combobox
theme_combobox = ttk.Combobox(frame_feedback, values=["Light", "Dark", "Pink", "Green", "Blue", "Yellow"])
theme_combobox.set("Light")
theme_combobox.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

# Change theme on selection
def change_theme(event):
    selected_theme = theme_combobox.get()
    if selected_theme == "Light":
        change_color_theme("light gray")
    elif selected_theme == "Dark":
        change_color_theme("dark gray")
    elif selected_theme == "Pink":
        change_color_theme("pink")
    elif selected_theme == "Green":
        change_color_theme("green")
    elif selected_theme == "Blue":
        change_color_theme("blue")
    elif selected_theme == "Yellow":
        change_color_theme("yellow")
theme_combobox.bind("<<ComboboxSelected>>", change_theme)

# Check master password on startup
if not check_master_password():
    app.destroy()
else:
    app.mainloop()
