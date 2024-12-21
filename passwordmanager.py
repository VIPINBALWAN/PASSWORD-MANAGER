import tkinter as tk
from tkinter import messagebox, simpledialog
from tkinter import ttk
import random
import string
from cryptography.fernet import Fernet
import base64

# Define your admin password here
ADMIN_PASSWORD = "admin"  # Change this to your desired admin password
# Use a specific key "admin"
base_key = "admin".ljust(32)  #  "admin" to 32 bytes
specific_key = base64.urlsafe_b64encode(base_key.encode())
cipher_suite = Fernet(specific_key)


def check_admin_password():
    # Prompts for admin password on startup.
    entered_password = simpledialog.askstring(
        "Admin Password", "Enter Admin Password:", show="*"
    )
    if entered_password == ADMIN_PASSWORD:
        return True
    else:
        messagebox.showerror("Error", "Invalid Admin password!")
        return False


def generate_random_password(
    length=12,
):  # Generate a random password with uppercase, lowercase, digits, and special characters.
    characters = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choice(characters) for i in range(length))


def encrypt_data(data):
    """Encrypt data using the cipher suite."""
    return cipher_suite.encrypt(data.encode())


def decrypt_data(data):
    """Decrypt data using the cipher suite."""
    return cipher_suite.decrypt(data).decode()


def add():
    # Prompt for username and password to add, with a recommended random password.
    username = simpledialog.askstring("Input", "Enter Username:")
    if username:
        password_length = simpledialog.askinteger(
            "Input",
            "Enter desired password length:",
            initialvalue=12,
            minvalue=6,
            maxvalue=32,
        )
        if password_length:
            recommended_password = generate_random_password(password_length)
            message = (
                f"Enter Password or use the recommended one:\n{recommended_password}"
            )
            password = simpledialog.askstring(
                "Input", message, initialvalue=recommended_password, show="*"
            )
            if password:
                additional_info = simpledialog.askstring(
                    "Input", "Enter additional information (e.g., email or note):"
                )
                encrypted_username = encrypt_data(username)
                encrypted_password = encrypt_data(password)
                encrypted_additional_info = (
                    encrypt_data(additional_info) if additional_info else b""
                )
                with open("encrypted_passwords.txt", "ab") as f:
                    f.write(
                        encrypted_username
                        + b" "
                        + encrypted_password
                        + b" "
                        + encrypted_additional_info
                        + b"\n"
                    )
                messagebox.showinfo("Success", "Password added!")
            else:
                messagebox.showerror("Error", "Password cannot be empty!")
        else:
            messagebox.showerror("Error", "Invalid password length!")
    else:
        messagebox.showerror("Error", "Username cannot be empty!")


def search():
    # Retrieve and show the password for the specified username.
    username = simpledialog.askstring("Input", "Enter Username:")
    passwords = {}
    try:
        with open("encrypted_passwords.txt", "rb") as f:
            for line in f:
                i = line.split(maxsplit=2)
                decrypted_username = decrypt_data(i[0])
                decrypted_password = decrypt_data(i[1])
                decrypted_additional_info = decrypt_data(i[2]) if len(i) > 2 else ""
                passwords[decrypted_username] = (
                    decrypted_password,
                    decrypted_additional_info,
                )
    except FileNotFoundError:
        messagebox.showerror("Error", "No passwords found!")
    if passwords:
        if username in passwords:
            password, additional_info = passwords[username]
            message = f"Password for {username} is {password}\nAdditional info: {additional_info}"
        else:
            message = "No such username exists!"
        messagebox.showinfo("Passwords", message)
    else:
        messagebox.showinfo("Passwords", "Empty list!")


def list():
    # Retrieve and show all stored passwords in a new window.
    passwords = {}
    try:
        with open("encrypted_passwords.txt", "rb") as f:
            for line in f:
                i = line.split(maxsplit=2)
                decrypted_username = decrypt_data(i[0])
                decrypted_password = decrypt_data(i[1])
                decrypted_additional_info = decrypt_data(i[2]) if len(i) > 2 else ""
                passwords[decrypted_username] = (
                    decrypted_password,
                    decrypted_additional_info,
                )
    except FileNotFoundError:
        messagebox.showerror("Error", "No passwords found!")
        return
    # Create a new window
    list_window = tk.Toplevel()
    list_window.title("Password List")
    list_window.geometry("600x300")
    list_window.configure(bg="#333333")
    # Create table in the new window
    columns = ("Username", "Password", "Additional Info")
    tree = ttk.Treeview(list_window, columns=columns, show="headings")
    tree.heading("Username", text="Username")
    tree.heading("Password", text="Password")
    tree.heading("Additional Info", text="Additional Info")
    tree.column("Username", width=150)
    tree.column("Password", width=200)
    tree.column("Additional Info", width=200)
    tree.pack(expand=True, fill="both", padx=10, pady=10)
    # Populate the table with data
    if passwords:
        for name, (password, additional_info) in passwords.items():
            tree.insert("", "end", values=(name, password, additional_info))
    else:
        messagebox.showinfo("Passwords", "Empty list!")


def delete():
    # Delete a specified user.
    username = simpledialog.askstring("Input", "Enter Username:")
    temp_passwords = []
    try:
        with open("encrypted_passwords.txt", "rb") as f:
            for line in f:
                i = line.split(maxsplit=2)
                decrypted_username = decrypt_data(i[0])
                if decrypted_username != username:
                    temp_passwords.append(line)
        with open("encrypted_passwords.txt", "wb") as f:
            for line in temp_passwords:
                f.write(line)
        messagebox.showinfo("Success", f"User {username} deleted successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Error deleting user {username}: {e}")


def open_main_window():
    # Opens the main application window after successful admin password entry.
    app = tk.Tk()
    app.geometry("700x300")
    app.title("Password Manager")
    app.configure(bg="#FFFFFF")  # background
    # Welcome text
    welcome_text = tk.Label(
        app,
        text="Manage your passwords securely.",
        bg="#FFFFFF",
        fg="#000000",
        font=("Arial", 16, "normal"),
    )
    welcome_text.pack(padx=20, pady=20)
    # Frame for buttons
    button_frame = tk.Frame(app, bg="#FFFFFF")
    button_frame.pack(padx=20, pady=20, fill="x")
    # Action Buttons
    buttonAdd = tk.Button(
        button_frame,
        text="Add user",
        command=add,
        bg="#333333",
        fg="#000000",
        font=("Arial", 12, "bold"),
        relief="flat",
    )
    buttonAdd.grid(row=1, column=0, padx=15, pady=8, sticky="we")
    buttonGet = tk.Button(
        button_frame,
        text="Search user",
        command=search,
        bg="#333333",
        fg="#000000",
        font=("Arial", 12, "bold"),
        relief="flat",
    )
    buttonGet.grid(row=1, column=1, padx=15, pady=8, sticky="we")
    buttonList = tk.Button(
        button_frame,
        text="List of passwords",
        command=list,
        bg="#333333",
        fg="#000000",
        font=("Arial", 12, "bold"),
        relief="flat",
    )
    buttonList.grid(row=1, column=2, padx=15, pady=8, sticky="we")
    buttonDelete = tk.Button(
        button_frame,
        text="Delete user",
        command=delete,
        bg="#333333",
        fg="#000000",
        font=("Arial", 12, "bold"),
        relief="flat",
    )
    buttonDelete.grid(row=1, column=3, padx=15, pady=8, sticky="we")
    app.mainloop()


if __name__ == "__main__":
    # Check admin password before opening the main window
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    if check_admin_password():
        open_main_window()
    else:
        root.destroy()
        