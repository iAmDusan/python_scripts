import tkinter as tk
from tkinter import simpledialog, messagebox
from tkinter.ttk import Treeview
import hashlib
import secrets
import string

class PasswordHasherGUI:
    def __init__(self, master):
        self.master = master
        master.title("Password Hasher")

        # In-memory "database" for demonstration purposes
        self.passwords = {}

        # Button Setup
        self.hash_password_btn = tk.Button(master, text="Hash a Password", command=self.hash_password_dialog)
        self.hash_password_btn.pack()

        self.display_table_btn = tk.Button(master, text="Display Password Table", command=self.display_password_table)
        self.display_table_btn.pack()

        self.verify_password_btn = tk.Button(master, text="Verify a Password", command=self.verify_password)
        self.verify_password_btn.pack()

        self.delete_password_btn = tk.Button(master, text="Delete a Password", command=self.delete_password)
        self.delete_password_btn.pack()

        self.generate_password_btn = tk.Button(master, text="Generate a Password", command=self.generate_password)
        self.generate_password_btn.pack()

        self.about_btn = tk.Button(master, text="About", command=self.display_about)
        self.about_btn.pack()

        self.exit_btn = tk.Button(master, text="Exit", command=master.quit)
        self.exit_btn.pack()

    def hash_password(self, password):
        # Securely hash a password
        hasher = hashlib.sha256()
        hasher.update(password.encode('utf-8'))
        return hasher.hexdigest()

    def hash_password_dialog(self):
        user = simpledialog.askstring("Hash Password", "Enter the username:")
        password = simpledialog.askstring("Hash Password", "Enter the password to hash:")
        if user and password:
            hashed_password = self.hash_password(password)
            self.add_password_to_table(user, hashed_password)

    def display_password_table(self):
        password_table_window = tk.Toplevel(self.master)
        password_table_window.title("Password Table")

        tree = Treeview(password_table_window, columns=("User", "Hashed Password"), show="headings")
        tree.heading("User", text="User")
        tree.heading("Hashed Password", text="Hashed Password")

        for user, hashed_password in self.passwords.items():
            tree.insert("", "end", values=(user, hashed_password))

        tree.pack()

    def verify_password(self):
        user = simpledialog.askstring("Verify Password", "Enter the username:")
        password = simpledialog.askstring("Verify Password", "Enter the password to verify:")
        if user and password:
            hashed_input_password = self.hash_password(password)
            stored_hashed_password = self.passwords.get(user)
            if stored_hashed_password and hashed_input_password == stored_hashed_password:
                messagebox.showinfo("Verification Result", "Password is verified.")
            else:
                messagebox.showerror("Verification Result", "Password verification failed.")
        else:
            messagebox.showerror("Verification Result", "Username or password cannot be empty.")

    def delete_password(self):
        user_to_delete = simpledialog.askstring("Delete Password", "Enter the username to delete:")
        if user_to_delete and user_to_delete in self.passwords:
            del self.passwords[user_to_delete]
            messagebox.showinfo("Deletion Result", f"Password for {user_to_delete} deleted successfully.")
        else:
            messagebox.showerror("Deletion Result", "User not found.")

    def generate_password(self):
        length = 12  # or ask the user for the length
        characters = string.ascii_letters + string.digits + string.punctuation
        generated_password = ''.join(secrets.choice(characters) for i in range(length))
        messagebox.showinfo("Generated Password", f"The generated password is: {generated_password}")

    def display_about(self):
        messagebox.showinfo("About", "Password Hasher\nDeveloped by Mike D.")

    def add_password_to_table(self, user, hashed_password):
        if user not in self.passwords:
            self.passwords[user] = hashed_password
            messagebox.showinfo("Password Hashed", "Password hashed and added to the table.")
        else:
            messagebox.showerror("Duplicate User", "User already exists in the table.")

def main():
    root = tk.Tk()

    # Calculate the screen width and height
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    # Set the size of the window to be twice as large by default
    default_width = int(screen_width * 0.1)
    default_height = int(screen_height * 0.2)
    root.geometry(f"{default_width}x{default_height}")

    # Calculate the position to center the window on the screen
    x_position = (screen_width - default_width) // 2
    y_position = (screen_height - default_height) // 2
    root.geometry(f"+{x_position}+{y_position}")

    app = PasswordHasherGUI(root)
    
    root.mainloop()



if __name__ == "__main__":
    main()
