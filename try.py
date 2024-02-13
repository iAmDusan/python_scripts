import os
import bcrypt
import json
import random
import string
from rich.console import Console
from pyfiglet import Figlet
from rich.table import Table

console = Console()
figlet = Figlet(font='slant')

PASSWORDS_FILE = "passwords.json"
password_table = {}

def load_password_table():
    """Load the password table from a JSON file."""
    if os.path.exists(PASSWORDS_FILE):
        with open(PASSWORDS_FILE, "r") as file:
            return json.load(file)
    return {}

def save_password_table():
    """Save the password table to a JSON file."""
    with open(PASSWORDS_FILE, "w") as file:
        json.dump(password_table, file)

def hash_password_with_bcrypt(password):
    """Hash a password with bcrypt including salt."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed, salt

def check_password_strength(password):
    """Check the strength of a password."""
    if len(password) < 8:
        return "Weak"
    elif len(password) < 12:
        return "Moderate"
    else:
        return "Strong"

def generate_random_password(length=12, strength="Strong"):
    """Generate a random password of specified length and strength."""
    if strength == "Weak":
        chars = string.ascii_letters + string.digits
    elif strength == "Moderate":
        chars = string.ascii_letters + string.digits + string.punctuation
    else:
        chars = string.ascii_letters + string.digits + string.punctuation + string.ascii_lowercase + string.ascii_uppercase
    return ''.join(random.choice(chars) for _ in range(length))

def print_separator():
    console.print("=" * 60)

def print_header(header_text):
    print_separator()
    console.print(f"{header_text:^60}")
    print_separator()

def print_message(message, style=""):
    console.print(message, style=style)

def hash_password():
    print_header("Hash Password")
    password = input("Enter a password to hash: ")
    try:
        strength = check_password_strength(password)
        print_message(f"Password Strength: {strength}", style="blue")
        hashed_password, salt = hash_password_with_bcrypt(password)
        print_message("Password hashed successfully!", style="green")
        print_message(f"Hashed Password: {hashed_password.decode()}", style="green")
        print_message(f"Salt: {salt.decode()}", style="green")
        password_table[hashed_password.decode()] = {"plaintext": password, "salt": salt.decode()}
        save_password_table()
    except Exception as e:
        print_message(f"An error occurred: {e}", style="red")

def display_password_table():
    print_header("Password Table")
    if not password_table:
        print_message("Password table is empty.", style="yellow")
    else:
        table = Table()
        table.add_column("Hashed Password")
        table.add_column("Plaintext Password")
        table.add_column("Salt")
        for hashed_password, info in password_table.items():
            table.add_row(hashed_password, info["plaintext"], info["salt"])
        console.print(table)

def verify_password():
    print_header("Verify Password")
    print("You can verify a password by entering either the plaintext password or the hashed password.")
    print("If you have the hashed password, enter it directly.")
    print("If you have the plaintext password, it will be hashed and compared to the table.")
    print()

    choice = input("Enter 'p' to verify using plaintext password or 'h' to verify using hashed password: ").strip().lower()

    if choice == 'p':
        plaintext_password = input("Enter the plaintext password to verify: ")
        hashed_input_password = bcrypt.hashpw(plaintext_password.encode(), bcrypt.gensalt()).decode()
        print()
        print(f"Plaintext Password: {plaintext_password}")
        print(f"Hashed Password: {hashed_input_password}")
        print()
        print("Comparing hashed password with stored hashed passwords in the table:")
        for hashed_password, info in password_table.items():
            if info["plaintext"] == plaintext_password:
                print_message("Password verified successfully!", style="green")
                return
        print_message("Password verification failed.", style="red")
    elif choice == 'h':
        hashed_password = input("Enter the hashed password to verify: ")
        print()
        print(f"Hashed Password: {hashed_password}")
        print()
        print("Comparing hashed password with stored hashed passwords in the table:")
        for hashed, info in password_table.items():
            if hashed.startswith(hashed_password):
                print_message("Password verified successfully!", style="green")
                return
        print_message("Password verification failed.", style="red")
    else:
        print_message("Invalid choice. Please enter 'p' or 'h' only.", style="red")





def delete_password():
    print_header("Delete Password")
    hashed_password = input("Enter the hashed password to delete: ")
    if hashed_password in password_table:
        del password_table[hashed_password]
        save_password_table()
        print_message("Password deleted successfully!", style="green")
    else:
        print_message("Password not found in the table.", style="red")

def generate_password():
    print_header("Generate Password")
    length = int(input("Enter the length of the password: "))
    strength = input("Enter the desired strength (Weak/Moderate/Strong): ").capitalize()
    if strength not in ["Weak", "Moderate", "Strong"]:
        print_message("Invalid strength specified.", style="red")
        return
    password = generate_random_password(length, strength)
    print_message(f"Generated Password: {password}", style="green")

def display_about():
    print_header("About")
    console.print("This is a password hashing tool implemented in Python.", style="blue")
    console.print("It uses the bcrypt library for secure password hashing.", style="blue")
    console.print("Developed by Mike D.", style="blue")

def main_menu():
    while True:
        print_header("Password Hasher Menu")
        console.print("1. Hash a Password")
        console.print("2. Display Password Table")
        console.print("3. Verify a Password")
        console.print("4. Delete a Password")
        console.print("5. Generate a Password")
        console.print("6. About")
        console.print("7. Exit")
        print_separator()

        choice = input("Enter your choice (1-7): ").strip()

        if choice == "1":
            hash_password()
        elif choice == "2":
            display_password_table()
        elif choice == "3":
            verify_password()
        elif choice == "4":
            delete_password()
        elif choice == "5":
            generate_password()
        elif choice == "6":
            display_about()
        elif choice == "7":
            print("Exiting...")
            break
        else:
            print_message("Invalid choice. Please enter a number between 1-7.", style="red")
        
        input("Press Enter to continue...")

if __name__ == "__main__":
    password_table = load_password_table()
    title = figlet.renderText('Password Hasher')
    console.print(title, style="bold blue")
    main_menu()
