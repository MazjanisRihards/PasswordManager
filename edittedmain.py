import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyperclip

class PasswordNode:
    def __init__(self, website, username, password):
        self.website = website
        self.username = username
        self.password = password
        self.next = None

class PasswordList:
    def __init__(self):
        self.head = None
    
    def add(self, website, username, password):
        new_node = PasswordNode(website, username, password)
        if not self.head:
            self.head = new_node
        else:
            current = self.head
            while current.next:
                current = current.next
            current.next = new_node
    
    def to_list(self):
        result = []
        current = self.head
        while current:
            result.append((current.website, current.username, current.password))
            current = current.next
        return result

class PasswordManager:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Password Manager")
        self.window.geometry("600x400")
        self.window.configure(bg="#f0f0f0")
        self.window.resizable(False, False)
        self.fernet = None
        self.encryption_key = None
        self.view_window = None
        self.edit_window = None
        self.download_window = None
        self.data_file = "passwords.txt"
        self.current_index = 0
        if not os.path.exists(self.data_file):
            with open(self.data_file, "w") as f:
                json.dump({"passwords": [], "next_index": 0}, f)
        else:
            with open(self.data_file, "r") as f:
                data = json.load(f)
                self.current_index = data.get("next_index", 0)
        self.setup_ui()
        
    def setup_ui(self):
        self.main_frame = ttk.Frame(self.window, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        style = ttk.Style()
        style.configure("TButton", padding=5)
        style.configure("TEntry", padding=5)
        self.create_login_frame()
        self.create_password_frame()
        self.password_frame.grid_remove()
        
    def create_login_frame(self):
        self.login_frame = ttk.Frame(self.main_frame, padding="20")
        self.login_frame.grid(row=0, column=0, padx=140, pady=110, sticky=(tk.W, tk.E, tk.N, tk.S))
        ttk.Label(self.login_frame, text="Master Password:", font=("Times New Roman", 12)).grid(row=0, column=0, pady=5)
        self.master_password_entry = ttk.Entry(self.login_frame, show="*")
        self.master_password_entry.grid(row=0, column=1, pady=5)
        ttk.Button(self.login_frame, text="Login", command=self.login).grid(row=1, column=1, columnspan=2, pady=10)
        
    def create_password_frame(self):
        self.password_frame = ttk.Frame(self.main_frame, padding="20")
        self.password_frame.grid(row=0, column=0, padx=145, pady=80, sticky=(tk.W, tk.E, tk.N, tk.S))
        ttk.Label(self.password_frame, text="Website/Service:",font=("Times New Roman", 12)).grid(row=0, column=0, pady=5)
        self.website_entry = ttk.Entry(self.password_frame)
        self.website_entry.grid(row=0, column=1, pady=5)
        ttk.Label(self.password_frame, text="Username:",font=("Times New Roman", 12)).grid(row=1, column=0, pady=5)
        self.username_entry = ttk.Entry(self.password_frame)
        self.username_entry.grid(row=1, column=1, pady=5)
        ttk.Label(self.password_frame, text="Password:",font=("Times New Roman", 12)).grid(row=2, column=0, pady=5)
        self.password_entry = ttk.Entry(self.password_frame, show="*")
        self.password_entry.grid(row=2, column=1, pady=5)
        ttk.Button(self.password_frame, text="Save Password", command=self.save_password).grid(row=3, column=0, pady=10)
        ttk.Button(self.password_frame, text="View Passwords", command=self.view_passwords).grid(row=3, column=1, pady=10)
        
    def login(self):
        password = self.master_password_entry.get()
        if password != "1":
            messagebox.showerror("Error", "Incorrect master password")
            return
        salt = b'password_manager_salt'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        self.encryption_key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.fernet = Fernet(self.encryption_key)
        self.login_frame.grid_remove()
        self.password_frame.grid()
        
    def save_password(self):
        website = self.website_entry.get()
        username = self.username_entry.get()
        password = str(self.password_entry.get())
        if not all([website, username, password]):
            messagebox.showerror("Error", "Please fill in all fields")
            return
            
        with open(self.data_file, "r") as f:
            data = json.load(f)
            
       
        encrypted_username = self.fernet.encrypt(str(username).encode()).decode()
        encrypted_password = self.fernet.encrypt(str(password).encode()).decode()
        
        new_entry = {
            "index": self.current_index,
            "website": website,
            "username": encrypted_username,
            "password": encrypted_password
        }
        
        data["passwords"].append(new_entry)
        data["next_index"] = self.current_index + 1
        self.current_index += 1
        
        with open(self.data_file, "w") as f:
            json.dump(data, f, indent=4)
            
        messagebox.showinfo("Success", "Password saved successfully!")
        self.clear_entries()
        
    def view_passwords(self):
        self.view_window = tk.Toplevel(self.window)
        self.view_window.title("Saved Passwords")
        self.view_window.geometry("800x500")
        self.view_window.resizable(False, False)
        
        main_frame = ttk.Frame(self.view_window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        tree = ttk.Treeview(tree_frame, columns=("Index", "Website", "Username", "Password"), show="headings")
        tree.column("Index", width=0, stretch=False)  
        tree.column("Website", width=200)
        tree.column("Username", width=200)
        tree.column("Password", width=300)
        tree.heading("Index", text="")
        tree.heading("Website", text="Website")
        tree.heading("Username", text="Username")
        tree.heading("Password", text="Password")
        tree.pack(fill=tk.BOTH, expand=True)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        def edit_selected():
            selected_item = tree.selection()
            if not selected_item:
                messagebox.showwarning("Warning", "Please select a password to edit")
                return
                
            current_values = tree.item(selected_item[0])['values']
            index = current_values[0]
            website = current_values[1]
            username = current_values[2]
            password = current_values[3]

            edit_window = tk.Toplevel(self.view_window)
            edit_window.title("Edit Password")
            edit_window.geometry("400x300")
            edit_window.resizable(False, False)
            
            ttk.Label(edit_window, text="Website:").pack(pady=5)
            website_entry = ttk.Entry(edit_window)
            website_entry.insert(0, website)
            website_entry.pack(pady=5)
            
            ttk.Label(edit_window, text="Username:").pack(pady=5)
            username_entry = ttk.Entry(edit_window)
            username_entry.insert(0, username)
            username_entry.pack(pady=5)
            
            ttk.Label(edit_window, text="Password:").pack(pady=5)
            password_entry = ttk.Entry(edit_window, show="*")
            password_entry.insert(0, password)
            password_entry.pack(pady=5)
            
            def save_changes():
                new_website = website_entry.get()
                new_username = username_entry.get()
                new_password = password_entry.get()
                
                if not all([new_website, new_username, new_password]):
                    messagebox.showerror("Error", "Please fill in all fields")
                    return
                
                try:
                    with open(self.data_file, "r") as f:
                        data = json.load(f)
                    
                    for entry in data["passwords"]:
                        if entry["index"] == index:
                            entry["website"] = new_website
                            entry["username"] = self.fernet.encrypt(str(new_username).encode()).decode()
                            entry["password"] = self.fernet.encrypt(str(new_password).encode()).decode()
                            break
                    
                    with open(self.data_file, "w") as f:
                        json.dump(data, f, indent=4)
                    
                   
                    tree.item(selected_item[0], values=(index, new_website, new_username, new_password))
                    edit_window.destroy()
                    messagebox.showinfo("Success", "Password updated successfully!")
                except Exception as e:
                    messagebox.showerror("Error", f"Error updating password: {str(e)}")
            
            ttk.Button(edit_window, text="Save Changes", command=save_changes).pack(pady=10)
        
        def delete_selected():
            selected_item = tree.selection()
            if not selected_item:
                messagebox.showwarning("Warning", "Please select a password to delete")
                return
            if not messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this password?"):
                return
            
            try:
                current_values = tree.item(selected_item[0])['values']
                index = current_values[0]
                
                with open(self.data_file, "r") as f:
                    data = json.load(f)
                
     
                data["passwords"] = [p for p in data["passwords"] if p["index"] != index]
                
                with open(self.data_file, "w") as f:
                    json.dump(data, f, indent=4)
                
                tree.delete(selected_item[0])
                messagebox.showinfo("Success", "Password deleted successfully!")
            except Exception as e:
                print(f"Error during deletion: {e}")
                messagebox.showerror("Error", f"Error deleting password: {str(e)}")
        
        def copy_selected():
            selected_item = tree.selection()
            if not selected_item:
                messagebox.showwarning("Warning", "Please select a password to copy")
                return
            current_values = tree.item(selected_item[0])['values']
            password = current_values[3]  
            pyperclip.copy(password)
        
        ttk.Button(button_frame, text="Edit", command=edit_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete", command=delete_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Copy password to clipboard", command=copy_selected).pack(side=tk.LEFT, padx=5)
        
   
        with open(self.data_file, "r") as f:
            data = json.load(f)
            
        for entry in data["passwords"]:
            try:
                decrypted_username = self.fernet.decrypt(entry["username"].encode()).decode()
                decrypted_password = self.fernet.decrypt(entry["password"].encode()).decode()
                tree.insert("", "end", values=(
                    entry["index"],
                    entry["website"],
                    decrypted_username,
                    decrypted_password
                ))
            except Exception as e:
                print(f"Error decrypting entry: {e}")
        
    def clear_entries(self):
        self.website_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        
    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = PasswordManager()
    app.run()
