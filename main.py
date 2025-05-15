import tkinter as tk
from tkinter import ttk, messagebox
from passlib.hash import pbkdf2_sha256
import json
import os
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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
        self.data_file = "passwords.txt"
        if not os.path.exists(self.data_file):
            with open(self.data_file, "w") as f:
                json.dump({}, f)
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
        self.login_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        ttk.Label(self.login_frame, text="Master Password:").grid(row=0, column=0, pady=5)
        self.master_password_entry = ttk.Entry(self.login_frame, show="*")
        self.master_password_entry.grid(row=0, column=1, pady=5)
        ttk.Button(self.login_frame, text="Login", command=self.login).grid(row=1, column=0, columnspan=2, pady=10)
        
    def create_password_frame(self):
        self.password_frame = ttk.Frame(self.main_frame, padding="20")
        self.password_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        ttk.Label(self.password_frame, text="Website/Service:").grid(row=0, column=0, pady=5)
        self.website_entry = ttk.Entry(self.password_frame)
        self.website_entry.grid(row=0, column=1, pady=5)
        ttk.Label(self.password_frame, text="Username:").grid(row=1, column=0, pady=5)
        self.username_entry = ttk.Entry(self.password_frame)
        self.username_entry.grid(row=1, column=1, pady=5)
        ttk.Label(self.password_frame, text="Password:").grid(row=2, column=0, pady=5)
        self.password_entry = ttk.Entry(self.password_frame, show="*")
        self.password_entry.grid(row=2, column=1, pady=5)
        ttk.Button(self.password_frame, text="Save Password", command=self.save_password).grid(row=3, column=0, pady=10)
        ttk.Button(self.password_frame, text="View Passwords", command=self.view_passwords).grid(row=3, column=1, pady=10)
        
    def login(self):
        password = self.master_password_entry.get()
        if password != "1":
            messagebox.showerror("Error", "Incorrect master password")
            return
        try:
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
        except Exception as e:
            messagebox.showerror("Error", f"Error during login: {str(e)}")
        
    def save_password(self):
        if not self.fernet:
            messagebox.showerror("Error", "Not logged in properly")
            return
        website = self.website_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        if not all([website, username, password]):
            messagebox.showerror("Error", "Please fill in all fields")
            return
        try:
            with open(self.data_file, "r") as f:
                data = json.load(f)
            if website not in data:
                data[website] = {}
            encrypted_username = self.fernet.encrypt(username.encode()).decode()
            encrypted_password = self.fernet.encrypt(password.encode()).decode()
            data[website][encrypted_username] = encrypted_password
            with open(self.data_file, "w") as f:
                json.dump(data, f)
            messagebox.showinfo("Success", "Password saved successfully!")
            self.clear_entries()
        except Exception as e:
            messagebox.showerror("Error", f"Error saving password: {str(e)}")
        
    def view_passwords(self):
        if not self.fernet:
            messagebox.showerror("Error", "Not logged in properly")
            return
        if self.view_window is not None and self.view_window.winfo_exists():
            self.view_window.lift()
            return
        self.view_window = tk.Toplevel(self.window)
        self.view_window.title("Saved Passwords")
        self.view_window.geometry("800x500")
        self.view_window.resizable(False, False)
        def on_view_window_close():
            self.view_window.destroy()
            self.view_window = None
        self.view_window.protocol("WM_DELETE_WINDOW", on_view_window_close)
        main_frame = ttk.Frame(self.view_window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        y_scrollbar = ttk.Scrollbar(tree_frame)
        y_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        x_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)
        x_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        tree = ttk.Treeview(tree_frame, columns=("Website", "Username", "Password"), 
                           show="headings", 
                           yscrollcommand=y_scrollbar.set,
                           xscrollcommand=x_scrollbar.set)
        y_scrollbar.config(command=tree.yview)
        x_scrollbar.config(command=tree.xview)
        tree.column("Website", width=200, minwidth=150)
        tree.column("Username", width=200, minwidth=150)
        tree.column("Password", width=300, minwidth=200)
        tree.heading("Website", text="Website")
        tree.heading("Username", text="Username")
        tree.heading("Password", text="Password")
        tree.pack(fill=tk.BOTH, expand=True)
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        def edit_selected():
            if self.edit_window is not None and self.edit_window.winfo_exists():
                self.edit_window.lift()
                return
            selected_item = tree.selection()
            if not selected_item:
                messagebox.showwarning("Warning", "Please select a password to edit")
                return
            current_values = tree.item(selected_item[0])['values']
            website, username, password = current_values
            self.edit_window = tk.Toplevel(self.view_window)
            self.edit_window.title("Edit Password")
            self.edit_window.geometry("400x400")
            self.edit_window.resizable(False, False)
            self.edit_window.transient(self.view_window)
            self.edit_window.grab_set()
            def on_edit_window_close():
                self.edit_window.grab_release()
                self.edit_window.destroy()
                self.edit_window = None
            self.edit_window.protocol("WM_DELETE_WINDOW", on_edit_window_close)
            ttk.Label(self.edit_window, text="Website:").pack(pady=5)
            website_entry = ttk.Entry(self.edit_window)
            website_entry.insert(0, website)
            website_entry.pack(pady=5)
            ttk.Label(self.edit_window, text="Username:").pack(pady=5)
            username_entry = ttk.Entry(self.edit_window)
            username_entry.insert(0, username)
            username_entry.pack(pady=5)
            ttk.Label(self.edit_window, text="Password:").pack(pady=5)
            password_entry = ttk.Entry(self.edit_window, show="*")
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
                    if website in data:
                        for encrypted_username in list(data[website].keys()):
                            try:
                                if self.fernet.decrypt(encrypted_username.encode()).decode() == username:
                                    del data[website][encrypted_username]
                                    break
                            except:
                                continue
                        if not data[website]:
                            del data[website]
                    if new_website not in data:
                        data[new_website] = {}
                    encrypted_username = self.fernet.encrypt(new_username.encode()).decode()
                    encrypted_password = self.fernet.encrypt(new_password.encode()).decode()
                    data[new_website][encrypted_username] = encrypted_password
                    with open(self.data_file, "w") as f:
                        json.dump(data, f)
                    if new_website != website or new_username != username:
                        tree.delete(selected_item[0])
                        tree.insert("", "end", values=(new_website, new_username, new_password))
                    else:
                        tree.item(selected_item[0], values=(new_website, new_username, new_password))
                    self.edit_window.destroy()
                    self.edit_window = None
                    messagebox.showinfo("Success", "Password updated successfully!")
                except Exception as e:
                    messagebox.showerror("Error", f"Error updating password: {str(e)}")
            save_frame = ttk.Frame(self.edit_window)
            save_frame.pack(fill=tk.X, pady=10)
            ttk.Button(save_frame, text="Save", command=save_changes).pack(pady=5)
        
        def delete_selected():
            selected_item = tree.selection()
            if not selected_item:
                messagebox.showwarning("Warning", "Please select a password to delete")
                return
            if not messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this password?"):
                return
            try:
                current_values = tree.item(selected_item[0])['values']
                website, username, password = current_values
                with open(self.data_file, "r") as f:
                    data = json.load(f)
                if website in data:
                    for encrypted_username in list(data[website].keys()):
                        try:
                            if self.fernet.decrypt(encrypted_username.encode()).decode() == username:
                                del data[website][encrypted_username]
                                break
                        except:
                            continue
                    if not data[website]:
                        del data[website]
                with open(self.data_file, "w") as f:
                    json.dump(data, f)
                tree.delete(selected_item[0])
                messagebox.showinfo("Success", "Password deleted successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Error deleting password: {str(e)}")
        
        ttk.Button(button_frame, text="Edit", command=edit_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete", command=delete_selected).pack(side=tk.LEFT, padx=5)
        
        try:
            with open(self.data_file, "r") as f:
                data = json.load(f)
            for website, users in data.items():
                for encrypted_username, encrypted_password in users.items():
                    try:
                        decrypted_username = self.fernet.decrypt(encrypted_username.encode()).decode()
                        decrypted_password = self.fernet.decrypt(encrypted_password.encode()).decode()
                        tree.insert("", "end", values=(website, decrypted_username, decrypted_password))
                    except:
                        tree.insert("", "end", values=(website, "Error decrypting", "Error decrypting"))
        except Exception as e:
            messagebox.showerror("Error", f"Error loading passwords: {str(e)}")
        
    def clear_entries(self):
        self.website_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        
    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = PasswordManager()
    app.run()
