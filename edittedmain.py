import tkinter as tk
from tkinter import ttk, messagebox
import json, os, base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyperclip

class PasswordManager:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Password Manager")
        self.window.geometry("600x400")
        self.window.configure(bg="#f0f0f0")
        self.window.resizable(False, False)
        self.data_file = "passwords.txt"
        self.current_index = 0
        self.fernet = None

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
        self.main_frame.grid(row=0, column=0)
        style = ttk.Style()
        style.configure("TButton", padding=5)
        self.create_login_frame()
        self.create_password_frame()
        self.password_frame.grid_remove()

    def create_login_frame(self):
        self.login_frame = ttk.Frame(self.main_frame, padding="20")
        self.login_frame.grid(row=0, column=0, padx=140, pady=110)
        ttk.Label(self.login_frame, text="Master Password:", font=("Times New Roman", 12)).grid(row=0, column=0)
        self.master_password_entry = ttk.Entry(self.login_frame, show="*")
        self.master_password_entry.grid(row=0, column=1)
        ttk.Button(self.login_frame, text="Login", command=self.login).grid(row=1, column=1, pady=10)

    def create_password_frame(self):
        self.password_frame = ttk.Frame(self.main_frame, padding="20")
        self.password_frame.grid(row=0, column=0, padx=145, pady=80)

        fields = [("Website/Service:", "website_entry"), ("Username:", "username_entry"), ("Password:", "password_entry")]
        for idx, (label, attr) in enumerate(fields):
            ttk.Label(self.password_frame, text=label, font=("Times New Roman", 12)).grid(row=idx, column=0, pady=5)
            entry = ttk.Entry(self.password_frame, show="*" if "password" in attr else "")
            entry.grid(row=idx, column=1, pady=5)
            setattr(self, attr, entry)

        ttk.Button(self.password_frame, text="Save Password", command=self.save_password).grid(row=3, column=0, pady=10)
        ttk.Button(self.password_frame, text="View Passwords", command=self.view_passwords).grid(row=3, column=1, pady=10)

    def login(self):
        password = self.master_password_entry.get()
        if password != "1":
            messagebox.showerror("Error", "Incorrect master password")
            return

        salt = b'password_manager_salt'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.fernet = Fernet(key)
        self.login_frame.grid_remove()
        self.password_frame.grid()

    def save_password(self):
        website = self.website_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        if not all([website, username, password]):
            messagebox.showerror("Error", "Please fill in all fields")
            return

        with open(self.data_file, "r") as f:
            data = json.load(f)

        entry = {
            "index": self.current_index,
            "website": website,
            "username": self.fernet.encrypt(username.encode()).decode(),
            "password": self.fernet.encrypt(password.encode()).decode()
        }
        data["passwords"].append(entry)
        self.current_index += 1
        data["next_index"] = self.current_index

        with open(self.data_file, "w") as f:
            json.dump(data, f, indent=4)

        messagebox.showinfo("Success", "Password saved successfully!")
        self.clear_entries()

    def view_passwords(self):
        win = tk.Toplevel(self.window)
        win.title("Saved Passwords")
        win.geometry("800x500")
        tree = ttk.Treeview(win, columns=("Website", "Username", "Password", "Download"), show="headings")
        tree.pack(fill=tk.BOTH, expand=True)

        for col in ("Website", "Username", "Password", "Download"):
            tree.heading(col, text=col)
            tree.column(col, width=180 if col != "Download" else 80, anchor="center")

        self.password_data_items = {}

        def toggle_download(event):
            row_id = tree.identify_row(event.y)
            col = tree.identify_column(event.x)
            if col == "#4" and row_id in self.password_data_items:
                entry = self.password_data_items[row_id]
                entry["download_selected"] = not entry.get("download_selected", False)
                char = "✅" if entry["download_selected"] else "☐"
                vals = list(tree.item(row_id)['values'])
                vals[3] = char
                tree.item(row_id, values=vals)
                with open(self.data_file, "r") as f:
                    data = json.load(f)
                for e in data["passwords"]:
                    if e["index"] == entry["index"]:
                        e["download_selected"] = entry["download_selected"]
                        break
                with open(self.data_file, "w") as f:
                    json.dump(data, f, indent=4)

        tree.bind('<ButtonRelease-1>', toggle_download)

        def download_selected():
            selected = [v for v in self.password_data_items.values() if v.get("download_selected")]
            if not selected:
                messagebox.showwarning("Warning", "No password selected")
                return

            content = ""
            for e in selected:
                content += f"Website: {e['website']}\n"
                content += f"Username: {self.fernet.decrypt(e['username'].encode()).decode()}\n"
                content += f"Password: {self.fernet.decrypt(e['password'].encode()).decode()}\n"
                content += "-" * 40 + "\n"
                e["download_selected"] = False

            with open("downloaded_passwords.txt", "w") as f:
                f.write(content)

            with open(self.data_file, "r") as f:
                data = json.load(f)
            for e in data["passwords"]:
                e["download_selected"] = False
            with open(self.data_file, "w") as f:
                json.dump(data, f, indent=4)

            for iid, e in self.password_data_items.items():
                tree.item(iid, values=(e["website"],
                          self.fernet.decrypt(e["username"].encode()).decode(),
                          self.fernet.decrypt(e["password"].encode()).decode(),
                          "☐"))

            messagebox.showinfo("Success", "Passwords downloaded")

        def edit_selected():
            selected = tree.selection()
            if not selected:
                messagebox.showwarning("Warning", "Select one to edit")
                return
            iid = selected[0]
            entry = self.password_data_items[iid]

            edit_win = tk.Toplevel(win)
            edit_win.title("Edit")
            edit_win.geometry("300x200")
            w = ttk.Entry(edit_win)
            u = ttk.Entry(edit_win)
            p = ttk.Entry(edit_win, show="*")
            for val, e in zip([entry["website"],
                               self.fernet.decrypt(entry["username"].encode()).decode(),
                               self.fernet.decrypt(entry["password"].encode()).decode()], [w, u, p]):
                e.insert(0, val)
                e.pack(pady=5)

            def save():
                with open(self.data_file, "r") as f:
                    data = json.load(f)
                for e in data["passwords"]:
                    if e["index"] == entry["index"]:
                        e["website"] = w.get()
                        e["username"] = self.fernet.encrypt(u.get().encode()).decode()
                        e["password"] = self.fernet.encrypt(p.get().encode()).decode()
                        break
                with open(self.data_file, "w") as f:
                    json.dump(data, f, indent=4)
                edit_win.destroy()
                win.destroy()
                self.view_passwords()

            ttk.Button(edit_win, text="Save", command=save).pack(pady=5)

        def delete_selected():
            selected = tree.selection()
            if not selected:
                return
            iid = selected[0]
            index = self.password_data_items[iid]["index"]
            with open(self.data_file, "r") as f:
                data = json.load(f)
            data["passwords"] = [e for e in data["passwords"] if e["index"] != index]
            with open(self.data_file, "w") as f:
                json.dump(data, f, indent=4)
            tree.delete(iid)

        def copy_selected():
            selected = tree.selection()
            if not selected:
                return
            iid = selected[0]
            password = tree.item(iid)['values'][2]
            pyperclip.copy(password)

        btns = [("Edit", edit_selected), ("Delete", delete_selected),
                ("Copy", copy_selected), ("Download Selected", download_selected)]
        for txt, cmd in btns:
            ttk.Button(win, text=txt, command=cmd).pack(side=tk.LEFT, padx=5, pady=5)

        with open(self.data_file, "r") as f:
            for e in json.load(f)["passwords"]:
                try:
                    uname = self.fernet.decrypt(e["username"].encode()).decode()
                    pwd = self.fernet.decrypt(e["password"].encode()).decode()
                    check = "✅" if e.get("download_selected", False) else "☐"
                    iid = tree.insert("", "end", values=(e["website"], uname, pwd, check))
                    self.password_data_items[iid] = e
                except: continue

    def clear_entries(self):
        self.website_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    PasswordManager().run()
