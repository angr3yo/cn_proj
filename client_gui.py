# client_gui.py

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
from protocol import build_request, parse_response

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5050

def send_to_server(req_type, data):
    try:
        with socket.create_connection((SERVER_HOST, SERVER_PORT), timeout=5) as s:
            s.sendall(build_request(req_type, data))
            response = s.recv(8192)
            success, result = parse_response(response)
            return success, result
    except Exception as e:
        return False, f"Connection Error: {str(e)}"

# GUI functions
def resolve_dns():
    domain = entry.get().strip()
    if not domain:
        messagebox.showerror("Error", "Enter a domain name.")
        return
    success, res = send_to_server("DNS", domain)
    result_dns.set("✅ " + res if success else "❌ " + res)

def resolve_http():
    url = entry.get().strip()
    if not url:
        messagebox.showerror("Error", "Enter a URL.")
        return
    success, res = send_to_server("HTTP", url)
    result_http.set("✅ " + res if success else "❌ " + res)

def copy_result(var):
    app.clipboard_clear()
    app.clipboard_append(var.get())
    messagebox.showinfo("Copied", "📋 Result copied to clipboard.")

def save_result():
    data = f"DNS Result:\n{result_dns.get()}\n\nHTTP Result:\n{result_http.get()}"
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, "w") as f:
            f.write(data)
        messagebox.showinfo("Saved", f"💾 Results saved to:\n{file_path}")

def toggle_dark_mode():
    dark = dark_mode.get()
    bg, fg = ("#1e1e1e", "#f2f2f2") if dark else ("white", "black")
    style.theme_use("alt" if dark else "clam")
    dns_output.configure(background=bg, foreground=fg)
    http_output.configure(background=bg, foreground=fg)

# GUI Setup
app = tk.Tk()
app.title("Client: DNS + HTTP Resolver")
app.geometry("650x550")
app.resizable(True, True)

style = ttk.Style(app)
style.theme_use("clam")

dark_mode = tk.BooleanVar()
ttk.Checkbutton(app, text="🌙 Dark Mode", variable=dark_mode, command=toggle_dark_mode).pack(anchor="ne", padx=10, pady=5)

frame = ttk.Frame(app, padding=15)
frame.pack(fill=tk.BOTH, expand=True)

ttk.Label(frame, text="🌐 Enter Domain or URL:", font=("Consolas", 11)).pack(anchor="w")
entry = ttk.Entry(frame, font=("Consolas", 10), width=60)
entry.pack(pady=5)

btn_frame = ttk.Frame(frame)
btn_frame.pack(pady=10)
ttk.Button(btn_frame, text="🧠 Resolve DNS", command=resolve_dns).pack(side=tk.LEFT, padx=10)
ttk.Button(btn_frame, text="🚀 Resolve HTTP", command=resolve_http).pack(side=tk.LEFT, padx=10)
ttk.Button(btn_frame, text="💾 Save Result", command=save_result).pack(side=tk.LEFT, padx=10)

result_dns = tk.StringVar()
result_http = tk.StringVar()

ttk.Label(frame, text="📡 DNS Result:", font=("Consolas", 10, "bold")).pack(anchor="w")
dns_output = ttk.Label(frame, textvariable=result_dns, background="white", foreground="black",
                       padding=5, relief="sunken", wraplength=600, anchor="w", justify="left")
dns_output.pack(fill=tk.X, pady=2)
ttk.Button(frame, text="📋 Copy DNS", command=lambda: copy_result(result_dns)).pack(anchor="e", pady=(0, 10))

ttk.Label(frame, text="🌐 HTTP Result:", font=("Consolas", 10, "bold")).pack(anchor="w")
http_output = ttk.Label(frame, textvariable=result_http, background="white", foreground="black",
                        padding=5, relief="sunken", wraplength=600, anchor="w", justify="left")
http_output.pack(fill=tk.BOTH, expand=True, pady=2)
ttk.Button(frame, text="📋 Copy HTTP", command=lambda: copy_result(result_http)).pack(anchor="e", pady=(0, 5))

app.mainloop()
