import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import os
import shutil
import asyncio
import nest_asyncio
import datetime

from pyhanko.sign import signers
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

# Permite correr asyncio en entornos tipo Jupyter
dummy_loop = asyncio.get_event_loop()
nest_asyncio.apply()

# --- Configuración de carpetas ---
BASE_DIR    = r"C:\Users\DAVIDOmenlap\Desktop\iwo"
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")
SIGNED_DIR  = os.path.join(BASE_DIR, "signed")
# Crear carpetas si no existen
os.makedirs(UPLOADS_DIR, exist_ok=True)
os.makedirs(SIGNED_DIR, exist_ok=True)

# --- Base de datos de usuarios ---
USERS = {
    "admin": "admin123",
    "user1": "password1",
    "user2": "password2"
}

# Log global de acciones (solo admin lo ve en UI)
action_log = []

# --- Backend: inicialización del signer ---
def init_signer():
    key_path = os.path.join(BASE_DIR, "private.key")
    cert_candidates = [f for f in os.listdir(BASE_DIR) if f.lower().endswith(('.pem', '.cer', '.crt'))]
    if not cert_candidates:
        raise FileNotFoundError(f"No encontré ningún certificado en: {BASE_DIR}")
    cert_path = os.path.join(BASE_DIR, cert_candidates[0])
    return signers.SimpleSigner.load(
        key_path,
        cert_path,
        key_passphrase=None
    )

# Firma asíncrona
async def _async_sign(in_path, out_path, signer):
    with open(in_path, "rb") as inf:
        writer = IncrementalPdfFileWriter(inf)
        signed = await signers.async_sign_pdf(
            writer,
            signers.PdfSignatureMetadata(field_name="Signature1"),
            signer=signer
        )
    with open(out_path, "wb") as outf:
        outf.write(signed.getvalue())

# Funciones de backend

def upload_backend(src_path, user):
    filename = os.path.basename(src_path)
    dest = os.path.join(UPLOADS_DIR, filename)
    shutil.copy(src_path, dest)
    action_log.append(f"{user} subió {filename}")
    return filename


def download_backend(filename, user):
    src = os.path.join(UPLOADS_DIR, filename)
    dest = os.path.join(BASE_DIR, filename)
    shutil.copy(src, dest)
    action_log.append(f"{user} descargó {filename}")
    return dest


def sign_backend(filename, user):
    signer = init_signer()
    src = os.path.join(UPLOADS_DIR, filename)
    signed_name = filename.replace(".pdf", "_signed.pdf")
    dst = os.path.join(SIGNED_DIR, signed_name)
    asyncio.run(_async_sign(src, dst, signer))
    action_log.append(f"{user} firmó {filename}")
    return signed_name

# --- Aplicación GUI ---
class FileApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CryptoSignatures - Panel de Archivos")
        self.root.geometry("600x600")
        self.root.configure(bg="#f0f2f5")

        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.current_user = None

        self.create_login_ui()

    def create_login_ui(self):
        for w in self.root.winfo_children(): w.destroy()
        tk.Label(self.root, text="Usuario:", bg="#f0f2f5").pack(pady=10)
        tk.Entry(self.root, textvariable=self.username_var).pack()
        tk.Label(self.root, text="Contraseña:", bg="#f0f2f5").pack(pady=10)
        tk.Entry(self.root, textvariable=self.password_var, show="*").pack()
        tk.Button(self.root, text="Iniciar sesión", command=self.validate_login).pack(pady=20)

    def validate_login(self):
        u = self.username_var.get(); p = self.password_var.get()
        if USERS.get(u) == p:
            self.current_user = u
            self.create_main_ui()
        else:
            messagebox.showerror("Error", "Usuario o contraseña incorrectos")

    def create_main_ui(self):
        for w in self.root.winfo_children(): w.destroy()
        tk.Label(self.root, text=f"Bienvenido, {self.current_user}", bg="#f0f2f5", font=("Helvetica",14)).pack(pady=10)

        tk.Button(self.root, text="Subir archivo PDF", width=20, command=self.upload_file).pack(pady=5)
        tk.Button(self.root, text="Descargar archivo PDF", width=20, command=self.download_file).pack(pady=5)
        tk.Button(self.root, text="Firmar archivo seleccionado", width=20, command=self.gui_sign).pack(pady=5)
        if self.current_user == "admin": tk.Button(self.root, text="Agregar nuevo usuario", width=20, command=self.add_user).pack(pady=5)
        tk.Button(self.root, text="Cerrar sesión", width=20, command=self.logout).pack(pady=10)

        # Listados
        tk.Label(self.root, text="Archivos subidos:", bg="#f0f2f5").pack(pady=(15,2))
        self.file_listbox = tk.Listbox(self.root, height=6)
        self.file_listbox.pack(fill="x", padx=20)
        tk.Button(self.root, text="Refrescar subidos", command=self.refresh_file_list).pack(pady=5)

        tk.Label(self.root, text="Archivos firmados:", bg="#f0f2f5").pack(pady=(15,2))
        self.signed_listbox = tk.Listbox(self.root, height=6)
        self.signed_listbox.pack(fill="x", padx=20)
        tk.Button(self.root, text="Refrescar firmados", command=self.refresh_signed_list).pack(pady=5)

        # Status bar
        self.status_label = tk.Label(self.root, text="", bg="#f0f2f5", anchor="w")
        self.status_label.pack(fill="x", padx=10, pady=(5,0))

        # Log para admin
        if self.current_user == "admin":
            self.log_text = tk.Text(self.root, height=6, width=70)
            self.log_text.pack(pady=10)
            self.update_log()

        # Inicializar listas
        self.refresh_file_list()
        self.refresh_signed_list()

    def refresh_file_list(self):
        self.file_listbox.delete(0, tk.END)
        for f in sorted(os.listdir(UPLOADS_DIR)):
            if not f.lower().endswith(".pdf"): continue
            path = os.path.join(UPLOADS_DIR, f)
            try:
                with open(path, "rb") as fin:
                    hdr = fin.read(4)
                    if hdr != b"%PDF": raise ValueError("Cabecera no válida")
                read_ok = True
            except Exception as e:
                read_ok = False
                messagebox.showerror("Error lectura", f"No se pudo leer '{f}': {e}")
            fecha = datetime.datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%S")
            flag = "" if read_ok else " ⚠"
            self.file_listbox.insert(tk.END, f"{f}    [{fecha}]{flag}")
        self.status_label.config(text=f"{datetime.datetime.now():%H:%M:%S} – Listado actualizado")

    def refresh_signed_list(self):
        self.signed_listbox.delete(0, tk.END)
        for f in sorted(os.listdir(SIGNED_DIR)):
            if not f.lower().endswith(".pdf"): continue
            fecha = datetime.datetime.fromtimestamp(os.path.getmtime(os.path.join(SIGNED_DIR, f))).strftime("%Y-%m-%d %H:%M:%S")
            self.signed_listbox.insert(tk.END, f"{f}    [{fecha}]")
        self.status_label.config(text=f"{datetime.datetime.now():%H:%M:%S} – Firmados listados")

    def upload_file(self):
        path = filedialog.askopenfilename(filetypes=[("PDF Files","*.pdf")])
        if path:
            fn = upload_backend(path, self.current_user)
            messagebox.showinfo("Éxito", f"'{fn}' subido.")
            self.refresh_file_list()
            if self.current_user=="admin": self.update_log()

    def download_file(self):
        sel = self.file_listbox.curselection()
        if not sel:
            return messagebox.showwarning("Atención","Selecciona un archivo subido.")
        entry = self.file_listbox.get(sel[0])
        filename = entry.split()[0]
        pwd = simpledialog.askstring("Verificar","Ingresa tu contraseña:",show="*")
        if USERS.get(self.current_user)==pwd:
            dst = download_backend(filename, self.current_user)
            messagebox.showinfo("Descarga", f"Guardado en: {dst}")
            if self.current_user=="admin": self.update_log()
        else:
            messagebox.showerror("Error","Contraseña incorrecta")

    def gui_sign(self):
        sel = self.file_listbox.curselection()
        if not sel:
            return messagebox.showwarning("Atención","Selecciona un archivo subido.")
        entry = self.file_listbox.get(sel[0])
        filename = entry.split()[0]
        self.status_label.config(text=f"{datetime.datetime.now():%H:%M:%S} – Firmando '{filename}'…")
        signed = sign_backend(filename, self.current_user)
        self.status_label.config(text=f"{datetime.datetime.now():%H:%M:%S} – Firmado: {signed}")
        messagebox.showinfo("Firmado", f"PDF creado: {signed}")
        #  Mostrar popup para abrir
        if messagebox.askyesno("Abrir PDF", "¿Deseas abrir el documento firmado? "):
            os.startfile(os.path.join(SIGNED_DIR, signed))
        self.refresh_signed_list()
        if self.current_user=="admin": self.update_log()

    def add_user(self):
        pwd = simpledialog.askstring("Admin","Contraseña admin:",show="*")
        if USERS.get("admin")==pwd:
            u = simpledialog.askstring("Nuevo","Usuario:")
            p = simpledialog.askstring("Nuevo","Contraseña:",show="*")
            if u and p:
                USERS[u]=p
                messagebox.showinfo("OK",f"Usuario '{u}' creado.")
            else:
                messagebox.showwarning("Warning","Datos incompletos.")
        else:
            messagebox.showerror("Error","Pwd admin incorrecta")

    def update_log(self):
        self.log_text.delete(1.0, tk.END)
        for line in action_log[-6:]: self.log_text.insert(tk.END,line+"\n")

    def logout(self):
        self.username_var.set("")
        self.password_var.set("")
        self.create_login_ui()

if __name__ == "__main__":
    root = tk.Tk()
    app = FileApp(root)
    root.mainloop()
