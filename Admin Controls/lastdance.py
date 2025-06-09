import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import os
import shutil
import asyncio
import nest_asyncio
import datetime

from pyhanko.sign import signers
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

# Permite asyncio en entornos tipo Jupyter
nest_asyncio.apply()

# --- Configuración de carpetas ---
BASE_DIR       = r"C:\Users\DAVIDOmenlap\Desktop\iwo"
UPLOADS_DIR    = os.path.join(BASE_DIR, "uploads")
SIGNED_DIR     = os.path.join(BASE_DIR, "signed")
DOWNLOADS_DIR  = os.path.join(BASE_DIR, "downloads")
for d in (UPLOADS_DIR, SIGNED_DIR, DOWNLOADS_DIR):
    os.makedirs(d, exist_ok=True)

# --- Base de datos de usuarios ---
USERS = {
    "admin": "admin123",
    "user1": "password1",
    "user2": "password2",
}

# Log global de acciones (solo admin lo ve)
action_log = []

# --- Inicialización del signer ---
def init_signer():
    key_path = os.path.join(BASE_DIR, "private.key")
    certs = [f for f in os.listdir(BASE_DIR) if f.lower().endswith(('.pem', '.cer', '.crt'))]
    if not certs:
        raise FileNotFoundError(f"No encontré certificado en: {BASE_DIR}")
    cert_path = os.path.join(BASE_DIR, certs[0])
    return signers.SimpleSigner.load(key_path, cert_path, key_passphrase=None)

# Firma asíncrona - CORREGIDO: agregada palabra clave 'async'
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

# --- Backend functions ---
def upload_backend(src_path, user):
    fname = os.path.basename(src_path)
    dest = os.path.join(UPLOADS_DIR, fname)
    shutil.copy(src_path, dest)
    action_log.append(f"{user} subió {fname}")
    return fname

def download_backend(fname, user):
    src = os.path.join(UPLOADS_DIR, fname)
    dest = os.path.join(DOWNLOADS_DIR, fname)
    shutil.copy(src, dest)
    action_log.append(f"{user} descargó {fname}")
    return dest

def sign_backend(fname, user):
    signer = init_signer()
    src = os.path.join(UPLOADS_DIR, fname)
    signed_name = fname.replace(".pdf", "_signed.pdf")
    dst = os.path.join(SIGNED_DIR, signed_name)
    asyncio.run(_async_sign(src, dst, signer))
    action_log.append(f"{user} firmó {fname}")
    return signed_name

# --- Aplicación GUI ---
class FileApp:
    def __init__(self, root):
        self.root = root
        root.title("CryptoSignatures - Panel de Archivos")
        root.geometry("620x650")
        root.configure(bg="#f0f2f5")
        self.user_var = tk.StringVar()
        self.pw_var = tk.StringVar()
        self.current_user = None
        self.create_login_ui()

    def create_login_ui(self):
        for w in self.root.winfo_children(): w.destroy()
        tk.Label(self.root, text="Usuario:", bg="#f0f2f5").pack(pady=10)
        tk.Entry(self.root, textvariable=self.user_var).pack()
        tk.Label(self.root, text="Contraseña:", bg="#f0f2f5").pack(pady=10)
        tk.Entry(self.root, textvariable=self.pw_var, show="*").pack()
        tk.Button(self.root, text="Iniciar sesión", width=20, command=self.validate_login).pack(pady=20)

    def validate_login(self):
        u,p = self.user_var.get(), self.pw_var.get()
        if USERS.get(u)==p:
            self.current_user=u; self.create_main_ui()
        else:
            messagebox.showerror("Error","Usuario o contraseña incorrectos")

    def create_main_ui(self):
        for w in self.root.winfo_children(): w.destroy()
        tk.Label(self.root, text=f"Bienvenido, {self.current_user}", bg="#f0f2f5", font=("Helvetica",14)).pack(pady=10)
        # Botones
        tk.Button(self.root, text="Subir PDF", width=20, command=self.upload_file).pack(pady=5)
        tk.Button(self.root, text="Descargar PDF", width=20, command=self.download_file).pack(pady=5)
        tk.Button(self.root, text="Firmar PDF seleccionado", width=20, command=self.gui_sign).pack(pady=5)
        if self.current_user=="admin":
            tk.Button(self.root, text="Agregar usuario", width=20, command=self.add_user).pack(pady=5)
        tk.Button(self.root, text="Cerrar sesión", width=20, command=self.logout).pack(pady=10)
        # Listas
        self._make_list_section("Archivos subidos:", self.refresh_file_list)
        self._make_list_section("Archivos firmados:", self.refresh_signed_list, signed=True)
        if self.current_user=="admin":
            self._make_list_section("Archivos descargados:", self.refresh_download_list, downloads=True)
        # Status y log
        self.status_label = tk.Label(self.root, text="", bg="#f0f2f5", anchor="w")
        self.status_label.pack(fill='x', padx=10, pady=(5,0))
        if self.current_user=="admin":
            self.log_text = tk.Text(self.root, height=6)
            self.log_text.pack(pady=10)
            self.update_log()
        # Inicializar
        self.refresh_file_list(); self.refresh_signed_list()
        if self.current_user=="admin": self.refresh_download_list()

    def _make_list_section(self, label, refresh_fn, signed=False, downloads=False):
        tk.Label(self.root, text=label, bg="#f0f2f5").pack(pady=(15,2))
        lb = tk.Listbox(self.root, height=6)
        lb.pack(fill='x', padx=20)
        tk.Button(self.root, text=f"Refrescar {label.lower()}", command=refresh_fn).pack(pady=5)
        attr = 'file_listbox' if not signed and not downloads else ('signed_listbox' if signed else 'download_listbox')
        setattr(self, attr, lb)

    def refresh_file_list(self):
        self.file_listbox.delete(0,tk.END)
        for f in sorted(os.listdir(UPLOADS_DIR)):
            if not f.lower().endswith('.pdf'): continue
            path=os.path.join(UPLOADS_DIR,f)
            try:
                with open(path,'rb') as fin:
                    if fin.read(4)!=b'%PDF': raise ValueError
                ok=True
            except:
                ok=False
            ts=datetime.datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%S")
            flag='' if ok else ' ⚠'
            self.file_listbox.insert(tk.END,f"{f}    [{ts}]{flag}")
        self.status_label.config(text=f"{datetime.datetime.now():%H:%M:%S} – Subidos listados")

    def refresh_signed_list(self):
        self.signed_listbox.delete(0,tk.END)
        for f in sorted(os.listdir(SIGNED_DIR)):
            if not f.lower().endswith('.pdf'): continue
            ts=datetime.datetime.fromtimestamp(os.path.getmtime(os.path.join(SIGNED_DIR,f))).strftime("%Y-%m-%d %H:%M:%S")
            self.signed_listbox.insert(tk.END,f"{f}    [{ts}]")
        self.status_label.config(text=f"{datetime.datetime.now():%H:%M:%S} – Firmados listados")

    def refresh_download_list(self):
        self.download_listbox.delete(0,tk.END)
        for f in sorted(os.listdir(DOWNLOADS_DIR)):
            if not f.lower().endswith('.pdf'): continue
            ts=datetime.datetime.fromtimestamp(os.path.getmtime(os.path.join(DOWNLOADS_DIR,f))).strftime("%Y-%m-%d %H:%M:%S")
            self.download_listbox.insert(tk.END,f"{f}    [{ts}]")
        self.status_label.config(text=f"{datetime.datetime.now():%H:%M:%S} – Descargas listadas")

    def upload_file(self):
        p=filedialog.askopenfilename(filetypes=[('PDF','*.pdf')])
        if p:
            fn=upload_backend(p,self.current_user)
            messagebox.showinfo('Éxito',f"'{fn}' subido.")
            self.refresh_file_list();
            if self.current_user=='admin': self.update_log()

    def download_file(self):
        sel=self.file_listbox.curselection()
        if not sel: return messagebox.showwarning('Atención','Selecciona un subido.')
        entry=self.file_listbox.get(sel[0]); fname=entry.split()[0]
        pwd=simpledialog.askstring('Verificar','Ingresa contraseña:',show='*')
        if USERS.get(self.current_user)==pwd:
            dst=download_backend(fname,self.current_user)
            messagebox.showinfo('Descarga',f"Guardado en: {dst}")
            if self.current_user=='admin': self.refresh_download_list(); self.update_log()
        else:
            messagebox.showerror('Error','Contraseña incorrecta')

    def gui_sign(self):
        sel=self.file_listbox.curselection()
        if not sel: return messagebox.showwarning('Atención','Selecciona un subido.')
        fname=self.file_listbox.get(sel[0]).split()[0]
        self.status_label.config(text=f"{datetime.datetime.now():%H:%M:%S} – Firmando '{fname}'…")
        signed=sign_backend(fname,self.current_user)
        self.status_label.config(text=f"{datetime.datetime.now():%H:%M:%S} – Firmado: {signed}")
        messagebox.showinfo('Firmado',f"PDF creado: {signed}")
        if messagebox.askyesno('Abrir PDF','¿Abrir documento firmado?'):
            os.startfile(os.path.join(SIGNED_DIR,signed))
        self.refresh_signed_list()
        if self.current_user=='admin': self.update_log()

    def add_user(self):
        pwd=simpledialog.askstring('Admin','Pwd admin:',show='*')
        if USERS.get('admin')==pwd:
            u=simpledialog.askstring('Nuevo','Usuario:'); p=simpledialog.askstring('Nuevo','Pwd:',show='*')
            if u and p: USERS[u]=p; messagebox.showinfo('OK',f"Usuario '{u}' creado.")
        else: messagebox.showerror('Error','Pwd admin incorrecta')

    def update_log(self):
        self.log_text.delete(1.0,tk.END)
        for l in action_log[-6:]: self.log_text.insert(tk.END,l+'\n')

    def logout(self):
        self.user_var.set(''); self.pw_var.set('')
        self.create_login_ui()

if __name__=='__main__':
    root=tk.Tk()
    FileApp(root)
    root.mainloop()