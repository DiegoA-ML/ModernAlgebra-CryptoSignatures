import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
import os
import shutil
import asyncio
import nest_asyncio
import datetime
import traceback
from PIL import Image, ImageTk

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

# --- Base de datos de usuarios con permisos ---
USERS = {
    "admin": {
        "password": "admin123",
        "role": "admin",
        "permissions": ["upload", "download", "sign", "manage_users"],
        "active": True
    },
    "user1": {
        "password": "password1", 
        "role": "user",
        "permissions": ["upload", "download", "sign"],
        "active": True
    },
    "user2": {
        "password": "password2",
        "role": "user", 
        "permissions": ["upload", "download"],
        "active": True
    }
}

# Log global de acciones
action_log = []

# --- Backend: inicialización del signer ---
def init_signer():
    try:
        key_path = os.path.join(BASE_DIR, "private.key")
        if not os.path.exists(key_path):
            raise FileNotFoundError(f"No encontré la clave privada en: {key_path}")
            
        cert_candidates = [f for f in os.listdir(BASE_DIR) if f.lower().endswith(('.pem', '.cer', '.crt'))]
        if not cert_candidates:
            raise FileNotFoundError(f"No encontré ningún certificado en: {BASE_DIR}")
            
        cert_path = os.path.join(BASE_DIR, cert_candidates[0])
        print(f"Usando certificado: {cert_path}")
        
        return signers.SimpleSigner.load(
            key_path,
            cert_path,
            key_passphrase=None
        )
    except Exception as e:
        print(f"Error inicializando signer: {e}")
        raise

# Firma asíncrona con mejor manejo de errores
async def _async_sign(in_path, out_path, signer):
    try:
        print(f"Iniciando firma de: {in_path}")
        with open(in_path, "rb") as inf:
            writer = IncrementalPdfFileWriter(inf)
            signed = await signers.async_sign_pdf(
                writer,
                signers.PdfSignatureMetadata(field_name="Signature1"),
                signer=signer
            )
        
        with open(out_path, "wb") as outf:
            outf.write(signed.getvalue())
        print(f"Firma completada: {out_path}")
        return True
    except Exception as e:
        print(f"Error en firma asíncrona: {e}")
        print(traceback.format_exc())
        raise

# Funciones de backend mejoradas

def upload_backend(src_path, user):
    filename = os.path.basename(src_path)
    dest = os.path.join(UPLOADS_DIR, filename)
    shutil.copy(src_path, dest)
    action_log.append(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} - {user} subió {filename}")
    return filename

def download_backend(filename, user):
    src = os.path.join(UPLOADS_DIR, filename)
    dest = os.path.join(BASE_DIR, filename)
    shutil.copy(src, dest)
    action_log.append(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} - {user} descargó {filename}")
    return dest

def sign_backend(filename, user):
    try:
        print(f"Iniciando proceso de firma para: {filename}")
        signer = init_signer()
        src = os.path.join(UPLOADS_DIR, filename)
        
        if not os.path.exists(src):
            raise FileNotFoundError(f"Archivo no encontrado: {src}")
            
        signed_name = filename.replace(".pdf", "_signed.pdf")
        dst = os.path.join(SIGNED_DIR, signed_name)
        
        # Ejecutar firma asíncrona
        success = asyncio.run(_async_sign(src, dst, signer))
        
        if success and os.path.exists(dst):
            action_log.append(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} - {user} firmó {filename}")
            print(f"Firma exitosa: {signed_name}")
            return signed_name
        else:
            raise Exception("La firma no se completó correctamente")
            
    except Exception as e:
        error_msg = f"Error firmando {filename}: {str(e)}"
        print(error_msg)
        print(traceback.format_exc())
        action_log.append(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} - ERROR: {user} intentó firmar {filename} - {str(e)}")
        raise Exception(error_msg)

# Funciones de gestión de usuarios
def user_has_permission(username, permission):
    user_data = USERS.get(username, {})
    return user_data.get("active", False) and permission in user_data.get("permissions", [])

def add_user_backend(username, password, role, permissions, admin_user):
    if username in USERS:
        raise ValueError(f"El usuario '{username}' ya existe")
    
    USERS[username] = {
        "password": password,
        "role": role,
        "permissions": permissions,
        "active": True
    }
    action_log.append(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} - {admin_user} creó usuario {username}")

def delete_user_backend(username, admin_user):
    if username not in USERS:
        raise ValueError(f"El usuario '{username}' no existe")
    if username == "admin":
        raise ValueError("No se puede eliminar al usuario admin")
    
    del USERS[username]
    action_log.append(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} - {admin_user} eliminó usuario {username}")

def update_user_permissions(username, permissions, admin_user):
    if username not in USERS:
        raise ValueError(f"El usuario '{username}' no existe")
    
    USERS[username]["permissions"] = permissions
    action_log.append(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} - {admin_user} actualizó permisos de {username}")

def toggle_user_status(username, admin_user):
    if username not in USERS:
        raise ValueError(f"El usuario '{username}' no existe")
    if username == "admin":
        raise ValueError("No se puede desactivar al usuario admin")
    
    current_status = USERS[username]["active"]
    USERS[username]["active"] = not current_status
    status = "activó" if not current_status else "desactivó"
    action_log.append(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} - {admin_user} {status} usuario {username}")

# --- Aplicación GUI ---
class FileApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Casa Monarca - Sistema de Firma Digital")
        self.root.geometry("800x800")
        self.root.configure(bg="#f0f2f5")

        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.current_user = None
        
        # Variables para gestión de usuarios
        self.user_management_window = None
        
        # Cargar imagen de fondo
        self.load_background_image()
        self.create_login_ui()

    def load_background_image(self):
        """Carga y prepara la imagen de fondo"""
        try:
            image_path = r"C:\Users\DAVIDOmenlap\Downloads\CasaMonarcafondo.jpeg"
            self.bg_image = Image.open(image_path)
            self.bg_image = self.bg_image.resize((800, 800), Image.Resampling.LANCZOS)
            self.bg_photo = ImageTk.PhotoImage(self.bg_image)
        except Exception as e:
            print(f"Error cargando imagen de fondo: {e}")
            self.bg_photo = None

    def create_login_ui(self):
        for w in self.root.winfo_children(): 
            w.destroy()
        
        # Canvas para la imagen de fondo
        if self.bg_photo:
            canvas = tk.Canvas(self.root, width=800, height=800)
            canvas.pack(fill="both", expand=True)
            canvas.create_image(0, 0, anchor="nw", image=self.bg_photo)
            
            main_frame = tk.Frame(canvas, bg="#ffffff", relief="raised", bd=2)
            main_frame.place(relx=0.5, rely=0.5, anchor="center", width=400, height=350)
        else:
            main_frame = tk.Frame(self.root, bg="#ffffff", relief="raised", bd=2)
            main_frame.pack(expand=True, fill="both", padx=50, pady=50)

        # Título principal
        title_label = tk.Label(
            main_frame, 
            text="Casa Monarca\nAyuda Humanitaria al Migrante A.B.P.",
            font=("Helvetica", 16, "bold"),
            fg="#2c5530",
            bg="#ffffff",
            justify="center"
        )
        title_label.pack(pady=(20, 30))

        subtitle_label = tk.Label(
            main_frame,
            text="Sistema de Firma Digital",
            font=("Helvetica", 12),
            fg="#666666",
            bg="#ffffff"
        )
        subtitle_label.pack(pady=(0, 20))

        # Campos de login
        tk.Label(main_frame, text="Usuario:", bg="#ffffff", font=("Helvetica", 10)).pack(pady=(10, 5))
        user_entry = tk.Entry(main_frame, textvariable=self.username_var, font=("Helvetica", 10), width=25)
        user_entry.pack(pady=(0, 10))
        
        tk.Label(main_frame, text="Contraseña:", bg="#ffffff", font=("Helvetica", 10)).pack(pady=(5, 5))
        pass_entry = tk.Entry(main_frame, textvariable=self.password_var, show="*", font=("Helvetica", 10), width=25)
        pass_entry.pack(pady=(0, 20))

        login_btn = tk.Button(
            main_frame, 
            text="Iniciar Sesión", 
            command=self.validate_login,
            bg="#2c5530",
            fg="white",
            font=("Helvetica", 11, "bold"),
            relief="raised",
            bd=2,
            padx=20,
            pady=8
        )
        login_btn.pack(pady=20)

        user_entry.focus()
        pass_entry.bind('<Return>', lambda event: self.validate_login())

    def validate_login(self):
        u = self.username_var.get()
        p = self.password_var.get()
        
        user_data = USERS.get(u, {})
        if user_data.get("password") == p and user_data.get("active", False):
            self.current_user = u
            self.create_main_ui()
        else:
            messagebox.showerror("Error", "Usuario o contraseña incorrectos, o usuario desactivado")

    def create_main_ui(self):
        for w in self.root.winfo_children(): 
            w.destroy()
        
        # Header
        header_frame = tk.Frame(self.root, bg="#2c5530", height=80)
        header_frame.pack(fill="x")
        header_frame.pack_propagate(False)
        
        tk.Label(
            header_frame, 
            text="Casa Monarca - Ayuda Humanitaria al Migrante A.B.P.",
            bg="#2c5530", 
            fg="white",
            font=("Helvetica", 14, "bold")
        ).pack(pady=10)
        
        user_info = USERS.get(self.current_user, {})
        role_text = f"({user_info.get('role', 'user')})"
        
        tk.Label(
            header_frame,
            text=f"Bienvenido, {self.current_user} {role_text}",
            bg="#2c5530",
            fg="#cccccc",
            font=("Helvetica", 10)
        ).pack()

        # Frame principal
        main_frame = tk.Frame(self.root, bg="#f0f2f5")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Botones principales con verificación de permisos
        btn_frame = tk.Frame(main_frame, bg="#f0f2f5")
        btn_frame.pack(pady=(0, 20))

        if user_has_permission(self.current_user, "upload"):
            tk.Button(btn_frame, text="Subir archivo PDF", width=30, command=self.upload_file, 
                     bg="#4CAF50", fg="white", font=("Helvetica", 10)).pack(pady=3)
        
        if user_has_permission(self.current_user, "download"):
            tk.Button(btn_frame, text="Descargar archivo PDF", width=30, command=self.download_file,
                     bg="#2196F3", fg="white", font=("Helvetica", 10)).pack(pady=3)
        
        if user_has_permission(self.current_user, "sign"):
            tk.Button(btn_frame, text="Firmar archivo seleccionado", width=30, command=self.gui_sign,
                     bg="#FF9800", fg="white", font=("Helvetica", 10)).pack(pady=3)
        
        if user_has_permission(self.current_user, "manage_users"):
            tk.Button(btn_frame, text="Gestión de Usuarios", width=30, command=self.open_user_management,
                     bg="#9C27B0", fg="white", font=("Helvetica", 10)).pack(pady=3)
            tk.Button(btn_frame, text="Debug Log", width=30, command=self.debug_log,
                     bg="#607D8B", fg="white", font=("Helvetica", 10)).pack(pady=3)
        
        tk.Button(btn_frame, text="Cerrar sesión", width=30, command=self.logout,
                 bg="#f44336", fg="white", font=("Helvetica", 10)).pack(pady=10)

        # Listados
        tk.Label(main_frame, text="Archivos subidos:", bg="#f0f2f5", font=("Helvetica", 11, "bold")).pack(pady=(15,2))
        self.file_listbox = tk.Listbox(main_frame, height=6, font=("Helvetica", 9))
        self.file_listbox.pack(fill="x", padx=20)
        tk.Button(main_frame, text="Refrescar subidos", command=self.refresh_file_list).pack(pady=5)

        tk.Label(main_frame, text="Archivos firmados:", bg="#f0f2f5", font=("Helvetica", 11, "bold")).pack(pady=(15,2))
        self.signed_listbox = tk.Listbox(main_frame, height=6, font=("Helvetica", 9))
        self.signed_listbox.pack(fill="x", padx=20)
        tk.Button(main_frame, text="Refrescar firmados", command=self.refresh_signed_list).pack(pady=5)

        # Status bar
        self.status_label = tk.Label(main_frame, text="Sistema iniciado correctamente", bg="#f0f2f5", anchor="w", font=("Helvetica", 9))
        self.status_label.pack(fill="x", padx=10, pady=(5,0))

        # Log para admin
        if user_has_permission(self.current_user, "manage_users"):
            tk.Label(main_frame, text="Log de actividades:", bg="#f0f2f5", font=("Helvetica", 11, "bold")).pack(pady=(15,2))
            
            # Frame para el log con scrollbar
            log_frame = tk.Frame(main_frame, bg="#f0f2f5")
            log_frame.pack(pady=10, fill="x")
            
            self.log_text = tk.Text(log_frame, height=8, width=70, font=("Helvetica", 8), wrap=tk.WORD)
            scrollbar = tk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
            self.log_text.config(yscrollcommand=scrollbar.set)
            
            self.log_text.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            
            # Inicializar log si está vacío
            if not action_log:
                action_log.append(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} - Sistema iniciado por {self.current_user}")
            
            self.update_log()

        # Inicializar listas
        self.refresh_file_list()
        self.refresh_signed_list()

    def refresh_file_list(self):
        self.file_listbox.delete(0, tk.END)
        try:
            for f in sorted(os.listdir(UPLOADS_DIR)):
                if not f.lower().endswith(".pdf"): 
                    continue
                path = os.path.join(UPLOADS_DIR, f)
                try:
                    with open(path, "rb") as fin:
                        hdr = fin.read(4)
                        if hdr != b"%PDF": 
                            raise ValueError("Cabecera no válida")
                    read_ok = True
                except Exception:
                    read_ok = False
                
                fecha = datetime.datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%S")
                flag = "" if read_ok else " ⚠"
                self.file_listbox.insert(tk.END, f"{f}    [{fecha}]{flag}")
        except Exception as e:
            self.status_label.config(text=f"Error listando archivos: {e}")
        
        self.status_label.config(text=f"{datetime.datetime.now():%H:%M:%S} – Listado actualizado")

    def refresh_signed_list(self):
        self.signed_listbox.delete(0, tk.END)
        try:
            for f in sorted(os.listdir(SIGNED_DIR)):
                if not f.lower().endswith(".pdf"): 
                    continue
                fecha = datetime.datetime.fromtimestamp(os.path.getmtime(os.path.join(SIGNED_DIR, f))).strftime("%Y-%m-%d %H:%M:%S")
                self.signed_listbox.insert(tk.END, f"{f}    [{fecha}]")
        except Exception as e:
            self.status_label.config(text=f"Error listando firmados: {e}")

    def upload_file(self):
        if not user_has_permission(self.current_user, "upload"):
            messagebox.showerror("Error", "No tienes permisos para subir archivos")
            return
            
        path = filedialog.askopenfilename(filetypes=[("PDF Files","*.pdf")])
        if path:
            try:
                fn = upload_backend(path, self.current_user)
                messagebox.showinfo("Éxito", f"'{fn}' subido correctamente.")
                self.refresh_file_list()
                if user_has_permission(self.current_user, "manage_users"):
                    self.update_log()
                    print(f"Log actualizado después de subir {fn}")
            except Exception as e:
                messagebox.showerror("Error", f"Error subiendo archivo: {e}")

    def download_file(self):
        if not user_has_permission(self.current_user, "download"):
            messagebox.showerror("Error", "No tienes permisos para descargar archivos")
            return
            
        sel = self.file_listbox.curselection()
        if not sel:
            return messagebox.showwarning("Atención","Selecciona un archivo subido.")
        
        entry = self.file_listbox.get(sel[0])
        filename = entry.split()[0]
        pwd = simpledialog.askstring("Verificar","Ingresa tu contraseña:",show="*")
        
        user_data = USERS.get(self.current_user, {})
        if user_data.get("password") == pwd:
            try:
                dst = download_backend(filename, self.current_user)
                messagebox.showinfo("Descarga", f"Guardado en: {dst}")
                if user_has_permission(self.current_user, "manage_users"):
                    self.update_log()
            except Exception as e:
                messagebox.showerror("Error", f"Error descargando: {e}")
        else:
            messagebox.showerror("Error","Contraseña incorrecta")

    def gui_sign(self):
        if not user_has_permission(self.current_user, "sign"):
            messagebox.showerror("Error", "No tienes permisos para firmar archivos")
            return
            
        sel = self.file_listbox.curselection()
        if not sel:
            return messagebox.showwarning("Atención","Selecciona un archivo subido.")
        
        entry = self.file_listbox.get(sel[0])
        filename = entry.split()[0]
        
        try:
            self.status_label.config(text=f"{datetime.datetime.now():%H:%M:%S} – Firmando '{filename}'…")
            self.root.update()  # Actualizar la interfaz
            
            signed_name = sign_backend(filename, self.current_user)
            
            self.status_label.config(text=f"{datetime.datetime.now():%H:%M:%S} – Firmado exitosamente: {signed_name}")
            messagebox.showinfo("Éxito", f"PDF firmado correctamente: {signed_name}")
            
            # Mostrar popup para abrir - ESTE ES EL POPUP QUE NO APARECÍA
            if messagebox.askyesno("Abrir PDF", "¿Deseas abrir el documento firmado?"):
                signed_path = os.path.join(SIGNED_DIR, signed_name)
                os.startfile(signed_path)
            
            self.refresh_signed_list()
            if user_has_permission(self.current_user, "manage_users"):
                self.update_log()
                print(f"Log actualizado después de firmar {signed_name}")
                print(f"Total entradas en log: {len(action_log)}")
                
        except Exception as e:
            error_msg = f"Error al firmar el documento: {str(e)}"
            self.status_label.config(text=f"{datetime.datetime.now():%H:%M:%S} – Error en firma")
            messagebox.showerror("Error de Firma", error_msg)
            print(f"Error detallado: {e}")

    def open_user_management(self):
        if self.user_management_window and self.user_management_window.winfo_exists():
            self.user_management_window.lift()
            return
            
        self.user_management_window = tk.Toplevel(self.root)
        self.user_management_window.title("Gestión de Usuarios - Casa Monarca")
        self.user_management_window.geometry("800x600")
        self.user_management_window.configure(bg="#f0f2f5")

        # Frame principal
        main_frame = tk.Frame(self.user_management_window, bg="#f0f2f5")
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Título
        tk.Label(main_frame, text="Gestión de Usuarios", font=("Helvetica", 16, "bold"), 
                bg="#f0f2f5").pack(pady=(0, 20))

        # Frame de botones
        btn_frame = tk.Frame(main_frame, bg="#f0f2f5")
        btn_frame.pack(fill="x", pady=(0, 10))

        tk.Button(btn_frame, text="Agregar Usuario", command=self.add_user_dialog, 
                 bg="#4CAF50", fg="white", width=15).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Editar Permisos", command=self.edit_permissions_dialog, 
                 bg="#FF9800", fg="white", width=15).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Activar/Desactivar", command=self.toggle_user_dialog, 
                 bg="#2196F3", fg="white", width=15).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Eliminar Usuario", command=self.delete_user_dialog, 
                 bg="#f44336", fg="white", width=15).pack(side="left", padx=5)
        tk.Button(btn_frame, text="Refrescar", command=self.refresh_user_list, 
                 bg="#9E9E9E", fg="white", width=10).pack(side="right", padx=5)

        # Lista de usuarios con Treeview
        columns = ("Usuario", "Rol", "Permisos", "Estado")
        self.user_tree = ttk.Treeview(main_frame, columns=columns, show="headings", height=15)
        
        for col in columns:
            self.user_tree.heading(col, text=col)
            self.user_tree.column(col, width=150)

        self.user_tree.pack(fill="both", expand=True, pady=10)

        # Scrollbar para la lista
        scrollbar_users = ttk.Scrollbar(main_frame, orient="vertical", command=self.user_tree.yview)
        scrollbar_users.pack(side="right", fill="y")
        self.user_tree.configure(yscrollcommand=scrollbar_users.set)

        self.refresh_user_list()

    def refresh_user_list(self):
        if not hasattr(self, 'user_tree'):
            return
            
        for item in self.user_tree.get_children():
            self.user_tree.delete(item)

        for username, user_data in USERS.items():
            permisos = ", ".join(user_data.get("permissions", []))
            estado = "Activo" if user_data.get("active", False) else "Inactivo"
            
            self.user_tree.insert("", "end", values=(
                username,
                user_data.get("role", "user"),
                permisos,
                estado
            ))

    def add_user_dialog(self):
        dialog = tk.Toplevel(self.user_management_window)
        dialog.title("Agregar Usuario")
        dialog.geometry("400x500")
        dialog.configure(bg="#ffffff")

        tk.Label(dialog, text="Nuevo Usuario", font=("Helvetica", 14, "bold"), 
                bg="#ffffff").pack(pady=20)

        # Usuario
        tk.Label(dialog, text="Nombre de usuario:", bg="#ffffff").pack()
        username_var = tk.StringVar()
        tk.Entry(dialog, textvariable=username_var, width=30).pack(pady=5)

        # Contraseña
        tk.Label(dialog, text="Contraseña:", bg="#ffffff").pack()
        password_var = tk.StringVar()
        tk.Entry(dialog, textvariable=password_var, show="*", width=30).pack(pady=5)

        # Rol
        tk.Label(dialog, text="Rol:", bg="#ffffff").pack()
        role_var = tk.StringVar(value="user")
        role_combo = ttk.Combobox(dialog, textvariable=role_var, values=["user", "admin"], width=27)
        role_combo.pack(pady=5)

        # Permisos
        tk.Label(dialog, text="Permisos:", bg="#ffffff").pack(pady=(10, 5))
        perm_frame = tk.Frame(dialog, bg="#ffffff")
        perm_frame.pack()

        perm_vars = {}
        permisos_disponibles = ["upload", "download", "sign", "manage_users"]
        for perm in permisos_disponibles:
            var = tk.BooleanVar()
            if perm != "manage_users":  # Por defecto todos menos manage_users
                var.set(True)
            perm_vars[perm] = var
            tk.Checkbutton(perm_frame, text=perm.replace("_", " ").title(), 
                          variable=var, bg="#ffffff").pack(anchor="w")

        def create_user():
            try:
                username = username_var.get().strip()
                password = password_var.get().strip()
                role = role_var.get()
                
                if not username or not password:
                    messagebox.showerror("Error", "Usuario y contraseña son obligatorios")
                    return
                
                permissions = [perm for perm, var in perm_vars.items() if var.get()]
                
                add_user_backend(username, password, role, permissions, self.current_user)
                messagebox.showinfo("Éxito", f"Usuario '{username}' creado correctamente")
                self.refresh_user_list()
                self.update_log()
                dialog.destroy()
                
            except Exception as e:
                messagebox.showerror("Error", str(e))

        tk.Button(dialog, text="Crear Usuario", command=create_user, 
                 bg="#4CAF50", fg="white", font=("Helvetica", 10, "bold")).pack(pady=20)

    def edit_permissions_dialog(self):
        selected = self.user_tree.selection()
        if not selected:
            messagebox.showwarning("Atención", "Selecciona un usuario")
            return

        username = self.user_tree.item(selected[0])["values"][0]
        user_data = USERS.get(username, {})

        dialog = tk.Toplevel(self.user_management_window)
        dialog.title(f"Editar Permisos - {username}")
        dialog.geometry("300x400")
        dialog.configure(bg="#ffffff")

        tk.Label(dialog, text=f"Permisos para: {username}", 
                font=("Helvetica", 12, "bold"), bg="#ffffff").pack(pady=20)

        perm_vars = {}
        permisos_disponibles = ["upload", "download", "sign", "manage_users"]
        current_perms = user_data.get("permissions", [])

        for perm in permisos_disponibles:
            var = tk.BooleanVar(value=perm in current_perms)
            perm_vars[perm] = var
            tk.Checkbutton(dialog, text=perm.replace("_", " ").title(), 
                          variable=var, bg="#ffffff").pack(anchor="w", padx=20)

        def update_perms():
            try:
                new_permissions = [perm for perm, var in perm_vars.items() if var.get()]
                update_user_permissions(username, new_permissions, self.current_user)
                messagebox.showinfo("Éxito", f"Permisos actualizados para {username}")
                self.refresh_user_list()
                self.update_log()
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("Error", str(e))

        tk.Button(dialog, text="Actualizar Permisos", command=update_perms, 
                 bg="#FF9800", fg="white").pack(pady=20)

    def toggle_user_dialog(self):
        selected = self.user_tree.selection()
        if not selected:
            messagebox.showwarning("Atención", "Selecciona un usuario")
            return

        username = self.user_tree.item(selected[0])["values"][0]
        user_data = USERS.get(username, {})
        current_status = "Activo" if user_data.get("active", False) else "Inactivo"
        new_status = "Inactivo" if current_status == "Activo" else "Activo"

        if messagebox.askyesno("Confirmar", f"¿Cambiar estado de {username} a {new_status}?"):
            try:
                toggle_user_status(username, self.current_user)
                messagebox.showinfo("Éxito", f"Estado de {username} cambiado a {new_status}")
                self.refresh_user_list()
                self.update_log()
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def delete_user_dialog(self):
        selected = self.user_tree.selection()
        if not selected:
            messagebox.showwarning("Atención", "Selecciona un usuario")
            return

        username = self.user_tree.item(selected[0])["values"][0]
        
        if messagebox.askyesno("Confirmar", f"¿Eliminar permanentemente al usuario {username}?"):
            try:
                delete_user_backend(username, self.current_user)
                messagebox.showinfo("Éxito", f"Usuario {username} eliminado")
                self.refresh_user_list()
                self.update_log()
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def debug_log(self):
        """Función para debuggear el log de actividades"""
        debug_info = f"""
=== DEBUG LOG ===
Total entradas en action_log: {len(action_log)}
Contenido del action_log:
{chr(10).join(action_log) if action_log else "VACÍO"}

Widget log_text existe: {hasattr(self, 'log_text')}
=================
        """
        
        print(debug_info)
        messagebox.showinfo("Debug Log", debug_info)
        
        # Agregar entrada de prueba
        action_log.append(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} - DEBUG: Prueba de log por {self.current_user}")
        self.update_log()

    def update_log(self):
        if hasattr(self, 'log_text'):
            self.log_text.delete(1.0, tk.END)
            if not action_log:
                self.log_text.insert(tk.END, "No hay actividades registradas aún.\n")
            else:
                for line in action_log[-20:]:  # Mostrar últimas 20 acciones
                    self.log_text.insert(tk.END, line + "\n")
            self.log_text.see(tk.END)  # Scroll al final
            self.log_text.update()  # Forzar actualización del widget

    def logout(self):
        self.username_var.set("")
        self.password_var.set("")
        if self.user_management_window and self.user_management_window.winfo_exists():
            self.user_management_window.destroy()
        self.create_login_ui()

if __name__ == "__main__":
    root = tk.Tk()
    app = FileApp(root)
    root.mainloop()