import hashlib
import os
import time
import mimetypes
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import webbrowser


class CryptoEngine:
    CHUNK_SIZE = 65536

    @staticmethod
    def calculate_sha256(filepath: str) -> str:
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(CryptoEngine.CHUNK_SIZE):
                sha256.update(chunk)
        return sha256.hexdigest()

    @staticmethod
    def compare_hashes(hash_calculated: str, hash_reference: str) -> bool:
        if not hash_calculated or not hash_reference:
            return False
        return hash_calculated.strip().lower() == hash_reference.strip().lower()


class FileMetadata:
    """Extrae metadatos del archivo para la tabla comparativa."""
    @staticmethod
    def extract(filepath: str) -> dict:
        stat_info = os.stat(filepath)
        mime_type, _ = mimetypes.guess_type(filepath)
        
        creation_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat_info.st_ctime))
        modified_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat_info.st_mtime))
        
        return {
            "name": os.path.basename(filepath),
            "type": mime_type or os.path.splitext(filepath)[1] or "Desconocido",
            "size": f"{stat_info.st_size:,} bytes",
            "created": creation_time,
            "modified": modified_time,
        }


class IntegrityApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Validador Criptográfico de Integridad y Forense - SHA-256 (CIB-06)")
        self.root.geometry("860x760")
        self.root.minsize(800, 700)

        self.current_hash = ""
        self.current_filepath = ""
        self.ref_filepath = ""
        self.meta_file1 = None
        self.meta_file2 = None

        self._build_ui()

    def _build_ui(self):
        main_frame = ttk.Frame(self.root, padding="14")
        main_frame.pack(fill=tk.BOTH, expand=True)

        lbl_title = ttk.Label(
            main_frame,
            text="Verificador de Integridad y Comparador de Archivos (SHA-256)",
            font=("Segoe UI", 13, "bold"),
        )
        lbl_title.pack(anchor=tk.W, pady=(0, 10))

        # --- SECCIÓN 1: Archivo Principal ---
        file_frame = ttk.LabelFrame(main_frame, text=" 1. Archivo Analizado (A) ", padding="8")
        file_frame.pack(fill=tk.X, pady=(0, 8))

        self.txt_filepath = ttk.Entry(file_frame, font=("Segoe UI", 9))
        self.txt_filepath.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))

        btn_browse = ttk.Button(file_frame, text="Examinar Archivo A", command=self.load_file)
        btn_browse.pack(side=tk.RIGHT)

        # --- SECCIÓN 2: Hash y VirusTotal ---
        hash_frame = ttk.LabelFrame(main_frame, text=" 2. Hash SHA-256 Calculado ", padding="8")
        hash_frame.pack(fill=tk.X, pady=(0, 8))

        self.txt_hash = ttk.Entry(hash_frame, font=("Consolas", 10), state="readonly")
        self.txt_hash.pack(fill=tk.X, pady=(0, 6))

        action_bar = ttk.Frame(hash_frame)
        action_bar.pack(fill=tk.X)

        btn_copy = ttk.Button(action_bar, text="Copiar Hash A", command=self.copy_hash_to_clipboard)
        btn_copy.pack(side=tk.LEFT, padx=(0, 8))

        self.btn_vt = ttk.Button(
            action_bar,
            text="Consultar Archivo A en VirusTotal",
            command=self.open_virustotal,
            state="disabled",
        )
        self.btn_vt.pack(side=tk.LEFT)

        # --- SECCIÓN 3: Referencia / Archivo B ---
        cmp_frame = ttk.LabelFrame(main_frame, text=" 3. Referencia de Validación ", padding="8")
        cmp_frame.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(cmp_frame, text="Hash de Referencia manual o carga de Archivo (B):").pack(anchor=tk.W)
        self.txt_reference = ttk.Entry(cmp_frame, font=("Consolas", 10))
        self.txt_reference.pack(fill=tk.X, pady=(3, 6))

        cmp_actions = ttk.Frame(cmp_frame)
        cmp_actions.pack(fill=tk.X)

        btn_load_ref = ttk.Button(
            cmp_actions,
            text="Cargar Archivo de Referencia (B)",
            command=self.load_reference_file,
        )
        btn_load_ref.pack(side=tk.LEFT, padx=(0, 8))

        btn_validate = ttk.Button(cmp_actions, text="Verificar Integridad", command=self.validate_integrity)
        btn_validate.pack(side=tk.RIGHT)

        # --- SECCIÓN 4: Veredicto Criptográfico ---
        verdict_frame = ttk.LabelFrame(main_frame, text=" 4. Veredicto de Integridad ", padding="8")
        verdict_frame.pack(fill=tk.X, pady=(0, 8))

        self.lbl_status = tk.Label(
            verdict_frame,
            text="SIN VERIFICAR",
            font=("Segoe UI", 11, "bold"),
            bg="#374151",
            fg="#f9fafb",
            padx=8,
            pady=6,
            relief=tk.GROOVE,
        )
        self.lbl_status.pack(fill=tk.X, pady=(0, 4))

        self.lbl_details = ttk.Label(
            verdict_frame,
            text="Seleccione un archivo e introduzca su referencia para evaluar el resumen SHA-256.",
            wraplength=800,
            font=("Segoe UI", 8),
        )
        self.lbl_details.pack(anchor=tk.W)

        # --- SECCIÓN 5: Tabla Comparativa de Metadatos ---
        table_frame = ttk.LabelFrame(main_frame, text=" 5. Tabla Comparativa de Propiedades Básicas ", padding="8")
        table_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("propiedad", "archivo_a", "archivo_b", "coincidencia")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=6)
        
        self.tree.heading("propiedad", text="Propiedad")
        self.tree.heading("archivo_a", text="Archivo Analizado (A)")
        self.tree.heading("archivo_b", text="Archivo Referencia (B)")
        self.tree.heading("coincidencia", text="¿Coincide?")

        self.tree.column("propiedad", width=140, anchor=tk.W)
        self.tree.column("archivo_a", width=250, anchor=tk.W)
        self.tree.column("archivo_b", width=250, anchor=tk.W)
        self.tree.column("coincidencia", width=90, anchor=tk.CENTER)

        self.tree.pack(fill=tk.BOTH, expand=True)

    def load_file(self):
        filepath = filedialog.askopenfilename()
        if not filepath:
            return

        try:
            self.current_filepath = filepath
            self.meta_file1 = FileMetadata.extract(filepath)
            
            self.txt_filepath.delete(0, tk.END)
            self.txt_filepath.insert(0, filepath)

            self.current_hash = CryptoEngine.calculate_sha256(filepath)
            self.txt_hash.config(state="normal")
            self.txt_hash.delete(0, tk.END)
            self.txt_hash.insert(0, self.current_hash)
            self.txt_hash.config(state="readonly")

            self.btn_vt.config(state="normal")
            self._update_table()
            self._reset_verdict()
        except Exception as e:
            messagebox.showerror("Error de Lectura", f"No se pudo procesar el archivo:\n{e}")

    def load_reference_file(self):
        filepath = filedialog.askopenfilename()
        if not filepath:
            return

        try:
            self.ref_filepath = filepath
            self.meta_file2 = FileMetadata.extract(filepath)
            ref_hash = CryptoEngine.calculate_sha256(filepath)
            
            self.txt_reference.delete(0, tk.END)
            self.txt_reference.insert(0, ref_hash)
            
            self._update_table()
            self.validate_integrity()
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo procesar el archivo de referencia:\n{e}")

    def _update_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        props = [
            ("Nombre", "name"),
            ("Tipo / Extensión", "type"),
            ("Tamaño", "size"),
            ("Fecha Creación/Inodo", "created"),
            ("Fecha Modificación", "modified"),
        ]

        for label, key in props:
            val_a = self.meta_file1.get(key, "—") if self.meta_file1 else "—"
            val_b = self.meta_file2.get(key, "—") if self.meta_file2 else "—"
            
            if self.meta_file1 and self.meta_file2:
                match = "SÍ" if val_a == val_b else "NO"
            else:
                match = "Pendiente"

            self.tree.insert("", tk.END, values=(label, val_a, val_b, match))

        hash_b = self.txt_reference.get().strip() or "—"
        match_hash = "—"
        if self.current_hash and hash_b != "—":
            match_hash = "SÍ" if CryptoEngine.compare_hashes(self.current_hash, hash_b) else "NO"

        self.tree.insert("", tk.END, values=("SHA-256 (Hash)", self.current_hash[:18] + "..." if self.current_hash else "—", hash_b[:18] + "..." if hash_b != "—" else "—", match_hash))

    def validate_integrity(self):
        if not self.current_hash:
            messagebox.showwarning("Atención", "Debe cargar un archivo principal primero.")
            return

        ref_hash = self.txt_reference.get().strip()
        if not ref_hash:
            messagebox.showwarning("Atención", "Debe ingresar un hash de referencia o cargar el archivo B.")
            return

        is_valid = CryptoEngine.compare_hashes(self.current_hash, ref_hash)
        self._update_table()

        if is_valid:
            self.lbl_status.config(
                text="✔ INTEGRIDAD VERIFICADA - EL ARCHIVO ES AUTÉNTICO",
                bg="#15803d",
                fg="#ffffff",
            )
            self.lbl_details.config(
                text="Los 256 bits del hash coinciden con exactitud matemática. El contenido analizado es idéntico a la referencia."
            )
        else:
            self.lbl_status.config(
                text="✖ ALERTA: INTEGRIDAD COMPROMETIDA / MODIFICADO",
                bg="#b91c1c",
                fg="#ffffff",
            )
            self.lbl_details.config(
                text="Discrepancia detectada (Efecto Avalancha). Al menos un bit difiere entre ambos archivos, independientemente de los metadatos."
            )

    def open_virustotal(self):
        if not self.current_hash:
            return
        vt_url = f"https://www.virustotal.com/gui/file/{self.current_hash}"
        webbrowser.open(vt_url)

    def copy_hash_to_clipboard(self):
        if self.current_hash:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.current_hash)
            messagebox.showinfo("Copiado", "Hash SHA-256 copiado al portapapeles.")

    def _reset_verdict(self):
        self.lbl_status.config(
            text="ARCHIVO PROCESADO - ESPERANDO COMPARACIÓN",
            bg="#1d4ed8",
            fg="#ffffff",
        )
        self.lbl_details.config(
            text="Establezca el hash esperado o cargue el archivo de referencia para ejecutar la verificación."
        )


if __name__ == "__main__":
    app_window = tk.Tk()
    app = IntegrityApp(app_window)
    app_window.mainloop()
