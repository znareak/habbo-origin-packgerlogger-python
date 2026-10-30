"""Interfaz grafica del Packet Logger (Tkinter).

Caracteristicas:
  - Pestañas por fuente (captura Npcap o archivo). Click derecho en la pestaña:
    Flotar, Dividir, Cerrar.
  - Perfiles de filtros cargados al inicio desde `profiles/*.json`.
  - Envio e inyeccion de paquetes una vez o periodicamente.
"""
from __future__ import annotations

import json
import os
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import List, Optional

from .capture import NpcapCaptureSource, encode_binary_message
from .filesource import FilePacketSource, FileReplayer
from .filters import PacketFilter, ProfileStore
from .models import Packet
from .processio import (
    SocketInjector,
    best_tcp_connection,
    find_process_connections,
    find_tcp_connections,
    is_admin,
    list_all_processes,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROFILES_DIR = os.path.join(BASE_DIR, "profiles")
SETTINGS_PATH = os.path.join(BASE_DIR, "settings.json")

DEFAULT_SETTINGS: dict = {}

MAX_ROWS = 10000

# Paleta dark mode (grises con buen contraste, estilo VS Code dark)
DARK_BG = "#1e1e1e"       # fondo general
DARK_PANEL = "#252526"    # menus, cabeceras, pestañas no activas
DARK_FIELD = "#2d2d2d"    # campos de texto y listas
DARK_BUTTON = "#333333"   # botones
DARK_HOVER = "#404040"    # resaltado al pasar el raton
DARK_BORDER = "#3c3c3c"   # bordes
DARK_FG = "#cccccc"       # texto principal
DARK_FG_DIM = "#9a9a9a"   # texto secundario
DARK_SELECT = "#264f78"   # seleccion
DARK_TREE = "#1b1b1b"     # fondo de la tabla de paquetes (ligeramente mas oscuro)


def load_settings() -> dict:
    settings = dict(DEFAULT_SETTINGS)
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as handle:
            settings.update(json.load(handle))
    except (OSError, ValueError):
        pass
    return settings


def save_settings(settings: dict) -> None:
    try:
        with open(SETTINGS_PATH, "w", encoding="utf-8") as handle:
            json.dump(settings, handle, indent=2, ensure_ascii=False)
    except OSError:
        pass


def pick_mono_font(root, size: int = 9):
    """Devuelve (familia, tamano) con una tipografia de consola instalada."""
    try:
        import tkinter.font as tkfont

        families = {name.lower() for name in tkfont.families(root)}
    except Exception:
        families = set()
    for family in ("Consolas", "Lucida Console", "Source Code Pro"):
        if family.lower() in families:
            return (family, size)
    return ("Consolas", size)


def center_window(window: tk.Toplevel) -> None:
    """Centra una ventana en la pantalla manteniendo su tamano."""
    try:
        window.update_idletasks()
        width = max(window.winfo_width(), window.winfo_reqwidth())
        height = max(window.winfo_height(), window.winfo_reqheight())
        x = max(0, (window.winfo_screenwidth() - width) // 2)
        y = max(0, (window.winfo_screenheight() - height) // 3)
        window.geometry(f"+{x}+{y}")
    except tk.TclError:
        pass


# ---------------------------------------------------------------------------
# Widgets
# ---------------------------------------------------------------------------

class PacketGrid(ttk.Frame):
    """Tabla de paquetes con columnas Tiempo | Direccion | Paquete.

    Incluye un panel de detalle que muestra el paquete seleccionado completo
    (la tabla puede recortarlo visualmente) y opciones de copiado.
    """

    def __init__(self, master, on_select=None, on_send_packet=None):
        super().__init__(master)
        self.columns = ("time", "dir", "data")
        self._on_send_packet = on_send_packet
        # Tema oscuro para la lista de paquetes (estilo consola)
        mono_font = pick_mono_font(self)
        style = ttk.Style(self)
        style.configure(
            "Treeview",
            background=DARK_TREE,
            fieldbackground=DARK_TREE,
            foreground=DARK_FG,
            font=mono_font,
            rowheight=26,
            relief="flat",
            borderwidth=0,
        )
        style.map(
            "Treeview",
            background=[("selected", DARK_SELECT)],
            foreground=[("selected", "#ffffff")],
        )
        style.configure(
            "Treeview.Heading",
            background=DARK_PANEL,
            foreground=DARK_FG,
            font=mono_font,
            relief="flat",
            borderwidth=0,
            padding=(8, 6),
        )
        style.map("Treeview.Heading", background=[("active", DARK_HOVER)])
        self.tree = ttk.Treeview(self, columns=self.columns, show="headings", selectmode="browse")
        self.tree.heading("time", text="Tiempo")
        self.tree.heading("dir", text="Dir")
        self.tree.heading("data", text="Paquete")
        self.tree.column("time", width=80, stretch=False, anchor="center")
        self.tree.column("dir", width=55, stretch=False, anchor="center")
        self.tree.column("data", width=400, stretch=True)
        self.tree.tag_configure("Send", foreground="#569cd6")
        self.tree.tag_configure("Recv", foreground="#6a9955")

        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        # Panel de detalle: paquete seleccionado completo, con salto de linea
        # para que el contenido largo nunca se corte.
        self._max_data_len = 0
        detail_frame = ttk.Frame(self)
        detail_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=(4, 0))
        detail_frame.rowconfigure(1, weight=1)
        detail_frame.columnconfigure(0, weight=1)
        detail_header = ttk.Frame(detail_frame)
        detail_header.grid(row=0, column=0, sticky="ew")
        ttk.Label(detail_header, text="Paquete seleccionado (completo):").pack(side="left")
        ttk.Button(detail_header, text="Copiar", command=self.copy_packet).pack(side="left", padx=4)
        self.detail_text = tk.Text(
            detail_frame,
            height=4,
            wrap="word",
            state="disabled",
            background=DARK_TREE,
            foreground=DARK_FG,
            insertbackground="#ffffff",
            relief="flat",
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=DARK_BORDER,
            highlightcolor=DARK_BORDER,
            font=pick_mono_font(self),
        )
        detail_vsb = ttk.Scrollbar(detail_frame, orient="vertical", command=self.detail_text.yview)
        self.detail_text.configure(yscrollcommand=detail_vsb.set)
        self.detail_text.grid(row=1, column=0, sticky="nsew")
        detail_vsb.grid(row=1, column=1, sticky="ns")

        # Menu contextual y atajo de teclado
        self._menu = tk.Menu(
            self, tearoff=0, bg=DARK_PANEL, fg=DARK_FG,
            activebackground=DARK_HOVER, activeforeground="#ffffff",
        )
        self._menu.add_command(label="Copiar paquete", command=self.copy_packet)
        self._menu.add_command(label="Copiar linea completa", command=self.copy_line)
        if self._on_send_packet is not None:
            self._menu.add_separator()
            self._menu.add_command(label="Enviar paquete", command=self._send_selected)
        self._menu.add_separator()
        self._menu.add_command(label="Limpiar pantalla", command=self.clear)
        self.tree.bind("<Button-3>", self._on_right_click)
        self.tree.bind("<Control-c>", lambda _event: self.copy_line())
        self.tree.bind("<Control-l>", lambda _event: self.clear())

        self._on_select = on_select
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)

    def _send_selected(self) -> None:
        """Envia el paquete seleccionado con su direccion original."""
        packet = self.selected()
        if packet is not None and self._on_send_packet is not None:
            self._on_send_packet(packet)

    def _on_tree_select(self, _event=None) -> None:
        packet = self.selected()
        self._set_detail(packet.data if packet is not None else "")
        if self._on_select is not None:
            self._on_select(packet)

    def _set_detail(self, text: str) -> None:
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        if text:
            self.detail_text.insert("1.0", text)
        self.detail_text.configure(state="disabled")

    def _on_right_click(self, event) -> None:
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
            self.tree.focus(row)
        try:
            self._menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._menu.grab_release()

    def copy_packet(self) -> None:
        """Copia al portapapeles el contenido del paquete seleccionado."""
        packet = self.selected()
        if packet is not None:
            text = packet.data
        else:
            text = self.detail_text.get("1.0", "end").strip()
        if not text:
            return
        self.clipboard_clear()
        self.clipboard_append(text)

    def copy_line(self) -> None:
        """Copia la linea completa en el formato [{hh:mm:ss}]\\t[{Recv|Send}]\\t{packet}."""
        packet = self.selected()
        if packet is None:
            return
        self.clipboard_clear()
        self.clipboard_append(packet.to_line())

    def add(self, packet: Packet, autoscroll: bool = True) -> None:
        self.tree.insert(
            "", "end", values=(packet.time.strftime("%H:%M:%S"), packet.direction, packet.data),
            tags=(packet.direction,),
        )
        children = self.tree.get_children()
        if len(children) > MAX_ROWS:
            self.tree.delete(children[0])
        if autoscroll:
            self.tree.see(children[-1])
        # Amplia la columna de datos cuando llega un paquete mas largo
        if len(packet.data) > self._max_data_len:
            self._max_data_len = len(packet.data)
            width = min(400 + self._max_data_len * 7, 1400)
            self.tree.column("data", width=width)

    def clear(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self._set_detail("")

    def selected(self) -> Optional[Packet]:
        selection = self.tree.selection()
        if not selection:
            return None
        values = self.tree.item(selection[0], "values")
        from datetime import datetime

        try:
            packet_time = datetime.strptime(values[0], "%H:%M:%S").time()
        except ValueError:
            packet_time = datetime.now().time()
        return Packet(time=packet_time, direction=values[1], data=values[2])


class FilterBar(ttk.Frame):
    """Barra de filtros rapidos + selector de perfil."""

    def __init__(self, master, profile_store: ProfileStore, on_change=None):
        super().__init__(master)
        self.on_change = on_change or (lambda: None)

        ttk.Label(self, text="Perfil:").pack(side="left", padx=(4, 2))
        self.profile_var = tk.StringVar(value="")
        self.profile_combo = ttk.Combobox(
            self, textvariable=self.profile_var, state="readonly", width=18
        )
        self.profile_combo["values"] = [""] + profile_store.names()
        self.profile_combo.pack(side="left", padx=2)
        self.profile_combo.bind("<<ComboboxSelected>>", lambda _e: self._changed())

        ttk.Label(self, text="Dir:").pack(side="left", padx=(8, 2))
        self.direction_var = tk.StringVar(value="All")
        direction_combo = ttk.Combobox(
            self, textvariable=self.direction_var, state="readonly", width=6, values=("All", "Send", "Recv")
        )
        direction_combo.pack(side="left", padx=2)
        direction_combo.bind("<<ComboboxSelected>>", lambda _e: self._changed())

        ttk.Label(self, text="Cabecera:").pack(side="left", padx=(8, 2))
        self.header_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.header_var, width=12).pack(side="left", padx=2)

        ttk.Label(self, text="Contiene:").pack(side="left", padx=(8, 2))
        self.contains_var = tk.StringVar()
        ttk.Entry(self, textvariable=self.contains_var, width=12).pack(side="left", padx=2)

        self.suppress_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            self, text="Suprimir (ocultar coincidencias)", variable=self.suppress_var,
            command=self._changed,
        ).pack(side="left", padx=(8, 2))

        ttk.Button(self, text="Aplicar", command=self._changed).pack(side="left", padx=(8, 2))

    def _changed(self) -> None:
        self.on_change()

    def refresh_profiles(self, profile_store: ProfileStore) -> None:
        current = self.profile_var.get()
        values = [""] + profile_store.names()
        self.profile_combo["values"] = values
        if current not in values:
            self.profile_var.set("")

    def selected_profile(self) -> str:
        return self.profile_var.get() or ""

    def quick_filter(self) -> PacketFilter:
        return PacketFilter(direction=self.direction_var.get(), header=self.header_var.get().strip(), contains=self.contains_var.get().strip())


class SendPanel(ttk.LabelFrame):
    """Panel para enviar/injectar paquetes una vez o periodicamente."""

    def __init__(self, master, on_send, injectors_provider):
        super().__init__(master, text="Envio / inyeccion")
        self.on_send = on_send  # on_send(direction, text)
        self.injectors_provider = injectors_provider  # -> (labels, selected_index)

        # Fila de controles: direccion, inyector y acciones de envio
        row = ttk.Frame(self)
        row.pack(fill="x", padx=8, pady=(4, 2))
        ttk.Label(row, text="Direccion:").pack(side="left")
        self.direction_var = tk.StringVar(value="Send")
        ttk.Combobox(
            row, textvariable=self.direction_var, state="readonly", width=6, values=("Send", "Recv")
        ).pack(side="left", padx=2)

        ttk.Label(row, text="Inyector:").pack(side="left", padx=(8, 2))
        self.injector_var = tk.StringVar(value="")
        self.injector_combo = ttk.Combobox(row, textvariable=self.injector_var, state="readonly", width=20)
        self.injector_combo.pack(side="left", padx=2)
        ttk.Button(row, text="Actualizar", command=self.refresh_injectors).pack(side="left", padx=4)

        ttk.Button(row, text="Enviar", command=self.send_once).pack(side="left", padx=(6, 0))
        ttk.Label(row, text="Intervalo (s):").pack(side="left", padx=(8, 2))
        self.interval_var = tk.DoubleVar(value=1.0)
        ttk.Spinbox(
            row, from_=0.1, to=3600, increment=0.1, textvariable=self.interval_var, width=7
        ).pack(side="left")
        self.periodic_button = ttk.Button(row, text="Periodico", command=self.toggle_periodic)
        self.periodic_button.pack(side="left", padx=4)
        self._periodic_active = False

        # Fila del paquete (ancho completo, nunca se corta)
        entry_row = ttk.Frame(self)
        entry_row.pack(fill="x", padx=8, pady=(2, 6))
        ttk.Label(entry_row, text="Paquete:").pack(side="left")
        self.packet_var = tk.StringVar()
        self.packet_entry = ttk.Entry(entry_row, textvariable=self.packet_var)
        self.packet_entry.pack(side="left", fill="x", expand=True, padx=4)
        self.packet_entry.bind("<Return>", lambda _event: self.send_once())

        self._set_periodic(False)

    def toggle_periodic(self) -> None:
        self._set_periodic(not self._periodic_active)

    def _set_periodic(self, active: bool) -> None:
        self._periodic_active = active
        self.periodic_button.configure(text="Detener" if active else "Periodico")

    def send_once(self) -> None:
        text = self.packet_var.get().strip()
        if not text:
            return
        self.on_send(self.direction_var.get(), text)

    def periodic_payload(self):
        """Devuelve el texto actual para el envio periodico (o None)."""
        return self.packet_var.get().strip() or None

    def refresh_injectors(self) -> None:
        labels, selected = self.injectors_provider()
        self.injector_combo["values"] = labels
        if selected is not None and 0 <= selected < len(labels):
            self.injector_var.set(labels[selected])
        elif labels:
            self.injector_var.set(labels[0])
        else:
            self.injector_var.set("")

    def selected_injector_label(self) -> str:
        return self.injector_var.get()


class SourceTab(ttk.Frame):
    """Pestaña de una fuente: captura Npcap o archivo de paquetes."""

    def __init__(self, master, title: str, source, profile_store: ProfileStore, app):
        super().__init__(master)
        self.title = title
        self.source = source
        self.app = app
        self.queue: "queue.Queue[Packet]" = queue.Queue()
        self.error_queue: "queue.Queue[str]" = queue.Queue()
        self._started = False
        self._periodic_id: Optional[str] = None
        self._replayer: Optional[FileReplayer] = None
        self._replayer_thread: Optional[threading.Thread] = None
        self._send_lock = threading.Lock()

        toolbar = ttk.Frame(self)
        toolbar.pack(fill="x", padx=8, pady=(8, 0))
        self.start_button = ttk.Button(toolbar, text="Iniciar", command=self.toggle_start)
        self.start_button.pack(side="left")
        ttk.Button(toolbar, text="Limpiar", command=self._clear).pack(side="left", padx=4)
        self.autoscroll_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            toolbar, text="Auto-scroll", variable=self.autoscroll_var
        ).pack(side="left")
        self.decode_var = tk.BooleanVar(value=False)
        if isinstance(source, NpcapCaptureSource):
            ttk.Checkbutton(
                toolbar, text="Decodificar", variable=self.decode_var, command=self._toggle_decode
            ).pack(side="left", padx=4)
        self.status_var = tk.StringVar(value="Detenido")
        ttk.Label(toolbar, textvariable=self.status_var, foreground="#9a9a9a").pack(side="right")

        self.filter_bar = FilterBar(self, profile_store, on_change=self._apply_filter)
        self.filter_bar.pack(fill="x", padx=8, pady=6)

        self.grid = PacketGrid(self, on_send_packet=self._send_packet_from_grid)
        self.grid.pack(fill="both", expand=True, padx=8, pady=6)

        self.send_panel = SendPanel(self, on_send=self._send, injectors_provider=self._injector_options)
        self.send_panel.pack(fill="x", padx=8, pady=(6, 8))
        # Conecta el boton periodico con el bucle real de envio
        self.send_panel.periodic_button.configure(command=self._toggle_periodic)

        if isinstance(source, FilePacketSource):
            self._show_file_replay()

        self.after(100, self._poll_queue)
        self._load_file_source()

    # -- filtros ---------------------------------------------------------

    def _filter_match(self, packet: Packet) -> bool:
        """Devuelve True si el paquete debe mostrarse con el filtro actual.

        Con el modo "Suprimir" activado se ocultan las coincidencias en lugar
        de mostrarlas (la captura es pasiva: no se pueden bloquear paquetes
        reales, solo ocultarlos de la lista).
        """
        profile = self.app.profile_store.get(self.filter_bar.selected_profile())
        quick = self.filter_bar.quick_filter()
        matched = (profile is None or profile.matches(packet)) and quick.matches(packet)
        if self.filter_bar.suppress_var.get():
            return not matched
        return matched

    def _apply_filter(self) -> None:
        # Re-inserta todo con el filtro actual
        self.grid.clear()
        source_packets = getattr(self.source, "packets", None)
        if source_packets is not None:
            for packet in source_packets:
                if self._filter_match(packet):
                    self.grid.add(packet, autoscroll=False)

    # -- fuente ----------------------------------------------------------

    def _load_file_source(self) -> None:
        if isinstance(self.source, FilePacketSource):
            self.status_var.set(
                f"{len(self.source.packets)} paquetes"
                + (f" | {self.source.invalid_lines} lineas ignoradas" if self.source.invalid_lines else "")
            )
            self._apply_filter()

    def toggle_start(self) -> None:
        if self._started:
            self.stop()
        else:
            self.start()

    def start(self) -> None:
        if isinstance(self.source, FilePacketSource):
            self._started = True
            self.status_var.set("Archivo cargado (usa el panel de envio para reproducir)")
            self.start_button.configure(text="Detener")
            return
        self.status_var.set("Iniciando captura...")
        self.start_button.configure(state="disabled")

        def worker():
            try:
                self.source.start()
                self.status_var.set("Capturando...")
                self._started = True
                self.start_button.configure(text="Detener", state="normal")
            except Exception as exc:
                self._report_error(f"Error al iniciar la captura: {exc}")
                self.start_button.configure(state="normal")

        threading.Thread(target=worker, daemon=True).start()

    def stop(self) -> None:
        try:
            stop = self.source.stop
        except AttributeError:
            stop = None
        if stop is not None:
            stop()
        self._stop_periodic()
        self._stop_replayer()
        self._started = False
        self.start_button.configure(text="Iniciar", state="normal")
        if not isinstance(self.source, FilePacketSource):
            self.status_var.set("Detenido")

    def _clear(self) -> None:
        self.grid.clear()

    def _toggle_decode(self) -> None:
        """Activa o desactiva la decodificacion del protocolo binario en la captura."""
        if isinstance(self.source, NpcapCaptureSource):
            self.source.binary_decode = self.decode_var.get()
            self.status_var.set(
                "Decodificacion binaria activada"
                if self.decode_var.get()
                else "Decodificacion binaria desactivada"
            )

    # -- cola de paquetes ------------------------------------------------

    def _poll_queue(self) -> None:
        try:
            while True:
                packet = self.queue.get_nowait()
                self._add_packet(packet)
        except queue.Empty:
            pass
        except tk.TclError:
            return
        # Errores pendientes: mostrarlos en una ventana emergente (hilo de UI)
        try:
            while True:
                message = self.error_queue.get_nowait()
                try:
                    messagebox.showerror("Error", message, parent=self.winfo_toplevel())
                except tk.TclError:
                    pass
        except queue.Empty:
            pass
        try:
            self.after(100, self._poll_queue)
        except tk.TclError:
            pass

    def _report_error(self, message: str) -> None:
        """Muestra el error en la barra de estado y en una ventana emergente."""
        self.status_var.set(message)
        self.error_queue.put(message)

    def _add_packet(self, packet: Packet) -> None:
        if not self._filter_match(packet):
            return
        self.grid.add(packet, autoscroll=self.autoscroll_var.get())

    # -- envio / inyeccion -----------------------------------------------

    def _injector_options(self):
        labels = []
        for injector in self.app.injectors:
            labels.append(repr(injector))
        selected = getattr(self, "_last_injector", None)
        return labels, selected

    def _resolve_injector(self) -> Optional[SocketInjector]:
        label = self.send_panel.selected_injector_label()
        for index, injector in enumerate(self.app.injectors):
            if repr(injector) == label:
                self._last_injector = index
                return injector
        # Intenta el inyector que coincida con la conexion de esta captura
        info = getattr(self.source, "info", None)
        if info:
            for injector in self.app.injectors:
                if injector.remote == (info.get("remote_ip"), info.get("remote_port")):
                    return injector
        return None

    def _send(self, direction: str, text: str) -> None:
        injector = self._resolve_injector()
        if injector is None:
            self.status_var.set(
                "No hay inyector: crea uno desde el menu Inyectores (con el proceso "
                "objetivo conectado)."
            )
            return

        payload: "str | bytes" = text
        hint = ""
        if isinstance(self.source, NpcapCaptureSource) and self.decode_var.get():
            # Con la decodificacion activa, construir el framing binario del mensaje
            try:
                payload = encode_binary_message(text)
                hint = " (framing binario)"
            except ValueError as exc:
                self._report_error(f"Error en el paquete binario: {exc}")
                return

        def worker():
            with self._send_lock:
                try:
                    sent = injector.send(direction, payload)
                    self.status_var.set(f"Enviado {sent} bytes ({direction}){hint}")
                except Exception as exc:
                    self._report_error(f"Error al enviar: {exc}")

        threading.Thread(target=worker, daemon=True).start()

    def _send_packet_from_grid(self, packet: Packet) -> None:
        """Envia el paquete seleccionado en la tabla con su direccion original."""
        self._send(packet.direction, packet.data)

    def _toggle_periodic(self) -> None:
        if self.send_panel._periodic_active:
            self._stop_periodic()
        else:
            self.send_panel._set_periodic(True)
            self._send_periodic_tick()

    def _send_periodic_tick(self) -> None:
        if not self.send_panel._periodic_active:
            return
        text = self.send_panel.periodic_payload()
        if text:
            self._send(self.send_panel.direction_var.get(), text)
        interval_ms = int(max(0.1, self.send_panel.interval_var.get()) * 1000)
        try:
            self._periodic_id = self.after(interval_ms, self._send_periodic_tick)
        except tk.TclError:
            pass

    def _stop_periodic(self) -> None:
        if self._periodic_id is not None:
            try:
                self.after_cancel(self._periodic_id)
            except (tk.TclError, ValueError):
                pass
            self._periodic_id = None
        self.send_panel._set_periodic(False)

    # -- reproduccion de archivo -----------------------------------------

    def _show_file_replay(self) -> None:
        frame = ttk.LabelFrame(self, text="Reproducir archivo")
        frame.pack(fill="x", padx=8, pady=(0, 8))
        self.replay_frame = frame
        ttk.Button(frame, text="Reenviar todos (1 vez)", command=self._replay_once).pack(
            side="left", padx=4, pady=2
        )
        self.replay_loop_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame, text="En bucle", variable=self.replay_loop_var).pack(side="left", padx=4)
        ttk.Label(frame, text="Intervalo (s):").pack(side="left")
        self.replay_interval_var = tk.DoubleVar(value=1.0)
        ttk.Spinbox(
            frame, from_=0.1, to=3600, increment=0.1, textvariable=self.replay_interval_var, width=7
        ).pack(side="left")
        ttk.Button(frame, text="Detener reproduccion", command=self._stop_replayer).pack(
            side="left", padx=8
        )

    def _replay_once(self) -> None:
        if not isinstance(self.source, FilePacketSource):
            return

        def send_via_injector(direction: str, text: str) -> None:
            injector = self._resolve_injector()
            if injector is None:
                raise RuntimeError("no hay inyector disponible")
            injector.send(direction, text)

        self._replayer = FileReplayer(self.source.packets, send_via_injector, self.replay_interval_var.get())

        def worker():
            try:
                while True:
                    self._replayer.play_once()
                    if not (self.replay_loop_var.get() and self._replayer is not None):
                        break
                    time.sleep(max(0.1, self.replay_interval_var.get()))
                self.status_var.set("Reproduccion finalizada")
            except Exception as exc:
                self._report_error(f"Reproduccion detenida: {exc}")

        threading.Thread(target=worker, daemon=True).start()

    def _stop_replayer(self) -> None:
        if self._replayer is not None:
            self._replayer.stop()
            self._replayer = None

    # -- cierre ----------------------------------------------------------

    def close(self) -> None:
        self.stop()
        self._stop_periodic()
        self._stop_replayer()


# ---------------------------------------------------------------------------
# Paneles de pestañas (split / float)
# ---------------------------------------------------------------------------

class NotebookPane(ttk.Frame):
    """Un panel con un Notebook y menu contextual en las pestañas."""

    def __init__(self, master, app):
        super().__init__(master)
        self.app = app
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True)
        self.notebook.bind("<Button-3>", self._on_right_click)
        self._menu = tk.Menu(
            self, tearoff=0, bg=DARK_PANEL, fg=DARK_FG,
            activebackground=DARK_HOVER, activeforeground="#ffffff",
        )
        self._menu.add_command(label="Flotar", command=self._float_tab)
        self._menu.add_command(label="Dividir / mover a otro panel", command=self._split_tab)
        self._menu.add_separator()
        self._menu.add_command(label="Cerrar", command=self._close_tab)
        self._menu_index: Optional[int] = None

    def add_tab(self, widget, title: str) -> None:
        self.notebook.add(widget, text=title)
        self.notebook.select(widget)

    def _on_right_click(self, event) -> None:
        try:
            index = self.notebook.index(f"@{event.x},{event.y}")
        except tk.TclError:
            return
        self._menu_index = index
        try:
            self._menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._menu.grab_release()

    def _detach(self, index: int):
        tab_id = self.notebook.tabs()[index]
        widget = self.notebook.nametowidget(tab_id)
        title = self.notebook.tab(tab_id, "text")
        self.notebook.forget(tab_id)
        return widget, title

    def _float_tab(self) -> None:
        if self._menu_index is None:
            return
        widget, title = self._detach(self._menu_index)
        self.app.float_tab(widget, title)

    def _split_tab(self) -> None:
        if self._menu_index is None:
            return
        widget, title = self._detach(self._menu_index)
        self.app.move_tab_to_next_pane(self, widget, title)

    def _close_tab(self) -> None:
        if self._menu_index is None:
            return
        tab_id = self.notebook.tabs()[self._menu_index]
        widget = self.notebook.nametowidget(tab_id)
        self.notebook.forget(tab_id)
        if isinstance(widget, SourceTab):
            widget.close()
        widget.destroy()
        self.app._on_pane_emptied(self)


# ---------------------------------------------------------------------------
# Ventana flotante
# ---------------------------------------------------------------------------

class FloatWindow(tk.Toplevel):
    """Ventana flotante que contiene un panel de pestañas."""

    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("Packet Logger - flotante")
        self.configure(bg=DARK_BG)
        x = max(0, (self.winfo_screenwidth() - 800) // 2)
        y = max(0, (self.winfo_screenheight() - 500) // 3)
        self.geometry(f"800x500+{x}+{y}")
        self.pane = NotebookPane(self, app)
        self.pane.pack(fill="both", expand=True)
        self.protocol("WM_DELETE_WINDOW", self._dock_back)

    def _dock_back(self) -> None:
        self.app.dock_float(self)


# ---------------------------------------------------------------------------
# Dialogos
# ---------------------------------------------------------------------------

class CaptureDialog(tk.Toplevel):
    """Configuracion de una nueva captura Npcap: cualquier proceso y conexion TCP/UDP."""

    def __init__(self, master, settings: dict):
        super().__init__(master)
        self.title("Nueva captura Npcap")
        self.resizable(False, False)
        self.configure(bg=DARK_BG)
        self.result: Optional[dict] = None

        body = ttk.Frame(self, padding=14)
        body.grid(row=0, column=0, sticky="nsew")

        # -- Proceso --
        ttk.Label(body, text="Proceso:").grid(row=0, column=0, sticky="w")
        process_row = ttk.Frame(body)
        process_row.grid(row=0, column=1, sticky="we")
        self.proc_options = []
        self.proc_var = tk.StringVar(value="")
        self.proc_combo = ttk.Combobox(process_row, textvariable=self.proc_var, state="readonly", width=36)
        self.proc_combo.pack(side="left")
        self.proc_combo.bind("<<ComboboxSelected>>", self._load_connections)
        ttk.Button(process_row, text="Actualizar", command=self._refresh_processes).pack(side="left", padx=4)

        # -- Busqueda de proceso --
        ttk.Label(body, text="Buscar proceso:").grid(row=1, column=0, sticky="w")
        self.search_var = tk.StringVar(value="")
        ttk.Entry(body, textvariable=self.search_var, width=40).grid(row=1, column=1, sticky="we")
        self.search_var.trace_add("write", self._on_search)

        # -- Conexiones --
        ttk.Label(body, text="Conexiones (ip:puerto):").grid(row=2, column=0, sticky="nw")
        self.conn_list = tk.Listbox(
            body, height=6, width=52, exportselection=False,
            bg=DARK_FIELD, fg=DARK_FG,
            selectbackground=DARK_SELECT, selectforeground="#ffffff",
            relief="flat", highlightthickness=1,
            highlightbackground=DARK_BORDER, highlightcolor=DARK_BORDER,
        )
        self.conn_list.grid(row=2, column=1, sticky="we")
        self.connections = []

        # -- Puerto manual --
        ttk.Label(body, text="O puerto manual:").grid(row=3, column=0, sticky="w")
        self.port_var = tk.StringVar(value="")
        ttk.Entry(body, textvariable=self.port_var, width=10).grid(row=3, column=1, sticky="w")
        ttk.Label(
            body,
            text="(vacio = auto; si no eliges conexion, se usara este puerto)",
            foreground="#666",
        ).grid(row=4, column=0, columnspan=2, sticky="w")

        buttons = ttk.Frame(body)
        buttons.grid(row=5, column=0, columnspan=2, pady=(10, 0))
        ttk.Button(buttons, text="Crear", command=self._ok).pack(side="left", padx=4)
        ttk.Button(buttons, text="Cancelar", command=self.destroy).pack(side="left")

        self._refresh_processes()
        self.grab_set()
        center_window(self)

    def _refresh_processes(self) -> None:
        current = self.proc_var.get()
        self.proc_options = list_all_processes()
        self._apply_search(current)

    def _apply_search(self, prefer: str = "") -> None:
        text = self.search_var.get().strip().lower()
        labels = [f"{p.pid} - {p.info.get('name', '')}" for p in self.proc_options]
        if text:
            labels = [label for label in labels if text in label.lower()]
        self.proc_combo["values"] = labels
        if self.proc_var.get() not in labels:
            chosen = prefer if prefer in labels else (labels[0] if labels else "")
            self.proc_var.set(chosen)
        # Si la busqueda deja un unico proceso, mostrar sus conexiones directamente
        if len(labels) == 1 and self.proc_var.get() == labels[0]:
            self._load_connections()

    def _on_search(self, *_args) -> None:
        self._apply_search()

    def _selected_process(self):
        label = self.proc_var.get()
        for proc in self.proc_options:
            if label.startswith(f"{proc.pid} -"):
                return proc
        return None

    def _load_connections(self, _event=None) -> None:
        process = self._selected_process()
        self.connections = []
        self.conn_list.delete(0, "end")
        if process is None:
            self.conn_list.insert("end", "(selecciona un proceso)")
            return
        try:
            connections = find_process_connections(process)
        except Exception:
            connections = []
        if not connections:
            self.conn_list.insert("end", "(sin conexiones TCP/UDP activas)")
            return
        self.connections = connections
        best = best_tcp_connection(connections)
        for connection in connections:
            label = self._conn_label(connection)
            if connection is best:
                label += "  <- recomendada"
            self.conn_list.insert("end", label)
        if best is not None:
            self.conn_list.selection_set(connections.index(best))

    @staticmethod
    def _conn_label(connection: dict) -> str:
        proto = connection.get("proto", "tcp").upper()
        local = f"{connection.get('local_ip', '?')}:{connection.get('local_port', '?')}"
        remote_ip = connection.get("remote_ip", "")
        if not remote_ip:
            return f"{proto} local {local} (sin destino)"
        return f"{proto} {local} <-> {remote_ip}:{connection.get('remote_port', '?')}"

    def _selected_connection(self):
        selection = self.conn_list.curselection()
        if not selection or not self.connections:
            return None
        index = selection[0]
        if 0 <= index < len(self.connections):
            return self.connections[index]
        return None

    def _ok(self) -> None:
        try:
            port_text = self.port_var.get().strip()
            remote_port = int(port_text) if port_text else None
        except ValueError:
            remote_port = None
        if self._selected_process() is None and remote_port is None:
            messagebox.showwarning(
                "Captura",
                "Elige un proceso y una conexion, o indica un puerto manual.",
                parent=self,
            )
            return
        self.result = {
            "process": self._selected_process(),
            "connection": self._selected_connection(),
            "remote_port": remote_port,
        }
        self.destroy()


class InjectorDialog(tk.Toplevel):
    """Creacion de un inyector conectado a un proceso (cualquier programa)."""

    AUTO_FIRST = "(auto: recomendada)"

    def __init__(self, master, settings: dict):
        super().__init__(master)
        self.title("Nuevo inyector")
        self.resizable(False, False)
        self.configure(bg=DARK_BG)
        self.result: Optional[dict] = None

        body = ttk.Frame(self, padding=14)
        body.grid(row=0, column=0, sticky="nsew")

        ttk.Label(body, text="Proceso:").grid(row=0, column=0, sticky="w")
        process_row = ttk.Frame(body)
        process_row.grid(row=0, column=1, sticky="we")
        self.proc_options = list_all_processes()
        self.proc_var = tk.StringVar(value="")
        self.proc_combo = ttk.Combobox(process_row, textvariable=self.proc_var, state="readonly", width=36)
        self.proc_combo.pack(side="left")
        self.proc_combo.bind("<<ComboboxSelected>>", self._load_connections)
        ttk.Button(process_row, text="Actualizar", command=self._refresh_processes).pack(side="left", padx=4)

        ttk.Label(body, text="Buscar proceso:").grid(row=1, column=0, sticky="w")
        self.search_var = tk.StringVar(value="")
        ttk.Entry(body, textvariable=self.search_var, width=40).grid(row=1, column=1, sticky="we")
        self.search_var.trace_add("write", self._on_search)

        ttk.Label(body, text="Conexiones TCP (ip:puerto):").grid(row=2, column=0, sticky="nw")
        self.conn_list = tk.Listbox(
            body, height=6, width=52, exportselection=False,
            bg=DARK_FIELD, fg=DARK_FG,
            selectbackground=DARK_SELECT, selectforeground="#ffffff",
            relief="flat", highlightthickness=1,
            highlightbackground=DARK_BORDER, highlightcolor=DARK_BORDER,
        )
        self.conn_list.grid(row=2, column=1, sticky="we")
        self.connections = []

        ttk.Label(
            body,
            text="El texto se envia tal cual (sin cifrar). La inyeccion requiere\n"
            "ejecutar el programa como Administrador.",
            foreground="#666",
        ).grid(row=3, column=0, columnspan=2, sticky="w")

        buttons = ttk.Frame(body)
        buttons.grid(row=4, column=0, columnspan=2, pady=(10, 0))
        ttk.Button(buttons, text="Conectar", command=self._ok).pack(side="left", padx=4)
        ttk.Button(buttons, text="Cancelar", command=self.destroy).pack(side="left")

        self._refresh_processes()
        self.grab_set()
        center_window(self)

    def _refresh_processes(self) -> None:
        current = self.proc_var.get()
        self.proc_options = list_all_processes()
        self._apply_search(current)

    def _apply_search(self, prefer: str = "") -> None:
        text = self.search_var.get().strip().lower()
        labels = [f"{p.pid} - {p.info.get('name', '')}" for p in self.proc_options]
        if text:
            labels = [label for label in labels if text in label.lower()]
        self.proc_combo["values"] = labels
        if self.proc_var.get() not in labels:
            chosen = prefer if prefer in labels else (labels[0] if labels else "")
            self.proc_var.set(chosen)
        # Si la busqueda deja un unico proceso, mostrar sus conexiones directamente
        if len(labels) == 1 and self.proc_var.get() == labels[0]:
            self._load_connections()

    def _on_search(self, *_args) -> None:
        self._apply_search()

    def _selected_process(self):
        label = self.proc_var.get()
        for proc in self.proc_options:
            if label.startswith(f"{proc.pid} -"):
                return proc
        return None

    def _load_connections(self, _event=None) -> None:
        process = self._selected_process()
        self.connections = []
        self.conn_list.delete(0, "end")
        if process is None:
            self.conn_list.insert("end", "(selecciona un proceso)")
            return
        try:
            connections = find_tcp_connections(process, None)
        except Exception:
            connections = []
        if not connections:
            self.conn_list.insert("end", "(sin conexiones TCP activas)")
            return
        self.connections = connections
        self.conn_list.insert("end", self.AUTO_FIRST)
        best = best_tcp_connection(connections)
        for connection in connections:
            label = f"{connection['remote_ip']}:{connection['remote_port']}"
            if connection is best:
                label += "  <- recomendada"
            self.conn_list.insert("end", label)
        if best is not None:
            self.conn_list.selection_set(connections.index(best) + 1)

    def _selected_connection(self):
        selection = self.conn_list.curselection()
        if not selection or not self.connections:
            return None
        index = selection[0] - 1  # la primera fila es AUTO_FIRST
        if 0 <= index < len(self.connections):
            return self.connections[index]
        return None

    def _ok(self) -> None:
        process = self._selected_process()
        if process is None:
            messagebox.showerror("Inyector", "Selecciona un proceso de la lista.", parent=self)
            return
        self.result = {
            "process": process,
            "connection": self._selected_connection(),
        }
        self.destroy()


class ProfileManager(tk.Toplevel):
    """Gestion de perfiles de filtros (guardados en profiles/*.json)."""

    def __init__(self, master, profile_store: ProfileStore):
        super().__init__(master)
        self.title("Gestor de perfiles de filtros")
        self.geometry("560x420")
        self.configure(bg=DARK_BG)
        self.store = profile_store

        body = ttk.Frame(self, padding=12)
        body.pack(fill="both", expand=True)

        left = ttk.Frame(body)
        left.pack(side="left", fill="y", padx=(0, 8))
        ttk.Label(left, text="Perfiles:").pack(anchor="w")
        self.profile_list = tk.Listbox(
            left, width=22, bg=DARK_FIELD, fg=DARK_FG,
            selectbackground=DARK_SELECT, selectforeground="#ffffff",
            relief="flat", highlightthickness=1,
            highlightbackground=DARK_BORDER, highlightcolor=DARK_BORDER,
        )
        self.profile_list.pack(fill="both", expand=True)
        self.profile_list.bind("<<ListboxSelect>>", self._on_profile_select)
        ttk.Button(left, text="Eliminar perfil", command=self._delete_profile).pack(fill="x", pady=2)

        right = ttk.Frame(body)
        right.pack(side="left", fill="both", expand=True)
        ttk.Label(right, text="Nombre:").pack(anchor="w")
        self.name_var = tk.StringVar()
        ttk.Entry(right, textvariable=self.name_var).pack(fill="x")

        ttk.Label(right, text="Filtros del perfil (se cumple si alguno coincide):").pack(anchor="w", pady=(6, 0))
        self.filter_list = tk.Listbox(
            right, height=8, bg=DARK_FIELD, fg=DARK_FG,
            selectbackground=DARK_SELECT, selectforeground="#ffffff",
            relief="flat", highlightthickness=1,
            highlightbackground=DARK_BORDER, highlightcolor=DARK_BORDER,
        )
        self.filter_list.pack(fill="both", expand=True)
        self.filter_list.bind("<<ListboxSelect>>", self._on_filter_select)

        add_frame = ttk.Frame(right)
        add_frame.pack(fill="x", pady=4)
        ttk.Label(add_frame, text="Dir:").pack(side="left")
        self.dir_var = tk.StringVar(value="All")
        ttk.Combobox(add_frame, textvariable=self.dir_var, state="readonly", width=6, values=("All", "Send", "Recv")).pack(side="left", padx=2)
        ttk.Label(add_frame, text="Cabecera:").pack(side="left")
        self.header_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.header_var, width=10).pack(side="left", padx=2)
        ttk.Label(add_frame, text="Contiene:").pack(side="left")
        self.contains_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.contains_var, width=10).pack(side="left", padx=2)
        ttk.Button(add_frame, text="+", width=3, command=self._add_filter).pack(side="left", padx=2)

        ttk.Button(right, text="Eliminar filtro seleccionado", command=self._remove_filter).pack(anchor="w")

        buttons = ttk.Frame(right)
        buttons.pack(fill="x", pady=(8, 0))
        ttk.Button(buttons, text="Guardar perfil", command=self._save_profile).pack(side="left")
        ttk.Button(buttons, text="Cerrar", command=self.destroy).pack(side="right")

        self._working: List[PacketFilter] = []
        self._refresh_profiles()
        center_window(self)

    def _refresh_profiles(self) -> None:
        self.profile_list.delete(0, "end")
        for profile in self.store.profiles:
            self.profile_list.insert("end", profile.name)

    def _refresh_filters(self) -> None:
        self.filter_list.delete(0, "end")
        for filt in self._working:
            self.filter_list.insert(
                "end", f"{filt.direction} | {filt.header} | {filt.contains}" + (f" | {filt.regex}" if filt.regex else "")
            )

    def _on_profile_select(self, _event=None) -> None:
        selection = self.profile_list.curselection()
        if not selection:
            return
        profile = self.store.profiles[selection[0]]
        self.name_var.set(profile.name)
        self._working = list(profile.filters)
        self._refresh_filters()

    def _on_filter_select(self, _event=None) -> None:
        selection = self.filter_list.curselection()
        if not selection:
            return
        filt = self._working[selection[0]]
        self.dir_var.set(filt.direction)
        self.header_var.set(filt.header)
        self.contains_var.set(filt.contains)

    def _add_filter(self) -> None:
        self._working.append(
            PacketFilter(
                direction=self.dir_var.get(),
                header=self.header_var.get().strip(),
                contains=self.contains_var.get().strip(),
            )
        )
        self._refresh_filters()

    def _remove_filter(self) -> None:
        selection = self.filter_list.curselection()
        if not selection:
            return
        del self._working[selection[0]]
        self._refresh_filters()

    def _save_profile(self) -> None:
        name = self.name_var.get().strip()
        if not name:
            messagebox.showwarning("Perfil", "Escribe un nombre para el perfil.", parent=self)
            return
        from .filters import FilterProfile

        self.store.save(FilterProfile(name=name, filters=list(self._working)))
        self._refresh_profiles()

    def _delete_profile(self) -> None:
        selection = self.profile_list.curselection()
        if not selection:
            return
        self.store.delete(self.store.profiles[selection[0]].name)
        self.name_var.set("")
        self._working = []
        self._refresh_profiles()
        self._refresh_filters()


# ---------------------------------------------------------------------------
# Aplicacion principal
# ---------------------------------------------------------------------------

class App(tk.Tk):
    """Ventana principal del packet logger."""

    def __init__(self):
        super().__init__()
        self._apply_dark_theme()
        self.title("Packet Logger")
        width, height = 1100, 650
        x = max(0, (self.winfo_screenwidth() - width) // 2)
        y = max(0, (self.winfo_screenheight() - height) // 3)
        self.geometry(f"{width}x{height}+{x}+{y}")
        self.settings = load_settings()
        self.profile_store = ProfileStore(PROFILES_DIR)
        self.injectors: List[SocketInjector] = []
        self.floats: List[FloatWindow] = []

        self._build_menu()
        self._build_panes()
        self._build_statusbar()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # -- construccion -----------------------------------------------------

    def _apply_dark_theme(self) -> None:
        """Aplica un tema oscuro con buen contraste a toda la aplicacion."""
        background = DARK_BG
        self.configure(bg=background)
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background=background, foreground=DARK_FG)
        style.configure("TFrame", background=background)
        style.configure("TLabel", background=background, foreground=DARK_FG)
        style.configure("TButton", background=DARK_BUTTON, foreground=DARK_FG, padding=(10, 5))
        style.configure(
            "TButton",
            bordercolor=DARK_BORDER,
            lightcolor=DARK_BORDER,
            darkcolor=DARK_BORDER,
        )
        style.map("TButton", background=[("active", DARK_HOVER)])
        style.configure(
            "TCheckbutton", background=background, foreground=DARK_FG, padding=(4, 4)
        )
        style.configure(
            "TCheckbutton",
            indicatorbackground=DARK_FIELD,
            indicatorforeground=DARK_FG,
            lightcolor=DARK_BORDER,
            darkcolor=DARK_BORDER,
        )
        style.map("TCheckbutton", background=[("active", background)])
        style.configure("TRadiobutton", background=background, foreground=DARK_FG, padding=(4, 4))
        style.configure(
            "TRadiobutton",
            indicatorbackground=DARK_FIELD,
            indicatorforeground=DARK_FG,
            lightcolor=DARK_BORDER,
            darkcolor=DARK_BORDER,
        )
        style.map("TRadiobutton", background=[("active", background)])
        style.configure(
            "TEntry", fieldbackground=DARK_FIELD, foreground=DARK_FG, insertcolor=DARK_FG,
            padding=(5, 4),
        )
        style.configure(
            "TEntry",
            bordercolor=DARK_BORDER,
            lightcolor=DARK_BORDER,
            darkcolor=DARK_BORDER,
        )
        style.configure(
            "TCombobox",
            fieldbackground=DARK_FIELD,
            background=DARK_BUTTON,
            foreground=DARK_FG,
            arrowcolor=DARK_FG,
            bordercolor=DARK_BORDER,
            lightcolor=DARK_BORDER,
            darkcolor=DARK_BORDER,
            padding=(5, 4),
        )
        style.map("TCombobox", fieldbackground=[("readonly", DARK_FIELD)])
        style.configure(
            "TSpinbox", fieldbackground=DARK_FIELD, background=DARK_BUTTON, foreground=DARK_FG,
            padding=(5, 4),
        )
        style.configure(
            "TSpinbox",
            bordercolor=DARK_BORDER,
            lightcolor=DARK_BORDER,
            darkcolor=DARK_BORDER,
            arrowcolor=DARK_FG,
        )
        style.configure(
            "TLabelframe", background=background, foreground=DARK_FG, bordercolor=DARK_BORDER,
            padding=10,
        )
        style.configure("TLabelframe.Label", background=background, foreground=DARK_FG)
        style.configure("TNotebook", background=background, borderwidth=0)
        style.configure(
            "TNotebook",
            bordercolor=DARK_BORDER,
            lightcolor=DARK_BORDER,
            darkcolor=DARK_BORDER,
        )
        style.configure(
            "TNotebook.Tab",
            background=DARK_PANEL,
            foreground=DARK_FG,
            bordercolor=DARK_BORDER,
            lightcolor=DARK_BORDER,
            darkcolor=DARK_BORDER,
            padding=(14, 6),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", background)],
            lightcolor=[("selected", DARK_BORDER)],
            darkcolor=[("selected", DARK_BORDER)],
        )
        style.configure("TPanedwindow", background=background, sashwidth=4, sashrelief="flat")
        style.configure(
            "Treeview", background=DARK_TREE, fieldbackground=DARK_TREE,
            relief="flat", borderwidth=0,
        )
        style.configure(
            "Vertical.TScrollbar", background=DARK_BUTTON, troughcolor=background,
            bordercolor=DARK_BORDER, arrowcolor=DARK_FG,
            lightcolor=DARK_BORDER, darkcolor=DARK_BORDER,
        )
        style.map("Vertical.TScrollbar", background=[("active", DARK_HOVER)])
        style.configure(
            "Horizontal.TScrollbar", background=DARK_BUTTON, troughcolor=background,
            bordercolor=DARK_BORDER, arrowcolor=DARK_FG,
            lightcolor=DARK_BORDER, darkcolor=DARK_BORDER,
        )
        style.map("Horizontal.TScrollbar", background=[("active", DARK_HOVER)])

    def _build_menu(self) -> None:
        menu_colors = {
            "bg": DARK_PANEL,
            "fg": DARK_FG,
            "activebackground": DARK_HOVER,
            "activeforeground": "#ffffff",
        }
        menubar = tk.Menu(self, **menu_colors)

        sources_menu = tk.Menu(menubar, tearoff=0, **menu_colors)
        sources_menu.add_command(label="Captura Npcap (cualquier proceso)...", command=self._add_capture)
        sources_menu.add_command(label="Archivo de paquetes...", command=self._add_file)
        sources_menu.add_separator()
        self.recent_captures_menu = tk.Menu(sources_menu, tearoff=0, **menu_colors)
        sources_menu.add_cascade(label="Capturas recientes", menu=self.recent_captures_menu)
        sources_menu.add_separator()
        sources_menu.add_command(label="Cerrar pestaña activa", command=self._close_active_tab)
        menubar.add_cascade(label="Fuentes", menu=sources_menu)

        injector_menu = tk.Menu(menubar, tearoff=0, **menu_colors)
        injector_menu.add_command(label="Nuevo inyector...", command=self._add_injector)
        injector_menu.add_separator()
        self.recent_injectors_menu = tk.Menu(injector_menu, tearoff=0, **menu_colors)
        injector_menu.add_cascade(label="Inyectores recientes", menu=self.recent_injectors_menu)
        injector_menu.add_command(label="Cerrar todos los inyectores", command=self._close_injectors)
        menubar.add_cascade(label="Inyectores", menu=injector_menu)

        profiles_menu = tk.Menu(menubar, tearoff=0, **menu_colors)
        profiles_menu.add_command(label="Gestor de perfiles de filtros...", command=self._open_profiles)
        profiles_menu.add_command(label="Recargar perfiles", command=self._reload_profiles)
        menubar.add_cascade(label="Perfiles", menu=profiles_menu)

        help_menu = tk.Menu(menubar, tearoff=0, **menu_colors)
        help_menu.add_command(label="Acerca de", command=self._about)
        menubar.add_cascade(label="Ayuda", menu=help_menu)

        self.config(menu=menubar)
        self._rebuild_recent_menus()

    # -- conexiones recientes --------------------------------------------

    def _remember_capture(self, connection, process) -> None:
        if not connection:
            return
        try:
            process_name = process.name() if process is not None else ""
        except Exception:
            process_name = ""
        entry = {
            "proto": connection.get("proto", "tcp"),
            "local_ip": connection.get("local_ip", ""),
            "local_port": connection.get("local_port", 0),
            "remote_ip": connection.get("remote_ip", ""),
            "remote_port": connection.get("remote_port", 0),
            "process_name": process_name,
        }
        recent = self.settings.setdefault("recent_captures", [])
        recent = [
            item for item in recent
            if not (item.get("remote_ip") == entry["remote_ip"] and item.get("remote_port") == entry["remote_port"])
        ]
        recent.insert(0, entry)
        self.settings["recent_captures"] = recent[:10]
        save_settings(self.settings)
        self._rebuild_recent_menus()

    def _remember_injector(self, injector: SocketInjector) -> None:
        if not injector.remote:
            return
        entry = {
            "process_name": injector.name,
            "remote_ip": injector.remote[0],
            "remote_port": injector.remote[1],
        }
        recent = self.settings.setdefault("recent_injectors", [])
        recent = [
            item for item in recent
            if not (item.get("remote_ip") == entry["remote_ip"] and item.get("remote_port") == entry["remote_port"])
        ]
        recent.insert(0, entry)
        self.settings["recent_injectors"] = recent[:10]
        save_settings(self.settings)
        self._rebuild_recent_menus()

    def _rebuild_recent_menus(self) -> None:
        menus = (
            (self.recent_captures_menu, self.settings.get("recent_captures", []), self._open_recent_capture),
            (self.recent_injectors_menu, self.settings.get("recent_injectors", []), self._open_recent_injector),
        )
        for menu, entries, handler in menus:
            menu.delete(0, "end")
            if not entries:
                menu.add_command(label="(vacio)", state="disabled")
                continue
            for entry in entries:
                label = (
                    f"{entry.get('remote_ip', '?')}:{entry.get('remote_port', '?')} "
                    f"- {entry.get('process_name') or 'desconocido'}"
                )
                menu.add_command(label=label, command=lambda e=entry: handler(e))

    def _open_recent_capture(self, entry: dict) -> None:
        connection = {
            "proto": entry.get("proto", "tcp"),
            "local_ip": entry.get("local_ip", ""),
            "local_port": entry.get("local_port", 0),
            "remote_ip": entry.get("remote_ip", ""),
            "remote_port": entry.get("remote_port", 0),
        }
        source = NpcapCaptureSource(connection=connection)
        title = (
            f"Captura {connection['proto'].upper()} "
            f"{connection['remote_ip']}:{connection['remote_port']}"
        )
        tab = self.add_source_tab(title, source)
        source.emit = lambda packet: tab.queue.put(packet)
        # La captura reciente se inicia automaticamente
        tab.start()

    def _open_recent_injector(self, entry: dict) -> None:
        if not is_admin():
            messagebox.showwarning(
                "Inyector",
                "El programa no se ejecuta como Administrador.\n"
                "Reinicia el programa con permisos de Administrador para poder inyectar.",
                parent=self,
            )
            return
        target_name = (entry.get("process_name") or "").lower()
        process = None
        for proc in list_all_processes():
            try:
                name = (proc.name() or "").lower()
            except Exception:
                continue
            if target_name and name == target_name:
                process = proc
                break
        if process is None:
            messagebox.showwarning(
                "Inyector",
                f"No se encontro el proceso '{entry.get('process_name') or '?'}' en "
                "ejecucion. Abrelo antes de reutilizar el inyector.",
                parent=self,
            )
            return
        injector = SocketInjector(process)
        try:
            injector.connect(target=(entry["remote_ip"], entry["remote_port"]))
        except RuntimeError as exc:
            messagebox.showerror("Inyector", str(exc), parent=self)
            injector.close()
            return
        self.injectors.append(injector)
        self._refresh_all_send_panels()
        self.status_text.set(f"Inyector conectado a {injector.remote}")

    def _build_panes(self) -> None:
        self.paned = ttk.Panedwindow(self, orient=tk.HORIZONTAL)
        self.paned.pack(fill="both", expand=True)
        self.panes: List[NotebookPane] = []
        self._add_pane()

    def _add_pane(self) -> NotebookPane:
        pane = NotebookPane(self.paned, self)
        self.paned.add(pane, weight=1)
        self.panes.append(pane)
        return pane

    def _build_statusbar(self) -> None:
        bar = ttk.Frame(self, relief="sunken")
        bar.pack(fill="x", side="bottom")
        self.status_text = tk.StringVar(value="Listo. Añade una fuente desde el menu Fuentes.")
        ttk.Label(bar, textvariable=self.status_text, padding=(6, 2)).pack(side="left")
        self.npcap_text = tk.StringVar(value="")
        ttk.Label(bar, textvariable=self.npcap_text, padding=(6, 2)).pack(side="right")
        self.admin_text = tk.StringVar(value="")
        ttk.Label(bar, textvariable=self.admin_text, padding=(6, 2)).pack(side="right")
        self._check_npcap()
        self._check_admin()

    def _check_admin(self) -> None:
        if is_admin():
            self.admin_text.set("Administrador: SI")
        else:
            self.admin_text.set("Administrador: NO (necesario para inyectar)")

    def _check_npcap(self) -> None:
        try:
            from scapy.all import conf

            use_pcap = bool(getattr(conf, "use_pcap", False))
            self.npcap_text.set("Npcap: OK" if use_pcap else "Npcap: no detectado")
        except Exception:
            self.npcap_text.set("Npcap: ?")

    # -- fuentes ----------------------------------------------------------

    def add_source_tab(self, title: str, source, pane: Optional[NotebookPane] = None) -> SourceTab:
        target = pane or (self.panes[0] if self.panes else self._add_pane())
        tab = SourceTab(target.notebook, title, source, self.profile_store, self)
        target.add_tab(tab, title)
        self._refresh_all_send_panels()
        self.status_text.set(f"Fuente añadida: {title}")
        return tab

    def _add_capture(self) -> None:
        dialog = CaptureDialog(self, self.settings)
        self.wait_window(dialog)
        if not dialog.result:
            return
        result = dialog.result
        connection = result.get("connection")
        source = NpcapCaptureSource(
            process=result["process"],
            remote_port=result["remote_port"],
            connection=connection,
        )
        title = "Captura Npcap"
        if connection:
            title = (
                f"Captura {connection.get('proto', 'tcp').upper()} "
                f"{connection.get('remote_ip', '?')}:"
                f"{connection.get('remote_port') or connection.get('local_port', '?')}"
            )
        tab = self.add_source_tab(title, source)
        # Conectar el hilo de captura a la cola de la pestaña
        source.emit = lambda packet: tab.queue.put(packet)
        self._remember_capture(connection, result["process"])

    def _add_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Selecciona un archivo de paquetes",
            filetypes=[("Registros de paquetes", "*.txt *.log"), ("Todos", "*.*")],
        )
        if not path:
            return
        try:
            source = FilePacketSource(path)
        except OSError as exc:
            messagebox.showerror("Archivo", f"No se pudo leer el archivo: {exc}", parent=self)
            return
        self.add_source_tab(f"Archivo: {source.summary.split(' (')[0]}", source)

    def _close_active_tab(self) -> None:
        for pane in self.panes:
            selected = pane.notebook.select()
            if selected:
                widget = pane.notebook.nametowidget(selected)
                pane.notebook.forget(selected)
                if isinstance(widget, SourceTab):
                    widget.close()
                widget.destroy()
                self._on_pane_emptied(pane)
                return

    # -- inyectores -------------------------------------------------------

    def _add_injector(self) -> None:
        if not is_admin():
            messagebox.showwarning(
                "Inyector",
                "El programa no se ejecuta como Administrador.\n"
                "Cierra el programa y vuelve a abrirlo desde una terminal "
                "elevada (como Administrador) para poder inyectar.",
                parent=self,
            )
            return
        dialog = InjectorDialog(self, self.settings)
        self.wait_window(dialog)
        if not dialog.result:
            return
        result = dialog.result
        injector = SocketInjector(result["process"])
        connection = result.get("connection")
        ports = None
        target = None
        if connection is not None:
            ports = (connection["remote_port"],)
            target = (connection["remote_ip"], connection["remote_port"])
        try:
            injector.connect(ports=ports, target=target)
        except RuntimeError as exc:
            messagebox.showerror("Inyector", str(exc), parent=self)
            injector.close()
            return
        self.injectors.append(injector)
        self._refresh_all_send_panels()
        self.status_text.set(f"Inyector conectado a {injector.remote}")
        self._remember_injector(injector)

    def _close_injectors(self) -> None:
        for injector in self.injectors:
            injector.close()
        self.injectors.clear()
        self._refresh_all_send_panels()

    def _refresh_all_send_panels(self) -> None:
        for widget in self._all_tabs():
            if isinstance(widget, SourceTab):
                widget.send_panel.refresh_injectors()

    def _all_tabs(self):
        result = []
        for pane in self.panes:
            result.extend(pane.notebook.nametowidget(tab) for tab in pane.notebook.tabs())
        for float_window in self.floats:
            try:
                if float_window.winfo_exists():
                    result.extend(
                        float_window.pane.notebook.nametowidget(tab)
                        for tab in float_window.pane.notebook.tabs()
                    )
            except tk.TclError:
                pass
        return result

    # -- perfiles ---------------------------------------------------------

    def _open_profiles(self) -> None:
        ProfileManager(self, self.profile_store)

    def _reload_profiles(self) -> None:
        self.profile_store.load_all()
        for widget in self._all_tabs():
            if isinstance(widget, SourceTab):
                widget.filter_bar.refresh_profiles(self.profile_store)
        self.status_text.set("Perfiles recargados")

    # -- paneles flotantes / split ---------------------------------------

    def float_tab(self, widget, title: str) -> None:
        window = FloatWindow(self)
        window.pane.add_tab(widget, title)
        self.floats.append(window)

    def dock_float(self, window: FloatWindow) -> None:
        for tab in list(window.pane.notebook.tabs()):
            widget = window.pane.notebook.nametowidget(tab)
            text = window.pane.notebook.tab(tab, "text")
            window.pane.notebook.forget(tab)
            self.panes[0].add_tab(widget, text)
        self.floats = [f for f in self.floats if f is not window]
        window.destroy()

    def move_tab_to_next_pane(self, source_pane: NotebookPane, widget, title: str) -> None:
        if len(self.panes) == 1:
            self._add_pane()
        target = next(
            (pane for pane in self.panes if pane is not source_pane),
            self.panes[0],
        )
        target.add_tab(widget, title)

    def _on_pane_emptied(self, pane: NotebookPane) -> None:
        # No se eliminan paneles vacios para mantener la estructura simple
        pass

    # -- miscelanea -------------------------------------------------------

    def _about(self) -> None:
        messagebox.showinfo(
            "Acerca de",
            "Packet Logger\n\n"
            "- Captura TCP/UDP de cualquier proceso con Npcap (Scapy)\n"
            "- Inyeccion de paquetes en el proceso (socket duplicado, TCP)\n"
            "- Los paquetes se muestran como texto si son legibles y hex si no\n"
            "- Lectura/filtrado de archivos [{hh:mm:ss}]\\t[{Recv|Send}]\\t{packet}\n"
            "- Perfiles de filtros guardados en profiles/\n"
            "El trafico cifrado (TLS/HTTPS) no se puede descifrar.\n"
            "Uso educativo.",
            parent=self,
        )

    def _on_close(self) -> None:
        save_settings(self.settings)
        for widget in self._all_tabs():
            if isinstance(widget, SourceTab):
                try:
                    widget.close()
                except tk.TclError:
                    pass
        self._close_injectors()
        self.destroy()


def run() -> None:
    app = App()
    app.mainloop()
