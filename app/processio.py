"""Acceso Win32 a procesos: enumeracion de sockets e inyeccion de paquetes.

Tecnica:
  1. Localizar el proceso objetivo y sus conexiones TCP.
  2. Enumerar los handles del proceso con NtQuerySystemInformation.
  3. Duplicar el handle del socket TCP con DuplicateHandle.
  4. Enviar datos sobre el socket duplicado con send() de ws2_32.

Requiere ejecutar como Administrador (o el mismo usuario que el proceso
objetivo) para abrirlo con PROCESS_DUP_HANDLE.
"""
from __future__ import annotations

import ctypes
import socket as _socket
import threading
import time
from ctypes import wintypes
from typing import List, Optional, Tuple

import psutil

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
ws2_32 = ctypes.WinDLL("ws2_32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)
shell32.IsUserAnAdmin.restype = wintypes.BOOL

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_DUP_HANDLE = 0x0040
MAXIMUM_ALLOWED = 0x02000000

SOL_SOCKET = 0xFFFF
SO_TYPE = 0x1008
SOCK_STREAM = 1
AF_INET = 2

# NtQuerySystemInformation(SystemHandleInformation)
SYSTEM_HANDLE_INFORMATION_CLASS = 16
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004


class SOCKADDR_IN(ctypes.Structure):
    _fields_ = [
        ("sin_family", ctypes.c_short),
        ("sin_port", ctypes.c_ushort),
        ("sin_addr", ctypes.c_ubyte * 4),
        ("sin_zero", ctypes.c_ubyte * 8),
    ]


class SYSTEM_HANDLE_TABLE_ENTRY_INFO(ctypes.Structure):
    _fields_ = [
        ("UniqueProcessId", wintypes.USHORT),
        ("CreatorBackTraceIndex", wintypes.USHORT),
        ("ObjectTypeIndex", ctypes.c_byte),
        ("HandleAttributes", ctypes.c_byte),
        ("HandleValue", wintypes.USHORT),
        ("Object", ctypes.c_void_p),
        ("GrantedAccess", wintypes.ULONG),
    ]


class SYSTEM_HANDLE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("NumberOfHandles", wintypes.ULONG),
        ("Handles", SYSTEM_HANDLE_TABLE_ENTRY_INFO * 1),
    ]


class PROCESS_HANDLE_TABLE_ENTRY_INFO(ctypes.Structure):
    _fields_ = [
        ("HandleValue", ctypes.c_void_p),
        ("HandleCount", ctypes.c_size_t),
        ("PointerCount", ctypes.c_size_t),
        ("GrantedAccess", ctypes.c_ulong),
        ("ObjectTypeIndex", ctypes.c_ulong),
        ("HandleAttributes", ctypes.c_ulong),
        ("Reserved", ctypes.c_ulong),
    ]


class PROCESS_HANDLE_SNAPSHOT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("NumberOfHandles", ctypes.c_size_t),
        ("Handles", PROCESS_HANDLE_TABLE_ENTRY_INFO * 1),
    ]


def _errcheck_handle(result, _func, _args):
    if not result:
        raise ctypes.WinError(ctypes.get_last_error())
    return result


kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.errcheck = _errcheck_handle

kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

kernel32.GetCurrentProcess.restype = wintypes.HANDLE

kernel32.DuplicateHandle.restype = wintypes.BOOL
kernel32.DuplicateHandle.argtypes = [
    wintypes.HANDLE,
    wintypes.HANDLE,
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.HANDLE),
    wintypes.DWORD,
    wintypes.BOOL,
    wintypes.DWORD,
]
kernel32.DuplicateHandle.errcheck = _errcheck_handle

kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]

ntdll.NtQuerySystemInformation.restype = ctypes.c_long
ntdll.NtQuerySystemInformation.argtypes = [
    ctypes.c_long,
    ctypes.c_void_p,
    wintypes.ULONG,
    ctypes.POINTER(wintypes.ULONG),
]

# NtQueryInformationProcess(ProcessHandleInformation = 51)
ntdll.NtQueryInformationProcess.restype = ctypes.c_long
ntdll.NtQueryInformationProcess.argtypes = [
    wintypes.HANDLE,
    ctypes.c_long,
    ctypes.c_void_p,
    wintypes.ULONG,
    ctypes.POINTER(wintypes.ULONG),
]
PROCESS_HANDLE_INFORMATION_CLASS = 51

ws2_32.getsockopt.restype = ctypes.c_int
ws2_32.getsockopt.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_int),
]

ws2_32.getpeername.restype = ctypes.c_int
ws2_32.getpeername.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]

ws2_32.send.restype = ctypes.c_int
ws2_32.send.argtypes = [wintypes.HANDLE, ctypes.c_char_p, ctypes.c_int, ctypes.c_int]


# ---------------------------------------------------------------------------
# Procesos y conexiones
# ---------------------------------------------------------------------------

def find_tcp_connections(proc: psutil.Process, ports: Optional[Tuple[int, ...]] = None) -> List[dict]:
    """Devuelve las conexiones TCP establecidas del proceso.

    Si `ports` es None se devuelven todas las conexiones IPv4 establecidas.
    """
    connections: List[dict] = []
    net_connections = getattr(proc, "net_connections", None) or proc.connections
    try:
        for conn in net_connections(kind="tcp"):
            if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
                continue
            remote_port = conn.raddr.port
            if ports is not None and remote_port not in ports:
                continue
            connections.append(
                {
                    "proto": "tcp",
                    "local_ip": conn.laddr.ip if conn.laddr else "0.0.0.0",
                    "local_port": conn.laddr.port if conn.laddr else 0,
                    "remote_ip": conn.raddr.ip,
                    "remote_port": remote_port,
                }
            )
    except (psutil.AccessDenied, psutil.Error):
        return []
    return connections


def find_udp_endpoints(proc: psutil.Process) -> List[dict]:
    """Devuelve los endpoints UDP del proceso (sockets abiertos, aunque no esten conectados)."""
    endpoints: List[dict] = []
    net_connections = getattr(proc, "net_connections", None) or proc.connections
    try:
        for conn in net_connections(kind="udp"):
            if not conn.laddr:
                continue
            remote = conn.raddr if conn.raddr else None
            endpoints.append(
                {
                    "proto": "udp",
                    "local_ip": conn.laddr.ip if conn.laddr.ip else "0.0.0.0",
                    "local_port": conn.laddr.port if conn.laddr else 0,
                    "remote_ip": remote.ip if remote else "",
                    "remote_port": remote.port if remote else 0,
                }
            )
    except (psutil.AccessDenied, psutil.Error):
        return []
    return endpoints


def find_process_connections(proc: psutil.Process) -> List[dict]:
    """Combina las conexiones TCP establecidas y los endpoints UDP del proceso."""
    return find_tcp_connections(proc, None) + find_udp_endpoints(proc)


# Puertos tipicos de servidores de juegos online:
# 30000-30199 = puerto de juego, 20000-20099 = lobby/auth.
GAME_PORT_RANGES = ((30000, 30199), (20000, 20099))


def is_admin() -> bool:
    """True si el proceso actual se ejecuta con permisos de Administrador."""
    try:
        return bool(shell32.IsUserAnAdmin())
    except Exception:
        return False


def score_tcp_connection(connection: dict) -> int:
    """Puntuacion heuristica: cuanto mas alta, mas probable es la conexion de juego."""
    port = connection.get("remote_port", 0)
    score = 0
    if 30000 <= port <= 30199:
        score += 20
    elif 20000 <= port <= 20099:
        score += 10
    elif port not in (80, 443, 53, 8080, 8443):
        score += 5
    return score


def best_tcp_connection(connections: List[dict]) -> Optional[dict]:
    """Devuelve la conexion TCP mas probable para capturar/inyectar."""
    if not connections:
        return None
    return max(
        connections,
        key=lambda c: (score_tcp_connection(c), c.get("remote_port", 0)),
    )


def list_all_processes() -> List[psutil.Process]:
    """Devuelve todos los procesos con pid y nombre, ordenados por nombre."""
    found: List[psutil.Process] = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            pid = proc.info.get("pid")
            name = proc.info.get("name") or ""
        except (psutil.Error, OSError):
            continue
        if pid and name:
            found.append(proc)
    try:
        found.sort(key=lambda p: (p.info.get("name") or "").lower())
    except psutil.Error:
        pass
    return found


# ---------------------------------------------------------------------------
# Handles, sockets y memoria
# ---------------------------------------------------------------------------

def open_process(pid: int) -> wintypes.HANDLE:
    return kernel32.OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, False, pid
    )


def enumerate_process_handles(process_handle: wintypes.HANDLE) -> List[int]:
    """Enumeracion de handles del proceso objetivo via NtQueryInformationProcess.

    Mas fiable que la enumeracion global (funciona con PIDs grandes y requiere
    menos privilegios).
    """
    handles, _status = _query_process_handles(process_handle)
    return handles


def _query_process_handles(process_handle: wintypes.HANDLE):
    """Devuelve (lista_de_handles, status_nt) de NtQueryInformationProcess."""
    length = wintypes.ULONG(0x10000)
    needed = wintypes.ULONG(0)
    for _ in range(10):
        buffer = ctypes.create_string_buffer(length.value)
        status = ntdll.NtQueryInformationProcess(
            process_handle,
            PROCESS_HANDLE_INFORMATION_CLASS,
            buffer,
            length,
            ctypes.byref(needed),
        )
        if status == STATUS_INFO_LENGTH_MISMATCH:
            length.value = max(needed.value * 2, length.value * 2)
            continue
        if status != 0:
            return [], status
        snapshot = ctypes.cast(buffer, ctypes.POINTER(PROCESS_HANDLE_SNAPSHOT_INFORMATION))
        count = snapshot.contents.NumberOfHandles
        entries = ctypes.cast(
            ctypes.addressof(snapshot.contents.Handles),
            ctypes.POINTER(PROCESS_HANDLE_TABLE_ENTRY_INFO * count),
        )
        return [entry.HandleValue for entry in entries.contents], 0
    return [], 0


def enumerate_system_handles(pid: int) -> List[int]:
    """Respaldo: enumeracion global de handles via NtQuerySystemInformation."""
    length = wintypes.ULONG(0x100000)  # 1 MB inicial
    needed = wintypes.ULONG(0)
    for _ in range(10):
        buffer = ctypes.create_string_buffer(length.value)
        status = ntdll.NtQuerySystemInformation(
            SYSTEM_HANDLE_INFORMATION_CLASS, buffer, length, ctypes.byref(needed)
        )
        if status == STATUS_INFO_LENGTH_MISMATCH:
            length.value = max(needed.value * 2, length.value * 2)
            continue
        if status != 0:
            return []
        info = ctypes.cast(buffer, ctypes.POINTER(SYSTEM_HANDLE_INFORMATION))
        count = info.contents.NumberOfHandles
        entries = ctypes.cast(
            ctypes.addressof(info.contents.Handles),
            ctypes.POINTER(SYSTEM_HANDLE_TABLE_ENTRY_INFO * count),
        )
        return [
            entry.HandleValue
            for entry in entries.contents
            if entry.UniqueProcessId == pid
        ]
    return []


def duplicate_handle(process_handle: wintypes.HANDLE, handle_value: int):
    """Duplica un handle del proceso objetivo. Devuelve (handle, error_win) o (None, codigo)."""
    target = wintypes.HANDLE()
    current = kernel32.GetCurrentProcess()
    try:
        kernel32.DuplicateHandle(
            process_handle,
            wintypes.HANDLE(handle_value),
            current,
            ctypes.byref(target),
            0,
            False,
            MAXIMUM_ALLOWED,
        )
    except OSError as exc:
        return None, exc.winerror or ctypes.get_last_error()
    return (target if target.value else None), 0


def is_tcp_socket(handle: wintypes.HANDLE) -> bool:
    opt = ctypes.c_int(0)
    opt_len = ctypes.c_int(ctypes.sizeof(opt))
    if ws2_32.getsockopt(handle, SOL_SOCKET, SO_TYPE, ctypes.byref(opt), ctypes.byref(opt_len)) != 0:
        return False
    return opt.value == SOCK_STREAM


def socket_remote(handle: wintypes.HANDLE) -> Optional[Tuple[str, int]]:
    addr = SOCKADDR_IN()
    addr_len = ctypes.c_int(ctypes.sizeof(addr))
    if ws2_32.getpeername(handle, ctypes.byref(addr), ctypes.byref(addr_len)) != 0:
        return None
    if addr.sin_family != AF_INET:
        return None
    ip = _socket.inet_ntoa(bytes(addr.sin_addr))
    port = _socket.ntohs(addr.sin_port)
    return ip, port


def send_on_socket(handle: wintypes.HANDLE, data: bytes) -> int:
    if not data:
        return 0
    buffer = ctypes.create_string_buffer(data, len(data))
    sent = ws2_32.send(handle, buffer, len(data), 0)
    if sent < 0:
        # SOCKET_ERROR: incluir el codigo de error de Winsock en el mensaje
        raise OSError(ctypes.get_last_error(), "ws2_32.send fallo")
    return sent


def read_process_memory(process_handle: wintypes.HANDLE, address: int, size: int) -> Optional[bytes]:
    buffer = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    if not kernel32.ReadProcessMemory(
        process_handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(read)
    ):
        return None
    return buffer.raw[: read.value]


# ---------------------------------------------------------------------------
# Inyector
# ---------------------------------------------------------------------------

class SocketInjector:
    """Permite inyectar paquetes en una conexion TCP activa de otro proceso.

    El mismo socket duplicado sirve para ambas direcciones:
      - 'Send'  -> el servidor recibira el paquete como si lo enviara el cliente
      - 'Recv'  -> el cliente recibira el paquete como si lo enviara el servidor
    El texto se envia tal cual (sin cifrar).
    """

    def __init__(self, process: psutil.Process):
        self.process = process
        self.pid = process.pid
        try:
            self.name = process.name() or str(process.pid)
        except Exception:
            self.name = str(process.pid)
        self.process_handle: Optional[wintypes.HANDLE] = None
        self.socket_handle: Optional[wintypes.HANDLE] = None
        self.remote: Optional[Tuple[str, int]] = None
        # Reconexion automatica (los juegos cambian de conexion a menudo)
        self._target: Optional[Tuple[str, int]] = None
        self._reconnect_thread: Optional[threading.Thread] = None
        self._reconnect_stop = threading.Event()
        self._reconnect_wake = threading.Event()
        self._reconnect_interval = 5.0
        self._reconnect_callback = None

    def connect(
        self,
        ports: Optional[Tuple[int, ...]] = None,
        target: Optional[Tuple[str, int]] = None,
        retries: int = 3,
        retry_delay: float = 0.8,
    ) -> bool:
        """Duplica el socket de una conexion TCP del proceso.

        ports:  tupla de puertos remotos permitidos (None = cualquiera).
        target: (ip, puerto) remoto concreto que debe coincidir.
        retries: reintentos extra si la conexion no aparece o desaparece
                 (algunos juegos reconectan con frecuencia).

        Devuelve True si se conecto; lanza RuntimeError con el detalle si falla.
        """
        if target is not None:
            self._target = target
        attempts = max(1, retries + 1)
        last_error: Optional[RuntimeError] = None
        for attempt in range(attempts):
            try:
                self._connect_once(ports, target)
                return True
            except RuntimeError as exc:
                last_error = exc
                if attempt + 1 < attempts:
                    time.sleep(retry_delay)
        assert last_error is not None
        raise last_error

    def _connect_once(
        self,
        ports: Optional[Tuple[int, ...]] = None,
        target: Optional[Tuple[str, int]] = None,
    ) -> None:
        """Un unico intento de duplicar el socket (sin reintentos)."""
        self.close()
        try:
            self.process_handle = open_process(self.pid)
        except OSError as exc:
            raise RuntimeError(
                f"No se pudo abrir el proceso {self.pid} ({exc}). "
                "Ejecuta el programa como Administrador."
            ) from exc

        connections = find_tcp_connections(self.process, ports)
        if target is not None:
            connections = [
                c for c in connections if (c["remote_ip"], c["remote_port"]) == target
            ]
        if not connections:
            if target is not None:
                raise RuntimeError(
                    f"La conexion {target[0]}:{target[1]} ya no existe en el proceso. "
                    "Comprueba que siga conectado y vuelve a intentarlo."
                )
            raise RuntimeError(
                f"El proceso {self.pid} no tiene conexiones TCP establecidas."
            )

        chosen = best_tcp_connection(connections)
        target_remote = (chosen["remote_ip"], chosen["remote_port"])

        checked = 0
        duplicate_failures = 0
        first_dup_error = 0
        tcp_peers = []
        handle_values, nt_status = _query_process_handles(self.process_handle)
        handle_values = [value for value in handle_values if value]
        if not handle_values:
            handle_values = enumerate_system_handles(self.pid)
        total = len(handle_values)

        def try_socket(duplicated: wintypes.HANDLE) -> bool:
            """Comprueba si el handle es el socket TCP objetivo (y lo registra)."""
            if not is_tcp_socket(duplicated):
                return False
            peer = socket_remote(duplicated)
            if peer is not None and peer not in tcp_peers and len(tcp_peers) < 5:
                tcp_peers.append(peer)
            if peer == target_remote:
                self.socket_handle = duplicated
                self.remote = target_remote
                return True
            return False

        for handle_value in handle_values:
            duplicated, dup_error = duplicate_handle(self.process_handle, handle_value)
            if duplicated is None:
                duplicate_failures += 1
                if not first_dup_error:
                    first_dup_error = dup_error
                continue
            checked += 1
            try:
                if try_socket(duplicated):
                    return
                kernel32.CloseHandle(duplicated)
            except OSError:
                pass
        if self.socket_handle is None:
            # Respaldo: escanear valores de handle tipicos (el parseo de la tabla
            # puede fallar en algunas versiones de Windows).
            for handle_value in range(4, 0x10000, 4):
                duplicated, _dup_error = duplicate_handle(self.process_handle, handle_value)
                if duplicated is None:
                    continue
                checked += 1
                try:
                    if try_socket(duplicated):
                        return
                    kernel32.CloseHandle(duplicated)
                except OSError:
                    pass
        if checked == 0 and total == 0:
            if nt_status in (0xC0000022, 0xC0000005):
                hint = (
                    f"No se pudo enumerar los handles del proceso (acceso denegado, "
                    f"NT 0x{nt_status & 0xFFFFFFFF:08X}). Ejecuta el programa como "
                    "Administrador."
                )
            else:
                hint = (
                    f"No se pudo enumerar ningun handle del proceso (NT "
                    f"0x{nt_status & 0xFFFFFFFF:08X}). Ejecuta el programa como "
                    "Administrador; si ya lo haces, el proceso puede estar protegido."
                )
        elif checked == 0:
            hint = (
                f"Se enumeraron {total} handles pero ninguno pudo duplicarse "
                f"({duplicate_failures} fallos de DuplicateHandle, primer error "
                f"WinError {first_dup_error}). El proceso protege sus handles o no "
                "tienes permisos suficientes (ejecuta como Administrador)."
            )
        else:
            if tcp_peers:
                peers_text = ", ".join(f"{ip}:{port}" for ip, port in tcp_peers)
                peers_info = f" Sockets TCP vistos: {peers_text}."
            else:
                peers_info = " No se encontro ningun socket TCP entre los handles."
            hint = (
                f"Se comprobaron {checked} handles sin hallar el socket "
                f"{target_remote[0]}:{target_remote[1]}.{peers_info}\n"
                "Si aparece otro socket, elige esa conexion en el inyector; si no "
                "hay ninguno, el proceso puede estar protegiendo su socket."
            )
        raise RuntimeError(
            f"No se pudo duplicar el socket de {target_remote[0]}:{target_remote[1]} "
            f"(se comprobaron {checked} de {total} handles del proceso).\n{hint}"
        )

    def send(self, direction: str, text) -> int:
        """Envia un paquete (texto o bytes) por el socket duplicado.

        Devuelve bytes enviados. Lanza RuntimeError con el detalle si falla.
        """
        if self.socket_handle is None:
            raise RuntimeError("Inyector no conectado: no hay socket duplicado")
        if isinstance(text, str):
            data = text.encode("ascii", "ignore")
        else:
            data = bytes(text)
        try:
            sent = send_on_socket(self.socket_handle, data)
        except OSError as exc:
            self._reconnect_wake.set()
            raise RuntimeError(
                f"send() fallo (error Winsock {exc.errno}: {exc.strerror}). "
                "La conexion puede haberse cerrado o el proceso cerro el socket."
            ) from exc
        if sent != len(data):
            raise RuntimeError(f"send() incompleto: {sent}/{len(data)} bytes")
        return sent

    def start_auto_reconnect(self, interval: float = 5.0, callback=None) -> None:
        """Revisa cada `interval` segundos si la conexion sigue viva y reconecta.

        callback(injector) se invoca (desde el hilo) tras reconectar con exito.
        """
        self._reconnect_interval = max(1.0, interval)
        self._reconnect_callback = callback
        self._reconnect_stop.clear()
        self._reconnect_wake.clear()
        if self._reconnect_thread is None or not self._reconnect_thread.is_alive():
            self._reconnect_thread = threading.Thread(
                target=self._auto_reconnect_loop, name="auto-reconnect", daemon=True
            )
            self._reconnect_thread.start()

    def stop_auto_reconnect(self) -> None:
        self._reconnect_stop.set()
        self._reconnect_wake.set()

    def _auto_reconnect_loop(self) -> None:
        while not self._reconnect_stop.is_set():
            self._reconnect_wake.wait(self._reconnect_interval)
            self._reconnect_wake.clear()
            if self._reconnect_stop.is_set():
                break
            if self._connection_alive():
                continue
            try:
                self.connect(target=self._target, retries=3, retry_delay=1.5)
            except RuntimeError:
                self.close()
                continue
            callback = self._reconnect_callback
            if callback is not None:
                try:
                    callback(self)
                except Exception:
                    pass

    def _connection_alive(self) -> bool:
        """Comprueba (via psutil, sin tocar el socket) si la conexion sigue."""
        if self.remote is None:
            return False
        try:
            connections = find_tcp_connections(self.process, (self.remote[1],))
        except Exception:
            return False
        return any(
            connection.get("remote_ip") == self.remote[0] for connection in connections
        )

    def close(self) -> None:
        for handle in (self.socket_handle, self.process_handle):
            if handle is not None:
                try:
                    kernel32.CloseHandle(handle)
                except OSError:
                    pass
        self.socket_handle = None
        self.process_handle = None
        self.remote = None

    @property
    def connected(self) -> bool:
        return self.socket_handle is not None

    def __repr__(self) -> str:  # pragma: no cover
        state = f"{self.remote[0]}:{self.remote[1]}" if self.remote else "sin conexion"
        return f"{self.name} ({state})"


# ---------------------------------------------------------------------------
# Escaneo de memoria (busqueda del estado RC4 del proceso)
# ---------------------------------------------------------------------------

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

_READABLE_PROTECTS = {
    PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
}


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t,
]


def list_readable_regions(process_handle: wintypes.HANDLE, max_regions: int = 20000, private_only: bool = False):
    """Regiones de memoria comprometidas y legibles del proceso.

    Con private_only=True se devuelven solo regiones privadas (heap/datos del
    proceso, no imagenes mapeadas): donde viven las tablas RC4.
    """
    regions = []
    address = 0
    info = MEMORY_BASIC_INFORMATION()
    while len(regions) < max_regions:
        result = kernel32.VirtualQueryEx(
            process_handle, ctypes.c_void_p(address), ctypes.byref(info), ctypes.sizeof(info)
        )
        if result == 0:
            break
        start = info.BaseAddress or 0
        size = int(info.RegionSize)
        if (
            info.State == MEM_COMMIT
            and info.Protect in _READABLE_PROTECTS
            and size > 0
            and not (private_only and info.Type != MEM_PRIVATE)
        ):
            regions.append((start, min(size, 32 * 1024 * 1024)))
        address = start + size
        if address <= start:
            break
    return regions


def scan_process_permutations(
    process,
    region_limit: int = 20000,
    max_bytes: int = 256 * 1024 * 1024,
    progress=None,
    pass_start: int = 0,
    pass_count: int = 1,
):
    """Busca tablas RC4 (256 bytes permutacion de 0..255) en la memoria.

    Escanea solo regiones privadas, en pasadas alineadas a 4 bytes (las tablas
    estan alineadas por el asignador). `pass_start`/`pass_count` eligen que
    residuos modulo 4 se examinan (las 4 pasadas cubren toda la memoria).
    `progress(bytes_escaneados)` se llama periodicamente.

    Devuelve [(direccion, sbox_bytes)].
    """
    from .crypto import is_permutation

    handle = open_process(process.pid)
    if not handle:
        raise RuntimeError(f"No se pudo abrir el proceso {process.pid}")
    try:
        candidates = []
        regions = list_readable_regions(handle, region_limit, private_only=True)
        for pass_offset in range(pass_start, pass_start + pass_count):
            scanned = 0
            for start, size in regions:
                if scanned >= max_bytes:
                    break
                chunk = read_process_memory(handle, start, size)
                if not chunk:
                    continue
                scanned += len(chunk)
                if progress is not None:
                    progress(scanned)
                for index in range(pass_offset, len(chunk) - 255, 4):
                    window = chunk[index:index + 256]
                    if is_permutation(window):
                        candidates.append((start + index, bytes(window)))
                        if len(candidates) >= 300:
                            return candidates
        return candidates
    finally:
        kernel32.CloseHandle(handle)


def read_nearby_bytes(handle: wintypes.HANDLE, address: int, radius: int = 64) -> bytes:
    """Lee `radius` bytes alrededor de una direccion (para localizar i y j)."""
    chunk = read_process_memory(handle, address - radius, radius * 2 + 256)
    return bytes(chunk) if chunk else b""


def scan_process_for_bytes(process, needle: bytes, limit: int = 1000):
    """Busca una secuencia de bytes en la memoria del proceso."""
    handle = open_process(process.pid)
    if not handle:
        raise RuntimeError(f"No se pudo abrir el proceso {process.pid}")
    try:
        found = []
        for start, size in list_readable_regions(handle):
            chunk = read_process_memory(handle, start, size)
            if not chunk:
                continue
            pos = chunk.find(needle)
            while pos != -1 and len(found) < limit:
                found.append(start + pos)
                pos = chunk.find(needle, pos + 1)
        return found
    finally:
        kernel32.CloseHandle(handle)
