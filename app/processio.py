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
from ctypes import wintypes
from typing import List, Optional, Tuple

import psutil

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
ws2_32 = ctypes.WinDLL("ws2_32", use_last_error=True)

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


def enumerate_handles(pid: int) -> List[int]:
    """Enumeracion de handles del proceso via NtQuerySystemInformation."""
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


def duplicate_handle(process_handle: wintypes.HANDLE, handle_value: int) -> Optional[wintypes.HANDLE]:
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
    except OSError:
        return None
    return target if target.value else None


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
    return ws2_32.send(handle, buffer, len(data), 0)


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
        self.name = process.info.get("name") if process.info else str(process.pid)
        self.process_handle: Optional[wintypes.HANDLE] = None
        self.socket_handle: Optional[wintypes.HANDLE] = None
        self.remote: Optional[Tuple[str, int]] = None

    def connect(
        self,
        ports: Optional[Tuple[int, ...]] = None,
        target: Optional[Tuple[str, int]] = None,
    ) -> bool:
        """Duplica el socket de una conexion TCP del proceso.

        ports:  tupla de puertos remotos permitidos (None = cualquiera).
        target: (ip, puerto) remoto concreto que debe coincidir.

        Devuelve True si se conecto; lanza RuntimeError con el detalle si falla.
        """
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

        chosen = connections[0]
        target_remote = (chosen["remote_ip"], chosen["remote_port"])

        checked = 0
        for handle_value in enumerate_handles(self.pid):
            duplicated = duplicate_handle(self.process_handle, handle_value)
            if duplicated is None:
                continue
            checked += 1
            try:
                if is_tcp_socket(duplicated) and socket_remote(duplicated) == target_remote:
                    self.socket_handle = duplicated
                    self.remote = target_remote
                    return True
                kernel32.CloseHandle(duplicated)
            except OSError:
                pass
        raise RuntimeError(
            f"No se pudo duplicar el socket de {target_remote[0]}:{target_remote[1]} "
            f"(se comprobaron {checked} handles del proceso).\n"
            "Ejecuta el programa como Administrador; si ya lo haces, el proceso "
            "puede estar protegiendo sus handles."
        )

    def send(self, direction: str, text: str) -> int:
        """Envia un paquete por el socket duplicado. Devuelve bytes enviados."""
        if self.socket_handle is None:
            raise RuntimeError("Inyector no conectado: no hay socket duplicado")
        data = text.encode("ascii", "ignore")
        sent = send_on_socket(self.socket_handle, data)
        if sent != len(data):
            raise RuntimeError(f"send() incompleto: {sent}/{len(data)} bytes")
        return sent

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
