"""Captura de trafico de red de un proceso cualquiera usando Npcap/Scapy.

Flujo:
  1. Usar una conexion concreta (TCP o UDP) elegida por el usuario.
  2. Elegir la interfaz Npcap que posee la IP local de esa conexion.
  3. Olfatear con filtro BPF `tcp|udp and host <ip> and port <puerto>`.
  4. Decodificar la carga: texto si es legible, hex si no.

Notas: requiere Npcap instalado y permisos de Administrador. El trafico cifrado
(TLS/HTTPS) solo se puede mostrar en hex, no se puede descifrar.
"""
from __future__ import annotations

import queue
from datetime import datetime
from typing import Callable, Optional

import psutil
from scapy.all import AsyncSniffer, Raw, TCP, UDP, conf

from .models import Packet
from .processio import find_tcp_connections

PRINTABLE_BYTES = frozenset(list(range(32, 127)) + [9, 10, 13])


def decode_payload(payload: bytes) -> str:
    """Decodifica un payload: texto si es legible, hex si no."""
    if not payload:
        return ""
    printable = sum(1 for byte in payload if byte in PRINTABLE_BYTES)
    if printable / len(payload) >= 0.7:
        return payload.decode("ascii", "replace").strip("\x00\r\n ").rstrip()
    return payload.hex(" ")


class NpcapCaptureSource:
    """Fuente de paquetes que olfatea el trafico TCP/UDP de un proceso.

    connection: dict {proto, local_ip, local_port, remote_ip, remote_port}
                cuando se elige una conexion concreta en la interfaz.
    """

    def __init__(
        self,
        process: Optional[psutil.Process] = None,
        remote_port: Optional[int] = None,
        connection: Optional[dict] = None,
        emit: Optional[Callable[[Packet], None]] = None,
    ):
        self.process = process
        self.remote_port = remote_port
        self.connection = connection
        self.emit = emit or (lambda _packet: None)
        self.queue: "queue.Queue[Packet]" = queue.Queue()
        self.info: dict = {}
        self._sniffer: Optional[AsyncSniffer] = None

    def resolve(self) -> dict:
        """Devuelve la conexion a capturar. Lanza RuntimeError si no existe."""
        if self.connection is not None:
            self.info = dict(self.connection)
            return self.info

        if self.process is not None and self.remote_port:
            connections = find_tcp_connections(self.process, (self.remote_port,))
            if not connections:
                raise RuntimeError(
                    f"El proceso {self.process.pid} no tiene conexiones TCP activas "
                    f"hacia el puerto {self.remote_port}."
                )
            self.info = connections[0]
            return self.info

        raise RuntimeError(
            "No hay conexion seleccionada. Abre el dialogo de captura, elige un "
            "proceso y una de sus conexiones TCP/UDP."
        )

    def _find_interface(self, local_ip: str) -> Optional[str]:
        """Busca la interfaz Npcap que posee la IP local de la conexion."""
        try:
            for iface in conf.ifaces.values():
                if local_ip in iface.ips.get(4, []):
                    # description contiene el dispositivo NPF (p. ej. \\Device\\NPF_{GUID})
                    return iface.description or iface.name or None
        except Exception:
            pass
        return None

    def start(self) -> None:
        """Inicia el olfateo en segundo plano. Lanza RuntimeError si no hay conexion."""
        connection = self.resolve()
        proto = connection.get("proto", "tcp")
        remote_ip = connection.get("remote_ip", "")
        remote_port = connection.get("remote_port")
        local_ip = connection.get("local_ip", "0.0.0.0")
        local_port = connection.get("local_port")

        iface = self._find_interface(local_ip)
        is_ipv6 = ":" in (remote_ip or "")
        if remote_ip and remote_port:
            family = "ip6 and " if is_ipv6 else ""
            capture_filter = f"{family}{proto} and host {remote_ip} and port {remote_port}"
        elif proto == "udp" and local_port:
            # Endpoint UDP sin extremo remoto: capturar por puerto local
            family = "ip6 and " if ":" in str(local_ip) else ""
            capture_filter = f"{family}udp and port {local_port}"
        else:
            raise RuntimeError(
                "La conexion seleccionada no tiene ip:puerto remoto ni puerto local."
            )

        try:
            self._sniffer = AsyncSniffer(
                iface=iface,
                filter=capture_filter,
                prn=self._on_packet,
                store=False,
            )
            self._sniffer.start()
        except Exception as exc:
            raise RuntimeError(
                f"No se pudo iniciar la captura con Npcap: {exc}\n"
                "Comprueba que Npcap este instalado y que el programa se ejecute "
                "como Administrador."
            ) from exc

    def _on_packet(self, raw_packet) -> None:
        sport = None
        if TCP in raw_packet:
            sport = raw_packet[TCP].sport
        elif UDP in raw_packet:
            sport = raw_packet[UDP].sport
        if sport is None or Raw not in raw_packet:
            return
        payload = bytes(raw_packet[Raw].load)
        if not payload:
            return

        remote_port = self.info.get("remote_port")
        if remote_port:
            direction = "Recv" if sport == remote_port else "Send"
        else:
            # Sin extremo remoto conocido: heuristica por puerto local
            local_port = self.info.get("local_port")
            direction = "Send" if sport == local_port else "Recv"

        text = decode_payload(payload)

        source = (
            f"captura:{self.info.get('proto', 'tcp')}:"
            f"{self.info.get('remote_ip', '?')}:"
            f"{remote_port or self.info.get('local_port', '?')}"
        )
        self.queue.put(
            Packet(
                time=datetime.now().time(),
                direction=direction,
                data=text,
                source=source,
            )
        )
        self.emit(self.queue.queue[-1])

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None

    @property
    def running(self) -> bool:
        return self._sniffer is not None and self._sniffer.running

    @property
    def summary(self) -> str:
        if self.info:
            return (
                f"captura {self.info.get('proto', 'tcp')} "
                f"{self.info.get('remote_ip', '?')}:"
                f"{self.info.get('remote_port') or self.info.get('local_port', '?')}"
            )
        return "captura Npcap (sin conexion)"
