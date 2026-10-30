"""Fuente de paquetes basada en archivos con formato:
    [{hh:mm:ss}]\t[{Recv|Send}]\t{packet}
"""
from __future__ import annotations

import os
from typing import Callable, List, Optional

from .models import Packet, parse_packet_line


class FilePacketSource:
    """Lee un archivo de registro de paquetes y expone los paquetes filtrables."""

    def __init__(self, path: str):
        self.path = path
        self.packets: List[Packet] = []
        self.invalid_lines = 0
        self.load()

    def load(self) -> None:
        self.packets = []
        self.invalid_lines = 0
        with open(self.path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                packet = parse_packet_line(line)
                if packet is not None:
                    packet.source = os.path.basename(self.path)
                    self.packets.append(packet)
                elif line.strip():
                    self.invalid_lines += 1

    def __len__(self) -> int:
        return len(self.packets)

    @property
    def summary(self) -> str:
        return f"{os.path.basename(self.path)} ({len(self.packets)} paquetes)"


class FileReplayer:
    """Reenvia los paquetes de un archivo a un destino, una vez o periodicamente.

    direction_map permite mapear 'Send'/'Recv' del archivo a la direccion real
    de inyeccion (por defecto se mantiene tal cual).
    """

    def __init__(
        self,
        packets: List[Packet],
        send: Callable[[str, str], None],
        interval: float = 1.0,
    ):
        self.packets = list(packets)
        self.send = send
        self.interval = max(0.05, float(interval))
        self._stop = False
        self._index = 0

    def play_once(self) -> None:
        """Envia todos los paquetes una sola vez."""
        for packet in self.packets:
            if self._stop:
                return
            self.send(packet.direction, packet.data)

    def play_periodic(self) -> None:
        """Envia todos los paquetes y repite cada `interval` segundos hasta stop()."""
        import time

        while not self._stop:
            self.play_once()
            if not self._stop:
                time.sleep(self.interval)

    def stop(self) -> None:
        self._stop = True
