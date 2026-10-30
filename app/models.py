"""Modelos de datos: paquete y parseo del formato de archivo.

Formato soportado (una linea por paquete):
    [{hh:mm:ss}]\t[{Recv|Send}]\t{packet}
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import time as dtime

LINE_RE = re.compile(r"^\[(\d{2}):(\d{2}):(\d{2})\]\t\[(Recv|Send)\]\t(.*)$")

VALID_DIRECTIONS = ("Send", "Recv")


@dataclass
class Packet:
    """Un paquete capturado o leido de archivo."""

    time: dtime
    direction: str  # 'Send' (cliente -> servidor) | 'Recv' (servidor -> cliente)
    data: str
    source: str = ""

    def to_line(self) -> str:
        """Formatea el paquete en el formato de archivo compatible."""
        return f"[{self.time.strftime('%H:%M:%S')}]\t[{self.direction}]\t{self.data}"


def parse_packet_line(line: str) -> Packet | None:
    """Convierte una linea del formato `[{hh:mm:ss}]\\t[{Recv|Send}]\\t{packet}` en un Packet."""
    match = LINE_RE.match(line.rstrip("\n\r"))
    if not match:
        return None
    hh, mm, ss, direction, data = match.groups()
    try:
        packet_time = dtime(int(hh), int(mm), int(ss))
    except ValueError:
        return None
    return Packet(time=packet_time, direction=direction, data=data)
