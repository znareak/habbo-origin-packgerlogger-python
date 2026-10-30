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
        # Modo de decodificacion binaria (activado desde la interfaz)
        self.binary_decode = False
        self._binary_streams = {"Send": bytearray(), "Recv": bytearray()}
        self._binary_framed = {"Send": False, "Recv": False}

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

        if self.binary_decode and self.info.get("proto", "tcp") == "tcp":
            stream = self._binary_streams[direction]
            stream.extend(payload)
            # Si esta direccion nunca produjo un mensaje con framing y la
            # cabecera no parece una longitud valida, tratarla como flujo
            # sin framing y mostrar el payload crudo en hex.
            if len(stream) >= 4 and not self._binary_framed[direction]:
                first_length = int.from_bytes(stream[0:4], "big")
                if first_length < 2 or first_length > BINARY_MAX_MESSAGE_LENGTH:
                    self._emit_packet(
                        direction, _format_unframed_payload(bytes(stream))
                    )
                    stream.clear()
                    return
            # Extraer todos los mensajes con framing disponibles
            while True:
                frames = extract_binary_frames(stream)
                if not frames:
                    break
                self._binary_framed[direction] = True
                for header, body in frames:
                    self._emit_packet(
                        direction, format_binary_message(direction, header, body)
                    )
            return

        self._emit_packet(direction, decode_payload(payload))

    def _emit_packet(self, direction: str, text: str) -> None:
        remote_port = self.info.get("remote_port")
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
        self._binary_streams = {"Send": bytearray(), "Recv": bytearray()}
        self._binary_framed = {"Send": False, "Recv": False}

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


# ---------------------------------------------------------------------------
# Decodificador de protocolo binario con framing
# ---------------------------------------------------------------------------
#
# Algunos protocolos de juegos online envian mensajes sin cifrar con la forma
#   [longitud: int32 big-endian][header: int16 big-endian][cuerpo...]
# donde la longitud incluye header (2 bytes) + cuerpo. Reensamblamos el flujo
# TCP por direccion y decodificamos el cuerpo con una heuristica generica
# (cadenas con prefijo de longitud, enteros, booleanos).

BINARY_MAX_MESSAGE_LENGTH = 1 << 20  # 1 MB: si se supera, el flujo se desincronizo


def extract_binary_frames(buffer: bytearray):
    """Extrae mensajes completos de un buffer TCP y los consume.

    Devuelve una lista de (header, body). Los bytes incompletos quedan en el
    buffer a la espera de mas datos. Si el flujo se desincroniza (longitud
    absurda) descarta bytes de uno en uno hasta volver a sincronizar.
    """
    frames = []
    while True:
        if len(buffer) < 4:
            break
        length = int.from_bytes(buffer[0:4], "big")
        if length < 2 or length > BINARY_MAX_MESSAGE_LENGTH:
            del buffer[0]
            continue
        if len(buffer) < 4 + length:
            break
        header = int.from_bytes(buffer[4:6], "big")
        body = bytes(buffer[6:4 + length])
        del buffer[0:4 + length]
        frames.append((header, body))
    return frames


def parse_binary_tokens(body: bytes):
    """Parsea el cuerpo de un mensaje binario con heuristica generica.

    Devuelve una lista de (tipo, valor):
      ('s', str)   cadena con longitud int16 big-endian
      ('i', int)   entero int32 big-endian (bytes altos a cero, lo habitual)
      ('h', int)   corto int16 big-endian
      ('b', bool)  booleano (byte 0/1)
      ('u', int)   byte crudo
    """
    tokens = []
    index = 0
    size = len(body)
    while index < size:
        # 1) Cadena con prefijo de longitud int16 BE
        if index + 2 <= size:
            string_len = int.from_bytes(body[index:index + 2], "big")
            if 0 < string_len <= size - index - 2:
                chunk = body[index + 2:index + 2 + string_len]
                printable = sum(
                    1 for byte in chunk if 32 <= byte < 127 or byte in (9, 10, 13)
                )
                if printable / len(chunk) >= 0.8:
                    tokens.append(("s", chunk.decode("utf-8", "replace")))
                    index += 2 + string_len
                    continue
        # 2) Entero int32 BE con bytes altos a cero (valores pequenos tipicos)
        if index + 4 <= size and body[index] == 0 and body[index + 1] == 0:
            tokens.append(("i", int.from_bytes(body[index:index + 4], "big")))
            index += 4
            continue
        # 3) Corto int16 BE
        if index + 2 <= size:
            tokens.append(("h", int.from_bytes(body[index:index + 2], "big")))
            index += 2
            continue
        # 4) Byte suelto (booleano o crudo)
        byte = body[index]
        index += 1
        tokens.append(("b", byte == 1) if byte in (0, 1) else ("u", byte))
    return tokens


def format_binary_message(direction: str, header: int, body: bytes) -> str:
    """Formatea un mensaje binario para mostrarlo en el logger."""
    if body:
        tokens = " ".join(_format_binary_token(token) for token in parse_binary_tokens(body))
    else:
        tokens = "(vacio)"
    side = "Incoming" if direction == "Recv" else "Outgoing"
    return f"{side} [{header}] {tokens}"


def encode_binary_message(text: str) -> bytes:
    """Construye un mensaje binario completo a partir de texto.

    Formato: "<header> <token> <token> ..." donde cada token es:
      i:123      entero int32 big-endian
      h:123      corto int16 big-endian
      s:"texto"  cadena (longitud int16 BE + bytes UTF-8)
      b:true     booleano (true/false/1/0)
      u:0xFF     byte crudo

    Devuelve [longitud int32 BE][header int16 BE][cuerpo].
    """
    tokens = text.split()
    if not tokens:
        raise ValueError("paquete vacio: indica el header y los campos")
    try:
        header = int(tokens[0], 0)
    except ValueError as exc:
        raise ValueError(f"header invalido: {tokens[0]}") from exc
    body = bytearray()
    for token in tokens[1:]:
        kind, separator, value = token.partition(":")
        if not separator:
            raise ValueError(f"token sin tipo (usa i:/h:/s:/b:/u:): {token}")
        try:
            if kind == "i":
                body += int(value, 0).to_bytes(4, "big", signed=True)
            elif kind == "h":
                body += int(value, 0).to_bytes(2, "big", signed=True)
            elif kind == "s":
                data = value.strip('"').encode("utf-8", "ignore")
                body += len(data).to_bytes(2, "big") + data
            elif kind == "b":
                body += b"\x01" if value.lower() in ("1", "true", "v") else b"\x00"
            elif kind == "u":
                body += bytes([int(value, 0) & 0xFF])
            else:
                raise ValueError(f"tipo desconocido: {kind}")
        except (ValueError, OverflowError) as exc:
            raise ValueError(f"token invalido: {token}") from exc
    return (2 + len(body)).to_bytes(4, "big") + header.to_bytes(2, "big") + bytes(body)


def _try_xor_byte(data: bytes) -> str:
    """Intenta descifrar con XOR de 1 byte y devuelve texto si parece legible.

    Muchos juegos cifran el trafico saliente con un XOR simple de un byte:
    se prueban las 256 claves y se conserva la que produce mas texto legible.
    """
    best_score = 0.0
    best_text = ""
    for key in range(256):
        plain = bytes(byte ^ key for byte in data)
        printable = sum(
            1 for byte in plain if 32 <= byte < 127 or byte in (9, 10, 13)
        )
        score = printable / max(len(plain), 1)
        if score > best_score:
            best_score = score
            best_text = plain.decode("ascii", "replace").rstrip("\x00")
    if best_score >= 0.85:
        return best_text
    return ""


def _format_unframed_payload(data: bytes) -> str:
    """Formatea un payload sin framing: XOR legible si existe, hex si no."""
    text = _try_xor_byte(data)
    if text:
        return text
    return data.hex(" ")


def _format_binary_token(token) -> str:
    kind, value = token
    if kind == "s":
        return f's:"{value}"'
    if kind == "b":
        return "b:true" if value else "b:false"
    if kind == "u":
        return f"u:0x{value:02x}"
    return f"{kind}:{value}"
