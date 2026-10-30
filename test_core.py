"""Pruebas basicas del nucleo (sin GUI ni captura real)."""
import os
import sys
import tempfile
from datetime import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.models import Packet, parse_packet_line
from app.filters import PacketFilter, FilterProfile, ProfileStore
from app.filesource import FilePacketSource

# 1. Parseo del formato de archivo
packet = parse_packet_line("[12:34:56]\t[Recv]\tshop 1 2 3")
assert packet is not None
assert packet.time == time(12, 34, 56)
assert packet.direction == "Recv"
assert packet.data == "shop 1 2 3"
assert parse_packet_line("linea invalida") is None
assert parse_packet_line("[99:99:99]\t[Send]\tx") is None
print("models OK")

# 2. Filtros
filt = PacketFilter(direction="Recv", header="shop")
assert filt.matches(Packet(time(0, 0, 0), "Recv", "shop 1"))
assert not filt.matches(Packet(time(0, 0, 0), "Send", "shop 1"))
profile = FilterProfile(
    name="prueba",
    filters=[PacketFilter(header="buy"), PacketFilter(contains="m_shop")],
)
assert profile.matches(Packet(time(0, 0, 0), "Recv", "buy 1"))
assert profile.matches(Packet(time(0, 0, 0), "Send", "m_shop 9"))
assert not profile.matches(Packet(time(0, 0, 0), "Recv", "walk 1"))
print("filters OK")

# 3. Perfiles: guardar / recargar / eliminar
with tempfile.TemporaryDirectory() as directory:
    store = ProfileStore(directory)
    store.save(profile)
    store2 = ProfileStore(directory)
    assert store2.get("prueba") is not None
    store2.delete("prueba")
    assert store2.get("prueba") is None
print("profiles OK")

# 4. Fuente de archivo
with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as handle:
    handle.write("[10:00:00]\t[Send]\twalk 1\n[10:00:01]\t[Recv]\tat 2 3\nlinea mala\n")
    path = handle.name
try:
    source = FilePacketSource(path)
    assert len(source.packets) == 2
    assert source.invalid_lines == 1
finally:
    os.unlink(path)
print("filesource OK")

# 5. Modulo Win32 importable
import app.processio as processio

assert callable(processio.enumerate_process_handles)
assert callable(processio.enumerate_system_handles)
assert callable(processio.find_process_connections)
assert callable(processio.list_all_processes)
print("processio OK")

# 6. Decodificador binario (framing + parseo heuristico)
from app.capture import (
    encode_binary_message,
    extract_binary_frames,
    format_binary_message,
    parse_binary_tokens,
)

frame = (6).to_bytes(4, "big") + (2430).to_bytes(2, "big") + (2).to_bytes(4, "big")
assert extract_binary_frames(bytearray(frame)) == [(2430, (2).to_bytes(4, "big"))]

split = (14).to_bytes(4, "big") + (10).to_bytes(2, "big") + (3).to_bytes(4, "big") + b"ab123456"
buffer = bytearray(split[:5])
assert extract_binary_frames(buffer) == []
buffer.extend(split[5:])
assert extract_binary_frames(buffer) == [(10, (3).to_bytes(4, "big") + b"ab123456")]

# resincronizacion ante basura inicial
buffer = bytearray((99999999).to_bytes(4, "big") + split)
assert extract_binary_frames(buffer) == [(10, (3).to_bytes(4, "big") + b"ab123456")]

tokens = parse_binary_tokens((2).to_bytes(4, "big") + (5).to_bytes(2, "big") + b"hello")
assert tokens == [("i", 2), ("s", "hello")]
assert format_binary_message("Recv", 2430, (2).to_bytes(4, "big")) == "Incoming [2430] i:2"
print("binary OK")

# 7. Codificador binario (framing para envio)
message = encode_binary_message('143 s:"hello_world" i:19 b:true u:0xFF')
frames = extract_binary_frames(bytearray(message))
assert frames == [(143, (11).to_bytes(2, "big") + b"hello_world" + (19).to_bytes(4, "big") + b"\x01\xff")]
assert format_binary_message("Send", frames[0][0], frames[0][1]).startswith("Outgoing [143]")
print("binary encode OK")

# 8. Inyector: prueba local de extremo a extremo (socket duplicado + send)
import socket
import subprocess
import threading
import time

import psutil

from app.processio import SocketInjector, find_tcp_connections

received = []
accepted = False
ready = threading.Event()
ready_port = []


def serve():
    global accepted
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        ready_port.append(server.getsockname()[1])
        ready.set()
        connection, _ = server.accept()
        accepted = True
        received.append(connection.recv(1024))


thread = threading.Thread(target=serve, daemon=True)
thread.start()
assert ready.wait(5), "el servidor de prueba no arranco"
client_code = (
    "import socket,time;"
    "s=socket.socket();"
    f"s.connect(('127.0.0.1',{ready_port[0]}));"
    "time.sleep(10)"
)
child = subprocess.Popen([sys.executable, "-c", client_code])
time.sleep(1)
try:
    # El python.exe del venv es un lanzador que arranca el interprete real con
    # otro PID: localizar el proceso que posee la conexion por el puerto.
    target_pid = None
    for connection in psutil.net_connections(kind="tcp"):
        if (
            connection.status == psutil.CONN_ESTABLISHED
            and connection.raddr
            and connection.raddr.port == ready_port[0]
            and connection.pid
        ):
            target_pid = connection.pid
            break
    assert target_pid, "no se encontro la conexion del cliente de prueba"
    process = psutil.Process(target_pid)
    connections = find_tcp_connections(process)
    print("conexiones vistas por psutil:", connections)
    injector = SocketInjector(process)
    assert injector.connect(ports=(ready_port[0],)), "no se pudo conectar al cliente de prueba"
    sent = injector.send("Send", "hola servidor")
    assert sent == len(b"hola servidor"), sent
    thread.join(5)
    assert received and received[0] == b"hola servidor", received
    injector.close()
finally:
    child.terminate()
print("inyector local OK")

# 9. Decodificacion binaria: fallback a hex para flujos sin framing
from app.capture import NpcapCaptureSource

try:
    import scapy.all as sp

    source = NpcapCaptureSource(
        connection={
            "proto": "tcp",
            "local_ip": "127.0.0.1",
            "local_port": 1,
            "remote_ip": "1.2.3.4",
            "remote_port": 30000,
        }
    )
    source.info = dict(source.connection)
    source.binary_decode = True
    emitted = []
    source.emit = emitted.append

    # Saliente sin framing (bytes cortos): debe mostrarse en hex, no descartarse
    raw = bytes.fromhex("1a 81 7a fa 06 ab")
    packet = sp.Ether() / sp.IP() / sp.TCP(sport=1234, dport=1) / sp.Raw(load=raw)
    source._on_packet(packet)
    assert emitted and emitted[0].data == raw.hex(" "), emitted
    emitted.clear()

    # Entrante con framing: debe decodificarse
    framed = (6).to_bytes(4, "big") + (2430).to_bytes(2, "big") + (2).to_bytes(4, "big")
    packet = sp.Ether() / sp.IP() / sp.TCP(sport=30000, dport=1) / sp.Raw(load=framed)
    source._on_packet(packet)
    assert emitted and emitted[0].data == "Incoming [2430] i:2", emitted
    print("binary fallback OK")
except ImportError:
    print("binary fallback OK (sin scapy, omitido)")

print("TODAS LAS PRUEBAS OK")
