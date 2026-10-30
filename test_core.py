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

# Par de bytes 01 01: deben leerse como dos booleanos, no como h:257
body = bytes([1, 1, 0, 0, 0, 0, 0, 0, 0, 20])
assert parse_binary_tokens(body) == [("b", True), ("b", True), ("i", 0), ("i", 20)], parse_binary_tokens(body)

# Esquema de campos por cabecera (define exactamente los tipos del cuerpo)
from app.capture import PACKET_SCHEMAS

PACKET_SCHEMAS[220] = {
    "name": "UserClub",
    "fields": ["s", "i", "i", "i", "b", "b", "i", "i", "i", "i"],
}
club_body = bytes.fromhex(
    "000a636c75625f686162626f"
    "0000001300000000000000010101"
    "000000000000001400006f2a00003f35"
)
msg = format_binary_message("Recv", 220, club_body)
expected = (
    'Incoming [220 UserClub] s:"club_habbo" i:19 i:0 i:1 b:true b:true '
    "i:0 i:20 i:28458 i:16181"
)
assert msg == expected, msg
PACKET_SCHEMAS.pop(220, None)

# Los enteros se muestran con signo (como G-Earth/xabbo): ff ff ff ff -> i:-1
PACKET_SCHEMAS[9999] = {"name": "ConSigno", "fields": ["i", "l"]}
neg_body = (-1).to_bytes(4, "big", signed=True) + (-2).to_bytes(8, "big", signed=True)
assert (
    format_binary_message("Recv", 9999, neg_body)
    == "Incoming [9999 ConSigno] i:-1 l:-2"
), format_binary_message("Recv", 9999, neg_body)
PACKET_SCHEMAS.pop(9999, None)

# Formato legacy de bytes estilo G-Earth (longitud + header + datos byte a byte)
from app.capture import format_legacy_packet

chat_body = (0).to_bytes(4, "big") + (12).to_bytes(2, "big") + b"Hello, world" + bytes(16)
legacy_expected = "Incoming[1064] -> [0][0][0]$[4]([0][0][0][0][0][12]Hello, world" + "[0]" * 16
assert format_legacy_packet("Recv", 1064, chat_body) == legacy_expected, format_legacy_packet("Recv", 1064, chat_body)

# Ejemplo del foro de Ragezone: 00 00 00 06 06 b4 b3 7d a9 c6
# -> longitud 6, header 1716, entero con signo -1283610170
rage_frame = extract_binary_frames(bytearray(bytes.fromhex("0000000606b4b37da9c6")))
assert rage_frame == [(1716, bytes.fromhex("b37da9c6"))], rage_frame
assert (
    format_binary_message("Recv", 7777, bytes.fromhex("b37da9c6"))
    == "Incoming [7777] i:-1283610170"
), format_binary_message("Recv", 7777, bytes.fromhex("b37da9c6"))
PACKET_SCHEMAS[1716] = {"name": "FurniListRemoveEvent", "fields": ["i"]}
assert (
    format_binary_message("Recv", 1716, rage_frame[0][1])
    == "Incoming [1716 FurniListRemoveEvent] i:-1283610170"
)
PACKET_SCHEMAS.pop(1716, None)
print("binary OK")

# 7. Codificador binario (framing para envio)
message = encode_binary_message('143 s:"hello_world" i:19 b:true u:0xFF')
frames = extract_binary_frames(bytearray(message))
assert frames == [(143, (11).to_bytes(2, "big") + b"hello_world" + (19).to_bytes(4, "big") + b"\x01\xff")]
assert format_binary_message("Send", frames[0][0], frames[0][1]).startswith("Outgoing [143")
long_msg = encode_binary_message("5 l:-7")
assert extract_binary_frames(bytearray(long_msg)) == [(5, (-7).to_bytes(8, "big", signed=True))]
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

# 10. Criptografia desde cero: MD5 + RC4
from app.crypto import RC4State, is_permutation, md5

assert md5(b"").hex() == "d41d8cd98f00b204e9800998ecf8427e"
assert md5(b"abc").hex() == "900150983cd24fb0d6963f7d28e17f72"
state = RC4State.from_key(b"Key")
assert state.crypt(b"Plaintext") == bytes.fromhex("BBF316E8D940AF0AD3")
plain = bytes(range(32)) * 3
key_state = RC4State.from_key(b"Key")
cipher = key_state.crypt(plain)
restored = RC4State.from_key(b"Key")
assert restored.crypt(cipher) == plain
back = RC4State(list(key_state.sbox), key_state.i, key_state.j)
assert back.crypt_backward(cipher[-16:]) == plain[-16:]
assert is_permutation(bytes(range(256)))
assert not is_permutation(bytes(256))

# El descifrado RC4 de la direccion Send se integra en la captura
import scapy.all as sp

from app.capture import NpcapCaptureSource as _NpcapSource

rc4_source = _NpcapSource(
    connection={
        "proto": "tcp",
        "local_ip": "127.0.0.1",
        "local_port": 1,
        "remote_ip": "1.2.3.4",
        "remote_port": 30000,
    }
)
rc4_source.info = dict(rc4_source.connection)
rc4_source.binary_decode = True
rc4_source.set_rc4_state(RC4State.from_key(b"K"))
rc4_emitted = []
rc4_source.emit = rc4_emitted.append
# Ciframos un mensaje con framing y lo enviamos como salida: debe decodificarse
sender = RC4State.from_key(b"K")
framed_send = (6).to_bytes(4, "big") + (2430).to_bytes(2, "big") + (2).to_bytes(4, "big")
encrypted_send = sender.crypt(framed_send)
send_packet = sp.Ether() / sp.IP() / sp.TCP(sport=1234, dport=1, flags="PA") / sp.Raw(load=encrypted_send)
rc4_source._on_packet(send_packet)
assert rc4_emitted and rc4_emitted[0].data == "Outgoing [2430] i:2", rc4_emitted
print("crypto OK")

# 11. Resincronizacion: los bytes descartados se muestran (hex o XOR legible)
#     y el flujo se re-sincroniza con el siguiente mensaje valido.
from app.capture import NpcapCaptureSource as _ResyncSource
from app.capture import _format_unframed_payload

source_resync = _ResyncSource(
    connection={
        "proto": "tcp",
        "local_ip": "127.0.0.1",
        "local_port": 1,
        "remote_ip": "1.2.3.4",
        "remote_port": 30000,
    }
)
source_resync.info = dict(source_resync.connection)
source_resync.binary_decode = True
source_resync._binary_framed["Recv"] = True
resync_emitted = []
source_resync.emit = resync_emitted.append
framed_ok = (6).to_bytes(4, "big") + (2430).to_bytes(2, "big") + (2).to_bytes(4, "big")
garbage = b"\x01\x02\x03"
resync_packet = (
    sp.Ether() / sp.IP() / sp.TCP(sport=30000, dport=1, flags="PA") / sp.Raw(load=garbage + framed_ok)
)
source_resync._on_packet(resync_packet)
assert len(resync_emitted) == 2, resync_emitted
assert resync_emitted[0].data == _format_unframed_payload(garbage), resync_emitted
assert resync_emitted[1].data == "Incoming [2430] i:2", resync_emitted
print("resync OK")

# 12. Alineamiento del estado RC4: el estado en memoria va ADELANTADO por los
#     bytes que el cliente envio entre la ultima captura y la lectura.
from app.capture import _find_alignment

align_key = RC4State.from_key(b"K")
align_frames = framed_ok * 3
align_cipher = align_key.crypt(align_frames)
snapshot = align_key.copy()
snapshot.crypt(b"\x00\x00\x00\x00\x00")  # 5 bytes extra despues del final
# El estado va 35 pasos por delante del inicio del flujo (30 + 5)
shift, score = _find_alignment(
    list(snapshot.sbox), snapshot.i, snapshot.j, align_cipher
)
assert score == 3 and shift == 35, (shift, score)
assert _find_alignment(list(snapshot.sbox), 1, 2, align_cipher) == (None, 0)
print("align OK")

# 13. Crack estilo G-Earth: primeros bytes cifrados + tabla -> (i, j, score)
from app.capture import _crack_table_from_stream_start

crack_key = RC4State.from_key(b"K")
crack_plain = framed_ok * 2
crack_enc = crack_key.crypt(crack_plain)
snap_i, snap_j = crack_key.i, crack_key.j
result = _crack_table_from_stream_start(crack_enc, list(crack_key.sbox))
assert result == (snap_i, snap_j, 2), result
print("crack OK")

# 14. Escaner de celdas int32 (tabla RC4 del cliente Flash, como G-Mem)
from app.processio import scan_rc4_cells_in_chunk

cells = b"".join(bytes([value, 0, 0, 0]) for value in range(256))
chunk = b"\x01\x02\x03\x04" * 100 + cells + b"\x05\x06\x07\x08" * 50
hits = scan_rc4_cells_in_chunk(chunk, 0x1000)
assert hits and hits[0][0] == 0x1000 + 4 * 100, hits
assert hits[0][1] == bytes(range(256)), hits[0][1][:4]
assert scan_rc4_cells_in_chunk(b"\x00" * 2048, 0) == []
print("cells OK")

print("TODAS LAS PRUEBAS OK")
