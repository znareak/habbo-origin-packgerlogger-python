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

# 6. Decodificador Habbo (framing + parseo heuristico)
from app.capture import (
    extract_habbo_frames,
    format_habbo_message,
    parse_habbo_tokens,
)

frame = (6).to_bytes(4, "big") + (2430).to_bytes(2, "big") + (2).to_bytes(4, "big")
assert extract_habbo_frames(bytearray(frame)) == [(2430, (2).to_bytes(4, "big"))]

split = (14).to_bytes(4, "big") + (10).to_bytes(2, "big") + (3).to_bytes(4, "big") + b"ab123456"
buffer = bytearray(split[:5])
assert extract_habbo_frames(buffer) == []
buffer.extend(split[5:])
assert extract_habbo_frames(buffer) == [(10, (3).to_bytes(4, "big") + b"ab123456")]

# resincronizacion ante basura inicial
buffer = bytearray((99999999).to_bytes(4, "big") + split)
assert extract_habbo_frames(buffer) == [(10, (3).to_bytes(4, "big") + b"ab123456")]

tokens = parse_habbo_tokens((2).to_bytes(4, "big") + (5).to_bytes(2, "big") + b"habbo")
assert tokens == [("i", 2), ("s", "habbo")]
assert format_habbo_message("Recv", 2430, (2).to_bytes(4, "big")) == "Incoming [2430] i:2"
print("habbo OK")

print("TODAS LAS PRUEBAS OK")
