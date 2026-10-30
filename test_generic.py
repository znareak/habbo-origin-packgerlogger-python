"""Prueba de las funciones genericas: procesos y conexiones TCP/UDP reales."""
import sys

from app.processio import find_process_connections, list_all_processes
from app.capture import decode_payload

processes = list_all_processes()
print(f"procesos visibles: {len(processes)}")

with_connections = 0
examples = []
for proc in processes:
    try:
        connections = find_process_connections(proc)
    except Exception:
        continue
    if connections:
        with_connections += 1
        if len(examples) < 5:
            examples.append((proc.info.get("name", "?"), connections))

print(f"procesos con conexiones TCP/UDP: {with_connections}")
for name, connections in examples:
    first = connections[0]
    remote = first.get("remote_ip") or "(sin destino)"
    print(
        f" - {name}: {len(connections)} conexiones | ejemplo: {first['proto'].upper()} "
        f"{first.get('local_ip')}:{first.get('local_port')} <-> {remote}:{first.get('remote_port', '?')}"
    )

assert repr(decode_payload(b"GET / HTTP/1.1\r\n")) == "'GET / HTTP/1.1'"
assert decode_payload(bytes([0, 1, 2, 255, 254])) == "00 01 02 ff fe"
print("decode_payload OK")
print("PRUEBA GENERICA OK")
