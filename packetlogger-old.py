import threading
import sys
from scapy.all import *


## Banner
print(r'''
.__          ___.  ___.          .___            __         ____ 
|  |__ _____ \_ |__\_ |__   ____ |   | ____     |__| ___  _/_   |
|  |  \\__  \ | __ \| __ \ /  _ \|   |/    \    |  | \  \/ /|   |
|   Y  \/ __ \| \_\ \ \_\ (  <_> )   |   |  \   |  |  \   / |   |
|___|  (____  /___  /___  /\____/|___|___|  /\__|  |   \_/  |___|
     \/     \/    \/    \/                \/\______|             
>--------------------------------------------->
Version 1.0
                              C0d3d by 303/g0d
┌─────────────────────────────────────────────┐
│        Tos: Only for Habbo origins !    │
├─────────────────────────────────────────────┤
│                 New stuff:                  │
│          [+] Added Packet Handler      │
│          [+] Packet Edition           │
│          [+] Windows Executable         │
├─────────────────────────────────────────────┤
│ twitter: twitter.com/g0dkorp │
└─────────────────────────────────────────────┘''')

def handle_packet(packet):
    summary = packet.summary()
    print(summary)
    save_packet_log(packet)

    # Filtro opcional: resaltar paquetes relacionados con "Item"
    if 'Item' in summary:
        print(f"[ITEM] {summary}")

def get_iface():
    """Devuelve la interfaz a usar según el sistema operativo."""
    if sys.platform.startswith('win'):
        # En Windows se usa la interfaz por defecto de Scapy (requiere Npcap)
        return None
    return 'eth0'

def packet_sniffer():
    iface = get_iface()
    print(f"[+] Connecting to the hotel... (iface: {iface or conf.iface})")
    sniff(prn=handle_packet, iface=iface, filter='tcp', store=False)

def start_sniffer():
    iface = get_iface()
    print(f"[+] Starting Sniffer. Please connect to the hotel... (iface: {iface or conf.iface})")
    sniff(prn=handle_packet, iface=iface, filter='tcp', store=False)

def save_packet_log(packet):
    with open("packet_logs.txt", "a") as log_file:
        log_file.write(f"{packet.summary()}\n")

def threading_logger():
    # Hilo NO demonio: así el proceso permanece vivo capturando paquetes
    threading.Thread(target=start_sniffer).start()

# Call the functions
threading_logger()
print("[+] Threads started !")