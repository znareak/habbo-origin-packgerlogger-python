"""Packet Logger - punto de entrada (interfaz grafica).

Uso:
    env\\Scripts\\python.exe packerlogger.py

Si se ejecuta con el Python del sistema, el script se relanza solo con el
Python del entorno virtual (`env`).
"""
import os
import sys

BANNER = r'''
.__          ___.  ___.          .___            __         ____ 
|  |__ _____ \_ |__\_ |__   ____ |   | ____     |__| ___  _/_   |
|  |  \\__  \ | __ \| __ \ /  _ \|   |/    \    |  | \  \/ /|   |
|   Y  \/ __ \| \_\ \ \_\ (  <_> )   |   |  \   |  |  \   / |   |
|___|  (____  /___  /___  /\____/|___|___|  /\__|  |   \_/  |___|
     \/     \/    \/    \/                \/\______|             
>--------------------------------------------->
Version 2.0 - Packet Logger
┌─────────────────────────────────────────────┐
│     Captura Npcap + inyeccion + filtros     │
└─────────────────────────────────────────────┘'''


def _venv_python() -> str | None:
    """Devuelve la ruta del python.exe del entorno virtual si existe."""
    base = os.path.dirname(os.path.abspath(__file__))
    for candidate in (
        os.path.join(base, "env", "Scripts", "python.exe"),
        os.path.join(base, ".venv", "Scripts", "python.exe"),
    ):
        if os.path.isfile(candidate):
            return candidate
    return None


def _relaunch_in_venv() -> None:
    """Si se ejecuta con el Python del sistema, relanza con el del venv.

    Se usa subprocess.run (en vez de os.execv) porque en Windows exec tiene
    semantica de spawn y deja procesos huerfanos con la consola desacoplada.
    """
    if sys.prefix != sys.base_prefix:
        return  # ya se ejecuta dentro de un entorno virtual
    venv_python = _venv_python()
    if not venv_python:
        return
    if os.path.normcase(venv_python) == os.path.normcase(sys.executable):
        return
    print(f"[*] Re-lanzando con el entorno virtual: {venv_python}")
    import subprocess

    try:
        completed = subprocess.run(
            [venv_python, os.path.abspath(__file__), *sys.argv[1:]],
            check=False,
        )
        sys.exit(completed.returncode)
    except OSError as exc:
        print(f"[!] No se pudo re-lanzar ({exc}).")
        print(f"    Ejecuta: {venv_python} {os.path.abspath(__file__)}")
        sys.exit(1)


def main() -> None:
    try:
        print(BANNER)
    except UnicodeEncodeError:
        # Salida redirigida con codificacion antigua (p. ej. cp1252): degradar el banner
        print(BANNER.encode("ascii", "replace").decode("ascii"))
    _relaunch_in_venv()
    try:
        from app.ui import App, run
    except ModuleNotFoundError as exc:
        print(f"[!] Falta dependencia: {exc.name}")
        print("    Instala con: env\\Scripts\\python.exe -m pip install -r requirements.txt")
        sys.exit(1)
    except ImportError as exc:
        print(f"[!] Error de importacion: {exc}")
        sys.exit(1)
    if os.environ.get("PACKETLOGGER_NO_GUI"):
        # Modo comprobacion: verifica que la interfaz se construye y sale
        app = App()
        app.update()
        app.destroy()
        print("[*] Dependencias e interfaz OK (modo comprobacion).")
        return
    try:
        run()
    except Exception as exc:  # noqa: BLE001 - informa al usuario y sale
        print(f"[!] Error al iniciar la interfaz: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()