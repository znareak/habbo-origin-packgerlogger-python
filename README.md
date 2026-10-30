# Packet Logger

Herramienta para capturar, filtrar e inyectar paquetes de red de cualquier
proceso en ejecucion (uso educativo), en Python.

## Funcionalidades

- **Filtrado de archivos de paquetes** con el formato
  `[{hh:mm:ss}]\t[{Recv|Send}]\t{packet}` (una linea por paquete).
- **Captura con Npcap del trafico TCP/UDP de cualquier proceso** en ejecucion:
  se elige el proceso y una de sus conexiones, se localiza la interfaz Npcap
  adecuada y se muestran los paquetes como texto si son legibles o en hex si no.
- **Inyeccion en un proceso en ejecucion**: se duplica el socket TCP del
  proceso (DuplicateHandle) y se envian paquetes como si los enviara el
  cliente (`Send`) o el servidor (`Recv`). Puede no funcionar con procesos
  protegidos.
- **Perfiles de filtros** guardados como JSON en `profiles/` y cargados
  automaticamente al arrancar.
- **Decodificador binario opcional**: con el checkbox "Decodificar" de una
  pestaña de captura TCP se reensamblan los mensajes del protocolo binario
  (`longitud int32 + header int16 + cuerpo`) y se decodifican los campos
  (cadenas, enteros, booleanos) de forma heuristica.
- **Multiples fuentes simultaneas** en pestañas: click derecho sobre el titulo
  de una pestaña para **Flotar**, **Dividir** o **Cerrar**.
- **Envio de paquetes una vez o periodicamente** (intervalo configurable),
  ademas de reproduccion de archivos completos en bucle.

## Instalacion

1. Instalar [Npcap](https://npcap.com/) (modo WinPcap API compatible).
2. Dependencias Python:

   ```
   env\Scripts\python.exe -m pip install -r requirements.txt
   ```

## Ejecucion

```
python packerlogger.py
```

El script se relanza automaticamente con el Python del entorno virtual
(`env`) si lo ejecutas con el Python del sistema. Tambien puedes lanzarlo
directamente con:

```
env\Scripts\python.exe packerlogger.py
```

Ejecutar como **Administrador** para capturar con Npcap e inyectar en procesos.

## Uso basico

1. Menu **Fuentes → Captura Npcap (cualquier proceso)**.
2. Elige el proceso, una de sus conexiones TCP/UDP y pulsa **Crear** + **Iniciar**.
3. Menu **Inyectores → Nuevo inyector** para poder enviar paquetes a un proceso.
4. En el panel inferior de cada pestaña escribe un paquete, elige direccion e
   intervalo y pulsa **Enviar una vez** o **Iniciar periodico**.
5. Para archivos: **Fuentes → Archivo de paquetes** y usa el panel
   **Reproducir archivo** para reenviarlos una vez o en bucle.

## Analizar cualquier programa

1. Ejecuta el logger como **Administrador** y abre el programa que quieras analizar.
2. Menu **Fuentes → Captura Npcap (cualquier proceso)**.
3. Elige el **proceso** en la lista (o pulsa Actualizar), selecciona una de sus
   **conexiones TCP/UDP** (la lista se rellena sola al elegir proceso) y deja
   **Sin descifrar**.
4. Pulsa **Crear** y luego **Iniciar**. Los paquetes apa y selecciona una de sus
   **conexiones TCP/UDP** (la lista se rellena sola al elegir proceso)
   Consejos:

- Si el programa usa TLS (navegadores, HTTPS) solo se veran los bytes cifrados;
  no se pueden descifrar.
- Para inyectar en ese programa: **Inyectores → Nuevo inyector**, elige el
  proceso y su conexion TCP y pulsa Conectar. Solo funciona con TCP.

## Perfiles de filtros

Se guardan en `profiles/*.json` y se cargan al inicio:

```json
{
  "name": "Ejemplo HTTP",
  "filters": [{ "direction": "Recv", "header": "HTTP/", "contains": "", "regex": "" }]
}
```

Un perfil coincide si **alguno** de sus filtros coincide; la barra de filtros
rapidos de cada pestaña se combina con el perfil seleccionado.

## Limitaciones conocidas

- El trafico cifrado (TLS/HTTPS) solo se muestra en hex.
- Para capturar conexiones nuevas del proceso hay que reiniciar la captura.
- La inyeccion requiere permisos de Administrador y solo funciona con TCP.

## Siguientes pasos (hoja de ruta)

- Inyeccion UDP (sendto al extremo destino).
- Entrada en hex para inyectar binario y exportar la captura a archivo.
