# node-packetlogger (CLI interactiva, solo Node.js)

Detector de paquetes **Send/Recv** en Node.js, versión resumida del Packet
Logger de Python: solo captura, sin inyección ni descifrado.

**No usa Python, no usa Npcap y no necesita ficheros auxiliares**: la captura
la hace un sniffer PowerShell embebido en `index.js` con raw sockets de
Windows (SIO_RCVALL). Solo requiere ejecutar como **administrador** (al
arrancar se pide elevación automáticamente con UAC). Si el módulo nativo
`cap` está instalado, se usa ese en su lugar.

## Uso normal (menú interactivo)

```powershell
cd node
node index.js
```

1. Muestra todos los **procesos** con conexiones activas (nombre, PID y
   número de conexiones), obtenidos con `netstat` + `tasklist` (sin módulos
   nativos).
2. Te mueves con **↑ / ↓**, eliges con **Enter** y sales con **q**.
3. Luego muestra las **conexiones** de ese proceso:
   `TCP  192.168.1.12:50939  <->  3.33.177.124:30000`
4. Al elegir una, empieza la captura de esa IP:puerto:

```
[20:48:08]	[Send]	hola
[20:48:08]	[Recv]	hola
```

`Ctrl+C` detiene la captura. Si el terminal no soporta flechas (o la entrada
está redirigida), se muestra automáticamente una **lista numerada**.

## Uso directo (sin menú)

```powershell
node index.js HOST PUERTO [tcp|udp]
```

## Notas

- La captura con raw socket no ve el tráfico de **loopback** (127.0.0.1);
  para conexiones normales (juegos a servidores remotos) funciona sin problema.
- Solo hay un fichero: `index.js` (el menú, la enumeración y el sniffer van
  dentro). `package.json` no declara dependencias; no hace falta
  `npm install`.
