const net = require("net");
const readline = require("readline");

// ==========================================
// CONFIGURACIÓN LOCAL
// ==========================================
const LOCAL_PORT = 9000; // El puerto donde escuchará tu proxy local

let activeServerToken = null; // Guardará la conexión activa del juego (puerto 30000)

// ==========================================
// INTERFAZ DE LÍNEA DE COMANDOS (INYECCIÓN)
// ==========================================
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

console.log(`[*] Iniciando Proxy TCP Dinámico con soporte SOCKS5 (Netch)...`);
console.log(`[*] Escribe paquetes en formato Hexadecimal para inyectar al servidor.\n`);

rl.on("line", (input) => {
  if (!activeServerToken || activeServerToken.destroyed) {
    console.log(`[-] No hay túnel activo con el servidor del juego (puerto 30000) para inyectar.`);
    return;
  }

  const cleanHex = input.replace(/\s+/g, "");
  if (!/^[0-9a-fA-F]+$/.test(cleanHex) || cleanHex.length % 2 !== 0) {
    console.log(`[!] Formato inválido. Usa pares, ej: 0A 1B 2C`);
    return;
  }

  const packet = Buffer.from(cleanHex, "hex");
  activeServerToken.write(packet);
  console.log(`[INJECT -> SERVER] ${packet.toString("hex").match(/../g).join(" ")}`);
});

// ==========================================
// LÓGICA DEL SERVIDOR PROXY (MANEJADOR SOCKS5)
// ==========================================
const server = net.createServer((clientSocket) => {
  let serverSocket = null;
  let socksState = 0; // 0 = Saludo, 1 = Petición de conexión, 2 = Tráfico de la aplicación
  let targetPort = 0; // Guardará el puerto final para filtrar los logs

  clientSocket.on("data", (data) => {
    // --- FASE 1: SALUDO SOCKS5 ---
    if (socksState === 0) {
      if (data[0] === 0x05) {
        // Responder: "SOCKS5 aceptado, no requiere contraseña" (05 00)
        clientSocket.write(Buffer.from([0x05, 0x00]));
        socksState = 1;
      }
      return;
    }

    // --- FASE 2: PETICIÓN DE CONEXIÓN SOCKS5 ---
    if (socksState === 1) {
      if (data.length >= 10 && data[0] === 0x05 && data[1] === 0x01) {
        let targetIP = "";

        // Determinar el tipo de dirección solicitada por Netch
        if (data[3] === 0x01) {
          // Es una IPv4
          targetIP = `${data[4]}.${data[5]}.${data[6]}.${data[7]}`;
          targetPort = data.readUInt16BE(8);
        } else if (data[3] === 0x03) {
          // Es un nombre de dominio
          const domainLen = data[4];
          targetIP = data.slice(5, 5 + domainLen).toString("utf8");
          targetPort = data.readUInt16BE(5 + domainLen);
        } else {
          clientSocket.destroy();
          return;
        }

        // Solo avisar si se está conectando al servidor principal del juego
        if (targetPort === 30000) {
          console.log(`\n[+] Netch solicita túnel hacia el juego: ${targetIP}:${targetPort}...`);
        }

        // Conectar dinámicamente al destino solicitado
        serverSocket = new net.Socket();
        serverSocket.connect(targetPort, targetIP, () => {
          if (targetPort === 30000) {
            console.log(`[+] ¡Túnel establecido con el destino real!`);
            activeServerToken = serverSocket; // Guardamos la sesión para inyectar
            console.log(`[!] LISTO PARA INYECTAR PAQUETES.`);
          }

          // Responder a Netch: "Conexión exitosa, envía los datos"
          const successReply = Buffer.from([
            0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          ]);
          clientSocket.write(successReply);

          socksState = 2; // Pasar a fase de tráfico puro
        });

        // Manejar los datos que devuelve el servidor remoto
        serverSocket.on("data", (serverData) => {
          // Solo imprimimos en consola si es el juego (no nos interesa el HTTP basura)
          if (targetPort === 30000) {
            const hex = serverData.toString("hex").match(/../g).join(" ");
            console.log(`[SERVER -> CLIENT] [Len: ${serverData.length}] ${hex}`);
          }
          if (!clientSocket.destroyed) clientSocket.write(serverData);
        });

        // Cierres de conexión remota
        serverSocket.on("close", () => {
          if (targetPort === 30000) {
            console.log(`[-] Servidor del juego desconectado.`);
            activeServerToken = null;
          }
          if (!clientSocket.destroyed) clientSocket.destroy();
        });

        serverSocket.on("error", (err) => {
          if (targetPort === 30000) console.log(`[ERR SERVIDOR] ${err.message}`);
        });
      }
      return;
    }

    // --- FASE 3: TRÁFICO REAL (PUENTE) ---
    if (socksState === 2) {
      // Solo imprimimos lo que envía el cliente si va al puerto del juego
      if (targetPort === 30000) {
        const hex = data.toString("hex").match(/../g).join(" ");
        console.log(`[CLIENT -> SERVER] [Len: ${data.length}] ${hex}`);
      }

      // Reenviamos los bytes crudos al destino
      if (serverSocket && !serverSocket.destroyed) {
        serverSocket.write(data);
      }
    }
  });

  // Cierre de la conexión local
  clientSocket.on("close", () => {
    if (socksState === 2 && targetPort === 30000) {
      console.log(`[-] Netch/Cliente desconectado.`);
    }
    if (serverSocket && !serverSocket.destroyed) serverSocket.destroy();
  });

  clientSocket.on("error", (err) => {
    // Errores locales ignorados silenciosamente para no manchar la consola
  });
});

// Iniciar el proxy
server.listen(LOCAL_PORT, () => {
  console.log(`[+] Proxy SOCKS5 escuchando en 127.0.0.1:${LOCAL_PORT}`);
  console.log(`[!] Enciende Netch y entra al juego.`);
});
