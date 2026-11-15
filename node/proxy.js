const net = require("net");
const readline = require("readline");
const { Worker } = require("worker_threads");
const { RC4State } = require("./rc4.js");

// Ruta absoluta de memscan.js para que el worker la cargue desde cualquier CWD.
const MEMSCAN_PATH = require.resolve("./memscan.js");

// ==========================================
// CONFIGURACIÓN LOCAL
// ==========================================
const LOCAL_PORT = 9000; // El puerto donde escuchará tu proxy local

// PID del cliente del juego (Flash/AIR) para leer su tabla RC4 de la memoria.
// Uso:  node proxy.js <PID>
// Si no se pasa, se usará el PID del propio proceso (solo para pruebas).
const GAME_PID = Number(process.argv[2]) || process.pid;

let activeServerToken = null; // Conexión activa del juego (puerto 30000)
let activeSendState = null; // RC4State descifrado de la dirección Send (para inyectar)

// Diagnóstico: no dejar que una excepción mate el proxy en silencio
process.on("uncaughtException", (err) => {
  console.error(`[FATAL] Excepción no capturada:`, err);
});
process.on("unhandledRejection", (err) => {
  console.error(`[FATAL] Promesa rechazada:`, err);
});

// ==========================================
// Framing del protocolo: [int32 BE len][int16 BE header][body]
//   len incluye header (2) + body. El RC4 cifra TODO el flujo, incluido el framing.
// ==========================================
const MAX_LEN = 0x7fffffff;
const HEX = /^[0-9a-f]+$/i;

function isHexString(s) {
  return HEX.test(s) && s.length >= 100; // valores DH de 256 bytes (512 chars hex)
}

function parseStrings(body) {
  const strings = [];
  let off = 0;
  while (off < body.length) {
    if (off + 2 > body.length) return null;
    const n = body.readUInt16BE(off);
    off += 2;
    if (off + n > body.length) return null;
    strings.push(body.slice(off, off + n).toString("utf8"));
    off += n;
  }
  return strings;
}

function buildFrame(header, body) {
  const out = Buffer.alloc(6 + body.length);
  out.writeInt32BE(2 + body.length, 0);
  out.writeUInt16BE(header, 4);
  body.copy(out, 6);
  return out;
}

// Detección por estructura (los IDs exactos varían por versión):
// InitDiffieHandshake     = 2 cadenas hex  — servidor -> cliente
// CompleteDiffieHandshake = 1 cadena hex   — cliente -> servidor
// ServerPub               = 1 cadena hex   — servidor -> cliente
function isInitDiffieHandshake(body) {
  const s = parseStrings(body);
  return s && s.length === 2 && s.every(isHexString);
}
function isSingleHexString(body) {
  const s = parseStrings(body);
  return s && s.length === 1 && isHexString(s[0]);
}

// ==========================================
// Formato / log
// ==========================================
function hexOf(buf) {
  return buf.toString("hex").match(/../g).join(" ");
}

function logFrame(dir, header, body) {
  let ascii = "";
  if (
    body.length > 0 &&
    body.every((b) => (b >= 0x20 && b < 0x7f) || b === 0x09 || b === 0x0a || b === 0x0d)
  ) {
    ascii = `  "${body.toString("utf8")}"`;
  }
  console.log(`[${dir}] [Header: ${header}] [Len: ${body.length}] ${hexOf(body)}${ascii}`);
}

// ==========================================
// INTERFAZ DE LÍNEA DE COMANDOS (INYECCIÓN)
// ==========================================
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

console.log(`[*] Proxy SOCKS5 (Netch) con descifrado RC4 por RAM (G-Earth).`);
console.log(
  `[*] PID del cliente del juego: ${GAME_PID}${Number(process.argv[2]) ? "" : " (pruebas)"}`,
);
console.log(`[*] Inyecta un FRAME completo (longitud+header+cuerpo) en hex; se cifra solo.\n`);

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

  let packet = Buffer.from(cleanHex, "hex");
  if (activeSendState) {
    packet = activeSendState.crypt(packet); // cifra con el flujo Send actual
    console.log(`[INJECT -> SERVER] (cifrado RC4) ${hexOf(packet)}`);
  } else {
    console.log(`[!] Aún no se ha crackeado el RC4 Send; se inyecta en claro (fallará).`);
    console.log(`[INJECT -> SERVER] (en claro) ${hexOf(packet)}`);
  }
  activeServerToken.write(packet);
});

// ==========================================
// LÓGICA DEL SERVIDOR PROXY (SOCKS5 + PASS-THROUGH + CRACK DE RAM)
// ==========================================
const server = net.createServer((clientSocket) => {
  let serverSocket = null;
  let socksState = 0; // 0 = Saludo, 1 = Petición de conexión, 2 = Tráfico de la aplicación
  let targetPort = 0;

  const conn = {
    phase: "handshake", // "handshake" | "crypto"
    hs: "init", // sub-estado: "init" | "clientPub" | "serverPub"
    bufC: Buffer.alloc(0), // pendiente client->server (plano durante handshake)
    bufS: Buffer.alloc(0), // pendiente server->client
    sendEnc: Buffer.alloc(0), // primeros bytes cifrados client->server (para crackear)
    sendState: null, // RC4State descifrado (Send) — estado al FINAL de sendEnc
    plainC: Buffer.alloc(0), // acumulador plano descifrado (client->server) para log
    cracking: false,
  };

  function logPlainFrames(dir, plain, accum) {
    let buf = Buffer.concat([accum, plain]);
    while (buf.length >= 4) {
      const len = buf.readInt32BE(0);
      if (len < 2 || len > MAX_LEN) {
        buf = buf.slice(1);
        continue;
      }
      if (buf.length < 4 + len) break;
      const header = buf.readUInt16BE(4);
      const body = buf.slice(6, 4 + len);
      logFrame(dir, header, body);
      buf = buf.slice(4 + len);
    }
    return buf;
  }

  function tryCrackSend() {
    if (conn.cracking || conn.sendState) return;
    if (conn.sendEnc.length < 8) return;
    conn.cracking = true;
    console.log(`[RC4] Crackeando estado Send (${conn.sendEnc.length} bytes cifrados)...`);

    const worker = new Worker(
      `
      const { parentPort, workerData } = require("worker_threads");
      const { findRc4State } = require(workerData.memscanPath);
      try {
        const result = findRc4State(workerData.pid, Buffer.from(workerData.enc));
        parentPort.postMessage({ ok: true, result });
      } catch (e) {
        parentPort.postMessage({ ok: false, error: e.message });
      }
      `,
      { eval: true, workerData: { pid: GAME_PID, enc: conn.sendEnc, memscanPath: MEMSCAN_PATH } },
    );

    worker.on("message", (msg) => {
      conn.cracking = false;
      if (msg.ok) {
        const { sbox, i, j, score } = msg.result;
        // Estado al FINAL del sendEnc (para descifrar bytes posteriores)
        const endState = new RC4State(sbox, i, j);
        // Deshacer al inicio para descifrar los bytes ya capturados (sendEnc)
        const initState = endState.copy();
        for (let k = 0; k < conn.sendEnc.length; k++) initState.stepBack();
        const plain = initState.crypt(conn.sendEnc);
        conn.plainC = logPlainFrames("CLIENT -> SERVER", plain, conn.plainC);
        conn.sendState = endState;
        activeSendState = endState;
        console.log(`[RC4] ¡Estado Send crackeado! (i=${i}, j=${j}, score=${score}).`);
      } else {
        console.log(`[RC4] Crack falló: ${msg.error}. Reconecta el juego con la captura activa.`);
      }
      worker.terminate();
    });

    worker.on("error", (err) => {
      conn.cracking = false;
      console.log(`[RC4] Error del worker: ${err.message}`);
    });
  }

  function processClientAppData(data) {
    if (conn.phase === "handshake") console.log(`[DEBUG C->S] ${hexOf(data)}`);
    conn.bufC = Buffer.concat([conn.bufC, data]);
    while (conn.bufC.length > 0) {
      if (conn.phase === "handshake") {
        if (conn.bufC.length < 4) break;
        const len = conn.bufC.readInt32BE(0);
        if (len < 2 || len > MAX_LEN) {
          conn.bufC = conn.bufC.slice(1);
          continue;
        }
        if (conn.bufC.length < 4 + len) break;
        const header = conn.bufC.readUInt16BE(4);
        const body = conn.bufC.slice(6, 4 + len);
        conn.bufC = conn.bufC.slice(4 + len);
        if (conn.hs === "clientPub" && isSingleHexString(body)) {
          conn.hs = "serverPub";
          console.log(`[RC4] CompleteDiffieHandshake detectado (header ${header}).`);
        }
        // pass-through: reenviamos el frame tal cual
        serverSocket.write(buildFrame(header, body));
      } else {
        // crypto
        const chunk = conn.bufC;
        conn.bufC = Buffer.alloc(0);
        if (conn.sendState) {
          const plain = conn.sendState.crypt(chunk);
          conn.plainC = logPlainFrames("CLIENT -> SERVER", plain, conn.plainC);
        } else {
          conn.sendEnc = Buffer.concat([conn.sendEnc, chunk]);
          tryCrackSend();
        }
        serverSocket.write(chunk); // reenvía los bytes cifrados originales
      }
    }
  }

  function processServerAppData(data) {
    if (conn.phase === "handshake") console.log(`[DEBUG S->C] ${hexOf(data)}`);
    conn.bufS = Buffer.concat([conn.bufS, data]);
    while (conn.bufS.length > 0) {
      if (conn.phase === "handshake") {
        if (conn.bufS.length < 4) break;
        const len = conn.bufS.readInt32BE(0);
        if (len < 2 || len > MAX_LEN) {
          conn.bufS = conn.bufS.slice(1);
          continue;
        }
        if (conn.bufS.length < 4 + len) break;
        const header = conn.bufS.readUInt16BE(4);
        const body = conn.bufS.slice(6, 4 + len);
        conn.bufS = conn.bufS.slice(4 + len);
        if (conn.hs === "init" && isInitDiffieHandshake(body)) {
          conn.hs = "clientPub";
          console.log(`[RC4] InitDiffieHandshake detectado (header ${header}).`);
        } else if (conn.hs === "serverPub") {
          // El ServerPub tiene un byte extra al final (no es exactamente 1 cadena hex),
          // así que en este estado CUALQUIER frame del servidor marca el inicio del cifrado.
          conn.phase = "crypto";
          console.log(`[RC4] Handshake detectado (ServerPub, header ${header}): RC4 activo.`);
        }
        // pass-through: reenviamos el frame tal cual
        clientSocket.write(buildFrame(header, body));
      } else {
        // crypto: por ahora la dirección server->client se reenvía cifrada (sin descifrar)
        const chunk = conn.bufS;
        conn.bufS = Buffer.alloc(0);
        clientSocket.write(chunk);
      }
    }
  }

  clientSocket.on("data", (data) => {
    // --- FASE 1: SALUDO SOCKS5 ---
    if (socksState === 0) {
      if (data[0] === 0x05) {
        clientSocket.write(Buffer.from([0x05, 0x00]));
        socksState = 1;
      }
      return;
    }

    // --- FASE 2: PETICIÓN DE CONEXIÓN SOCKS5 ---
    if (socksState === 1) {
      if (data.length >= 10 && data[0] === 0x05 && data[1] === 0x01) {
        let targetIP = "";

        if (data[3] === 0x01) {
          targetIP = `${data[4]}.${data[5]}.${data[6]}.${data[7]}`;
          targetPort = data.readUInt16BE(8);
        } else if (data[3] === 0x03) {
          const domainLen = data[4];
          targetIP = data.slice(5, 5 + domainLen).toString("utf8");
          targetPort = data.readUInt16BE(5 + domainLen);
        } else {
          clientSocket.destroy();
          return;
        }

        if (targetPort === 30000) {
          console.log(`\n[+] Netch solicita túnel hacia el juego: ${targetIP}:${targetPort}...`);
        }

        serverSocket = new net.Socket();
        serverSocket.connect(targetPort, targetIP, () => {
          if (targetPort === 30000) {
            console.log(`[+] ¡Túnel establecido con el destino real!`);
            activeServerToken = serverSocket;
            console.log(`[!] A la espera del handshake Diffie-Hellman...`);
          }

          const successReply = Buffer.from([
            0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          ]);
          clientSocket.write(successReply);

          socksState = 2;
        });

        serverSocket.on("data", (serverData) => {
          if (targetPort === 30000) {
            processServerAppData(serverData);
          } else if (!clientSocket.destroyed) {
            clientSocket.write(serverData);
          }
        });

        serverSocket.on("close", () => {
          if (targetPort === 30000) {
            console.log(`[-] Servidor del juego desconectado.`);
            activeServerToken = null;
            activeSendState = null;
          }
          if (!clientSocket.destroyed) clientSocket.destroy();
        });

        serverSocket.on("error", (err) => {
          if (targetPort === 30000) console.log(`[ERR SERVIDOR] ${err.message}`);
        });
      }
      return;
    }

    // --- FASE 3: TRÁFICO REAL ---
    if (socksState === 2) {
      if (targetPort === 30000) {
        processClientAppData(data);
      } else if (serverSocket && !serverSocket.destroyed) {
        serverSocket.write(data);
      }
    }
  });

  clientSocket.on("close", () => {
    if (socksState === 2 && targetPort === 30000) {
      console.log(`[-] Netch/Cliente desconectado.`);
    }
    if (serverSocket && !serverSocket.destroyed) serverSocket.destroy();
  });

  clientSocket.on("error", () => {
    // Errores locales ignorados silenciosamente para no manchar la consola
  });
});

server.listen(LOCAL_PORT, () => {
  console.log(`[+] Proxy SOCKS5 escuchando en 127.0.0.1:${LOCAL_PORT}`);
  console.log(`[!] Enciende Netch y entra al juego.`);
});
