const { execFileSync } = require("child_process");
const readline = require("readline");
const dgram = require("dgram");
const net = require("net");

const CLEAR = "\x1b[2J\x1b[0;0H";

// ---------- Enumeración de procesos y conexiones (Idéntica al Logger) ---

function parseAddress(text) {
  if (!text) return null;
  if (text === "*:*") return { ip: "*", port: 0 };

  const match = text.match(/^\[?([^\]]+)\]?:(\d+)$/);
  if (!match) return null;

  const ip = match[1];
  const port = parseInt(match[2], 10);
  return port > 0 ? { ip, port } : null;
}

function runCommand(command, args) {
  try {
    return execFileSync(command, args, {
      encoding: "latin1",
      maxBuffer: 16 * 1024 * 1024,
      windowsHide: true,
    });
  } catch {
    return "";
  }
}

function loadConnections() {
  const netstatOutput = runCommand("netstat", ["-ano"]);
  const tasklistOutput = runCommand("tasklist", ["/FO", "CSV", "/NH"]);

  const processNames = new Map();
  for (const line of tasklistOutput.split(/\r?\n/)) {
    const match = line.match(/^"([^"]+)",\s*"(\d+)"/);
    if (match) {
      processNames.set(parseInt(match[2], 10), match[1]);
    }
  }

  const seen = new Set();
  const connections = [];

  for (const line of netstatOutput.split(/\r?\n/)) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 4) continue;

    const proto = parts[0].toUpperCase();
    if (proto !== "TCP" && proto !== "UDP") continue;
    if (proto === "TCP" && parts[3] !== "ESTABLISHED") continue;

    const local = parseAddress(parts[1]);
    const remote = parseAddress(parts[2]);
    const pid = parseInt(proto === "TCP" ? parts[4] : parts[3], 10);

    if (!local || !remote || !pid) continue;
    if (proto === "TCP" && remote.port === 0) continue;
    if (proto === "UDP" && (local.ip.includes(":") || local.port === 0)) continue;

    const name = processNames.get(pid) || `(pid ${pid})`;
    const uniqueKey = `${name}|${proto}|${local.port}|${remote.ip}:${remote.port}`;

    if (!seen.has(uniqueKey)) {
      seen.add(uniqueKey);
      connections.push({
        proto: proto.toLowerCase(),
        pid,
        name,
        localIp: local.ip === "0.0.0.0" ? "" : local.ip,
        localPort: local.port,
        remoteIp: remote.ip,
        remotePort: remote.port,
      });
    }
  }

  return connections.sort((a, b) => a.name.localeCompare(b.name) || a.localPort - b.localPort);
}

function groupByProcess(connections) {
  const groups = new Map();

  for (const conn of connections) {
    const key = `${conn.name}|${conn.pid}`;
    if (!groups.has(key)) {
      groups.set(key, { name: conn.name, pid: conn.pid, connections: [] });
    }
    groups.get(key).connections.push(conn);
  }

  return [...groups.values()].sort((a, b) => a.name.localeCompare(b.name));
}

// ---------- Menú interactivo con teclado (Flechas) ------------------------

function numberedMenu(title, entries, renderItem) {
  return new Promise((resolve) => {
    console.log(CLEAR + title);
    entries.forEach((entry, i) => {
      console.log(` ${String(i + 1).padStart(2)}. ${renderItem(entry)}`);
    });

    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    const askQuestion = () => {
      rl.question("\nElige un numero (q = salir): ", (answer) => {
        const input = answer.trim().toLowerCase();
        if (!input || input === "q") {
          rl.close();
          return resolve(null);
        }

        const index = parseInt(input, 10) - 1;
        if (index >= 0 && index < entries.length) {
          rl.close();
          return resolve(entries[index]);
        }

        askQuestion();
      });
    };

    askQuestion();
  });
}

function rawMenu(title, entries, renderItem) {
  return new Promise((resolve) => {
    let selectedIndex = 0;

    readline.emitKeypressEvents(process.stdin);
    process.stdin.setRawMode(true);
    process.stdin.resume();

    const drawMenu = () => {
      const terminalRows = process.stdout.rows || 24;
      const pageSize = Math.max(3, terminalRows - 5);
      const halfPage = Math.floor(pageSize / 2);
      const maxStart = Math.max(0, entries.length - pageSize);
      const start = Math.min(Math.max(0, selectedIndex - halfPage), maxStart);

      const visibleEntries = entries.slice(start, start + pageSize);
      const lines = visibleEntries.map((entry, idx) => {
        const isSelected = start + idx === selectedIndex;
        const text = renderItem(entry);
        return isSelected ? `\x1b[7m> ${text}\x1b[0m\x1b[K` : `  ${text}\x1b[K`;
      });

      const footer = "\n\x1b[K↑/↓ mover | Enter elegir | q salir";
      process.stdout.write(`${CLEAR}${title}\n${lines.join("\n")}\n${footer}`);
    };

    const finish = (result) => {
      process.stdin.removeListener("keypress", onKeypress);
      resolve(result);
    };

    const onKeypress = (_, key = {}) => {
      if (key.ctrl && key.name === "c") process.exit(0);

      switch (key.name) {
        case "up":
          selectedIndex = Math.max(0, selectedIndex - 1);
          drawMenu();
          break;
        case "down":
          selectedIndex = Math.min(entries.length - 1, selectedIndex + 1);
          drawMenu();
          break;
        case "return":
        case "enter":
          finish(entries[selectedIndex]);
          break;
        case "q":
        case "escape":
          finish(null);
          break;
      }
    };

    process.stdin.on("keypress", onKeypress);
    drawMenu();
  });
}

function menu(title, entries, renderItem) {
  if (process.stdin.isTTY) {
    return rawMenu(title, entries, renderItem).catch(() =>
      numberedMenu(title, entries, renderItem),
    );
  }
  return numberedMenu(title, entries, renderItem);
}

// ---------- Envío del paquete ---------------------------------------------

function sendPacket(connection, payloadBuffer) {
  const { proto, remoteIp, remotePort } = connection;

  if (!remoteIp || remoteIp === "*" || remotePort === 0) {
    console.error("\n[!] Error: Esta conexión no tiene una IP/Puerto remoto fijo al cual enviar.");
    process.exit(1);
  }

  console.log(
    `\n[*] Enviando paquete (${payloadBuffer.length} bytes) por ${proto.toUpperCase()} a ${remoteIp}:${remotePort}...`,
  );

  if (proto === "udp") {
    const client = dgram.createSocket("udp4");
    client.send(payloadBuffer, remotePort, remoteIp, (err) => {
      if (err) {
        console.error(`[!] Error al enviar UDP: ${err.message}`);
      } else {
        console.log(`[✓] ¡Paquete UDP enviado con éxito!`);
      }
      client.close();
      process.exit(0);
    });
  } else if (proto === "tcp") {
    const client = new net.Socket();
    client.connect(remotePort, remoteIp, () => {
      client.write(payloadBuffer, () => {
        console.log(`[✓] ¡Paquete TCP enviado con éxito al socket del servidor!`);
        client.end();
        process.exit(0);
      });
    });

    client.on("error", (err) => {
      console.error(`[!] Error en la conexión TCP: ${err.message}`);
      process.exit(1);
    });
  }
}

// ---------- Flujo Principal -----------------------------------------------

async function main() {
  console.log(CLEAR + "[*] Cargando procesos y conexiones activas...");
  const connections = loadConnections();

  if (!connections.length) {
    console.error("No se encontraron conexiones activas.");
    process.exit(1);
  }

  const processes = groupByProcess(connections);
  const chosenProcess = await menu(
    "=== Selecciona el Proceso al que deseas enviar paquetes ===\n",
    processes,
    (p) => `${p.name} (${p.pid}) - ${p.connections.length} conexion(es)`,
  );

  if (!chosenProcess) {
    console.log(CLEAR + "[*] Cancelado.");
    process.exit(0);
  }

  const chosenConnection = await menu(
    `=== ${chosenProcess.name} (${chosenProcess.pid}) ===\n`,
    chosenProcess.connections,
    (c) =>
      `${c.proto.toUpperCase()}  ${c.localIp || "*"}:${c.localPort}  <->  ${c.remoteIp}:${c.remotePort}`,
  );

  if (!chosenConnection) {
    console.log(CLEAR + "[*] Cancelado.");
    process.exit(0);
  }

  try {
    process.stdin.setRawMode(false);
    process.stdin.pause();
  } catch {}

  console.log(CLEAR);
  console.log(
    `[*] Destino seleccionado: ${chosenConnection.proto.toUpperCase()} -> ${chosenConnection.remoteIp}:${chosenConnection.remotePort}\n`,
  );

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  console.log("Formatos admitidos:");
  console.log("  - hex:    d3923bb37ed4c1175fd0  (o con espacios)");
  console.log("  - ascii:  ascii /flatctrl 4/sit 0.55 1/");
  console.log("  - pkt:    pkt 2191 000000ba  (calcula [Len][Header][Body] automáticamente)\n");

  rl.question("Introduce el formato y contenido: ", (inputLine) => {
    rl.close();

    const trimmed = inputLine.trim();
    if (!trimmed) {
      console.log("[!] Entrada vacía.");
      process.exit(0);
    }

    let buffer;

    // Detectar si usa el formato automatizado "pkt <HeaderID> [hex]"
    if (trimmed.toLowerCase().startsWith("pkt ")) {
      const parts = trimmed.slice(4).trim().split(/\s+/);
      const headerId = parseInt(parts[0], 10);
      if (isNaN(headerId)) {
        console.error("[!] Error: Header ID inválido. Uso: pkt <HeaderID> [bytes hex]");
        process.exit(1);
      }
      const hexBody = parts
        .slice(1)
        .join("")
        .replace(/[^0-9a-fA-F]/g, "");
      const bodyBuf = Buffer.from(hexBody, "hex");

      buffer = Buffer.alloc(6 + bodyBuf.length);
      buffer.writeUInt32BE(2 + bodyBuf.length, 0);
      buffer.writeUInt16BE(headerId & 0xffff, 4);
      bodyBuf.copy(buffer, 6);
    }
    // Detectar si se indicó explícitamente "ascii "
    else if (trimmed.toLowerCase().startsWith("ascii ")) {
      buffer = Buffer.from(trimmed.slice(6), "latin1");
    }
    // Procesar como Hexadecimal (omitiendo la palabra "hex" si se incluyó)
    else {
      let hexRaw = trimmed;
      if (hexRaw.toLowerCase().startsWith("hex ")) {
        hexRaw = hexRaw.slice(4);
      }
      const cleanHex = hexRaw.replace(/[^0-9a-fA-F]/g, "");
      if (cleanHex.length % 2 !== 0) {
        console.error("[!] Error: La cadena hexadecimal tiene una cantidad impar de caracteres.");
        process.exit(1);
      }
      buffer = Buffer.from(cleanHex, "hex");
    }

    sendPacket(chosenConnection, buffer);
  });
}

if (require.main === module) {
  main();
}
