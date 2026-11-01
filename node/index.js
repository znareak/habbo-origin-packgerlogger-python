const { spawn, spawnSync, execFileSync } = require("child_process");
const readline = require("readline");
const fs = require("fs");
const path = require("path");
const buildSnifferScript = require("./shell");

const CLEAR = "\x1b[2J\x1b[0;0H";

let nativeModule = null;
try {
  nativeModule = require("cap");
} catch {
  // Módulo nativo 'cap' no disponible; se usará el motor PowerShell
}

// ---------- Enumeración de procesos y conexiones --------------------------

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

// ---------- Menú interactivo con teclado ----------------------------------

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

// ---------- Captura y permisos --------------------------------------------

function isAdmin() {
  const output = runCommand("whoami", ["/groups"]);
  return output.includes("S-1-16-12288");
}

function relaunchAsAdmin() {
  const rawArgs = [process.argv[1] || "index.js", ...process.argv.slice(2)];
  const escapedArgs = rawArgs.map((arg) => `'${arg.replace(/'/g, "''")}'`);
  const workingDir = __dirname.replace(/'/g, "''");

  const psCommand =
    `Start-Process -FilePath ((Get-Process -Id $PID).Path) ` +
    `-ArgumentList @(${escapedArgs.join(",")}) ` +
    `-WorkingDirectory '${workingDir}' -Verb RunAs`;

  spawnSync("powershell.exe", ["-NoProfile", "-Command", psCommand], {
    stdio: "inherit",
  });
}

function startCapture(connection, ifaceArg) {
  if (!isAdmin()) {
    console.log("[*] Capturar requiere administrador: reabriendo ventana elevada...");
    relaunchAsAdmin();
    process.exit(0);
  }

  runPowershellEngine(connection);
}

// ---------- Parseo de comandos de envío de paquetes ------------------------

function parseUserPacketInput(input) {
  const trimmed = input.trim();
  if (!trimmed) return null;

  if (trimmed.toLowerCase().startsWith("ascii ")) {
    return Buffer.from(trimmed.slice(6), "latin1");
  }

  if (trimmed.toLowerCase().startsWith("pkt ")) {
    const parts = trimmed.slice(4).trim().split(/\s+/);
    const headerId = parseInt(parts[0], 10);
    if (isNaN(headerId)) {
      console.log("[!] Uso: pkt <HeaderID> [bytes hex]. Ejemplo: pkt 2191 00 00 00 ba");
      return null;
    }
    const hexBody = parts
      .slice(1)
      .join("")
      .replace(/[^0-9a-fA-F]/g, "");
    const bodyBuf = Buffer.from(hexBody, "hex");
    const packet = Buffer.alloc(6 + bodyBuf.length);
    packet.writeUInt32BE(2 + bodyBuf.length, 0);
    packet.writeUInt16BE(headerId & 0xffff, 4);
    bodyBuf.copy(packet, 6);
    return packet;
  }

  let hexRaw = trimmed;
  if (hexRaw.toLowerCase().startsWith("hex ")) {
    hexRaw = hexRaw.slice(4);
  }
  const cleanHex = hexRaw.replace(/[^0-9a-fA-F]/g, "");

  if (!cleanHex || cleanHex.length % 2 !== 0) {
    console.log(
      "[!] Formato inválido. Usa:\n" +
        "    - Bytes en hex:  d3923bb37ed4c1175fd0\n" +
        "    - Paquete Habbo: pkt 2191 000000ba\n" +
        "    - Texto ASCII:   ascii /flatctrl 4/sit 0.55 1/",
    );
    return null;
  }

  return Buffer.from(cleanHex, "hex");
}

function runPowershellEngine(connection) {
  const script = buildSnifferScript(connection);
  const tempScriptPath = path.join(__dirname, "sniffer_temp.ps1");
  fs.writeFileSync(tempScriptPath, script, "utf8");

  const { proto, localIp, localPort, remoteIp, remotePort } = connection;

  console.log("[*] Motor: PowerShell embebido (Npcap + Inyector de paquetes)");
  console.log(
    `[*] Filtro: ${proto} ${localIp || "*"}:${localPort || "*"} <-> ${remoteIp}:${remotePort}`,
  );
  console.log("[*] Comandos para enviar paquetes al servidor mientras capturas:");
  console.log("    - Hex crudo:     d3923bb37ed4c1175fd0");
  console.log("    - Paquete Habbo: pkt 2191 000000ba");
  console.log("    - Texto ASCII:   ascii /flatctrl 4/sit 0.55 1/\n");

  const child = spawn(
    "powershell.exe",
    ["-NoProfile", "-NoLogo", "-ExecutionPolicy", "Bypass", "-File", tempScriptPath],
    { stdio: ["pipe", "pipe", "inherit"] },
  );

  const rlOut = readline.createInterface({ input: child.stdout });

  let autoInjected = false;

  rlOut.on("line", (line) => {
    const match = line.match(/^\[(\d{2}:\d{2}:\d{2})\]\t\[(Send|Recv)\]\t([A-Za-z0-9+/=]+)$/);
    if (match) {
      const direction = match[2];
      const payload = Buffer.from(match[3], "base64");
      printLine(direction, payload);

      if (!autoInjected) {
        autoInjected = true;
        setTimeout(() => {
          console.log("\n[*] [AUTO] Disparando paquete/comando automático al servidor...");
          const autoPayload = Buffer.from("/flatctrl 4/sit 0.55 1", "latin1");
          const b64 = autoPayload.toString("base64");
          child.stdin.write(`SEND:${b64}\n`);
        }, 1000);
      }
    } else if (line.trim()) {
      console.log(line);
    }
  });

  process.stdin.resume();
  const rlIn = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: "",
  });

  rlIn.on("line", (input) => {
    const packetBuf = parseUserPacketInput(input);
    if (packetBuf && packetBuf.length > 0) {
      const b64 = packetBuf.toString("base64");
      child.stdin.write(`SEND:${b64}\n`);
    }
  });

  const cleanup = () => {
    try {
      fs.unlinkSync(tempScriptPath);
    } catch {}
  };

  child.on("exit", () => {
    cleanup();
    process.exit(0);
  });

  process.on("SIGINT", () => {
    console.log("\n[*] Detenido.");
    cleanup();
    child.kill();
    process.exit(0);
  });
}

// ---------- Formateo de salida y flujo principal --------------------------

function printLine(direction, payload) {
  const time = new Date().toTimeString().slice(0, 8);
  const hex = payload.toString("hex").replace(/(..)/g, "$1 ").trim();

  if (payload.length >= 5 && payload.readInt32LE(0) === -1) {
    const typeChar = String.fromCharCode(payload[4]);
    const ascii = payload
      .subarray(5)
      .toString("latin1")
      .replace(/[^\x20-\x7E]+/g, " · ")
      .trim();
    console.log(
      `[${time}]\t[${direction}]\t[Source '${typeChar}' | Len: ${payload.length}] ${hex}` +
        (ascii ? `\n\t\t\tTexto: "${ascii}"` : ""),
    );
    return;
  }

  if (payload.length >= 6 && payload.readUInt32BE(0) === payload.length - 4) {
    const length = payload.readUInt32BE(0);
    const headerId = payload.readUInt16BE(4);
    const body = payload.subarray(6);

    const asciiPreview = body
      .toString("latin1")
      .replace(/[^\x20-\x7E]+/g, " · ")
      .replace(/^ · | · $/g, "");

    console.log(
      `[${time}]\t[${direction}]\t[ID: ${headerId} | Len: ${length}] ${hex}` +
        (asciiPreview ? `\n\t\t\tTexto: "${asciiPreview}"` : ""),
    );
    return;
  }

  console.log(`[${time}]\t[${direction}]\t${hex}`);
}

async function interactive() {
  console.log(CLEAR + "[*] Cargando procesos y conexiones (netstat/tasklist)...");
  const connections = loadConnections();

  if (!connections.length) {
    console.error("No se encontraron conexiones activas.");
    process.exit(1);
  }

  const processes = groupByProcess(connections);
  const chosenProcess = await menu(
    "=== Procesos con conexiones activas ===\n",
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
  } catch {}

  console.log(CLEAR);
  startCapture(chosenConnection, null);
}

function main() {
  const args = process.argv.slice(2);

  if (args.length >= 2 && !isNaN(parseInt(args[1], 10))) {
    const ifaceIndex = args.indexOf("--iface");
    const ifaceArg = ifaceIndex !== -1 ? args[ifaceIndex + 1] : null;

    const connection = {
      proto: args.find((a) => a === "tcp" || a === "udp") || "tcp",
      remoteIp: args[0],
      remotePort: parseInt(args[1], 10),
    };

    startCapture(connection, ifaceArg);
    return;
  }

  interactive();
}

if (require.main === module) {
  main();
}

module.exports = { loadConnections, groupByProcess, rawMenu, menu };
