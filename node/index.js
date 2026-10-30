const { spawn, spawnSync, execFileSync } = require("child_process");
const readline = require("readline");

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

    const name = processNames.get(pid) || `(pid ${pid})`;
    const uniqueKey = `${name}|${proto}|${remote.ip}:${remote.port}`;

    if (!seen.has(uniqueKey)) {
      seen.add(uniqueKey);
      connections.push({
        proto: proto.toLowerCase(),
        pid,
        name,
        localIp: local.ip,
        localPort: local.port,
        remoteIp: remote.ip,
        remotePort: remote.port,
      });
    }
  }

  return connections.sort((a, b) => a.name.localeCompare(b.name) || a.remotePort - b.remotePort);
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

  if (nativeModule) {
    runNative(connection, ifaceArg);
  } else {
    runPowershellEngine(connection);
  }
}

// ---------- Motor 1: Módulo nativo 'cap' ----------------------------------

function runNative(connection, ifaceArg) {
  const { Cap, decoders } = nativeModule;
  const { Ethernet, IPV4, IPV6, TCP, UDP, PROTOCOL } = decoders;
  const { proto, remoteIp: host, remotePort: port } = connection;

  const devices = Cap.deviceList();
  const chosenDevice = ifaceArg
    ? devices.find((d) => d.name === ifaceArg)
    : devices.find((d) => (d.addresses || []).some((a) => a.addr && !a.addr.includes(":"))) ||
      devices[0];

  if (!chosenDevice) {
    console.error("No se encontro ninguna interfaz con Npcap.");
    process.exit(1);
  }

  const filter = `${proto} and host ${host} and port ${port}`;
  console.log(`[*] Interfaz: ${chosenDevice.name}`);
  console.log(`[*] Filtro: ${filter}`);
  console.log("[*] Capturando (Ctrl+C para salir)...\n");

  const capture = new Cap();
  const buffer = Buffer.alloc(65535);
  const linkType = capture.open(chosenDevice.name, filter, 10 * 1024 * 1024, buffer);
  capture.setMinBytes?.(0);

  capture.on("packet", () => {
    try {
      const offset = linkType === "ETHERNET" ? Ethernet(buffer).offset : 0;
      const ipv4 = IPV4(buffer, offset);
      const ip = ipv4.info.version === 4 ? ipv4 : IPV6(buffer, offset);
      const transport =
        ip.protocol === PROTOCOL.IP.TCP ? TCP(buffer, ip.offset) : UDP(buffer, ip.offset);

      if (transport.data?.length) {
        const direction = transport.info.srcport === port ? "Recv" : "Send";
        printLine(direction, transport.data);
      }
    } catch {
      // Ignorar paquetes truncados o no soportados
    }
  });

  process.on("SIGINT", () => {
    console.log("\n[*] Detenido.");
    try {
      capture.close();
    } catch {}
    process.exit(0);
  });
}

// ---------- Motor 2: PowerShell + Npcap / Raw Socket ----------------------

function buildSnifferScript(connection) {
  const escapePs = (val) => String(val || "").replace(/'/g, "''");
  const isUdp = connection.proto === "udp";

  return `
$ErrorActionPreference = 'SilentlyContinue'
$LocalIP    = '${escapePs(connection.localIp)}'
$LocalPort  = ${connection.localPort || 0}
$RemoteIP   = '${escapePs(connection.remoteIp)}'
$RemotePort = ${connection.remotePort}
$ProtoNum   = ${isUdp ? 17 : 6}
$IsUdp      = $${isUdp}

if (-not $LocalIP) {
  $probe = New-Object Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork, [Net.Sockets.SocketType]::Dgram, [Net.Sockets.ProtocolType]::Udp)
  $probe.Connect($RemoteIP, 9)
  $LocalIP = $probe.LocalEndPoint.Address.ToString()
  $probe.Close()
}

$localBytes  = [Net.IPAddress]::Parse($LocalIP).GetAddressBytes()
$remoteBytes = [Net.IPAddress]::Parse($RemoteIP).GetAddressBytes()
$buffer      = New-Object byte[] 65536

function Test-IpMatch([byte[]]$buf, [int]$offset, [byte[]]$ip) {
  return ($buf[$offset] -eq $ip[0] -and $buf[$offset+1] -eq $ip[1] -and $buf[$offset+2] -eq $ip[2] -and $buf[$offset+3] -eq $ip[3])
}

function Format-Packet([byte[]]$buf, [int]$length, [int]$baseOffset) {
  if ($baseOffset -ge $length -or (($buf[$baseOffset] -band 0xF0) -ne 0x40) -or $buf[$baseOffset+9] -ne $ProtoNum) { return $null }

  $ipHeaderLen = ($buf[$baseOffset] -band 0x0F) * 4
  $transportOffset = $baseOffset + $ipHeaderLen
  $srcPort = $buf[$transportOffset] * 256 + $buf[$transportOffset+1]
  $dstPort = $buf[$transportOffset+2] * 256 + $buf[$transportOffset+3]

  if ($IsUdp) {
    $dataOffset = $transportOffset + 8
  } else {
    $tcpHeaderLen = (($buf[$transportOffset+12] -band 0xF0) -shr 4) * 4
    $dataOffset = $transportOffset + $tcpHeaderLen
  }

  if ($dataOffset -ge $length) { return $null }

  $isSend = (Test-IpMatch $buf ($baseOffset+12) $localBytes) -and (!$LocalPort -or $srcPort -eq $LocalPort) -and (Test-IpMatch $buf ($baseOffset+16) $remoteBytes) -and ($dstPort -eq $RemotePort)
  $isRecv = (Test-IpMatch $buf ($baseOffset+12) $remoteBytes) -and ($srcPort -eq $RemotePort) -and (Test-IpMatch $buf ($baseOffset+16) $localBytes) -and (!$LocalPort -or $dstPort -eq $LocalPort)

  if ($isSend) { $direction = 'Send' }
  elseif ($isRecv) { $direction = 'Recv' }
  else { return $null }

  $payloadLen = $length - $dataOffset
  $payload = New-Object byte[] $payloadLen
  [Array]::Copy($buf, $dataOffset, $payload, 0, $payloadLen)

  $time = Get-Date -Format 'HH:mm:ss'
  $base64 = [Convert]::ToBase64String($payload)
  return "[$time]\`t[$direction]\`t$base64"
}

# Intentar inicializar Npcap (wpcap.dll)
$capHandle = [IntPtr]::Zero
try {
  Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public struct bpf_program_t { public uint bf_len; public IntPtr bf_insns; }

public static class Npcap {
  [DllImport("wpcap.dll", CharSet=CharSet.Ansi)] public static extern int pcap_findalldevs(ref IntPtr alldevs, StringBuilder errbuf);
  [DllImport("wpcap.dll")] public static extern void pcap_freealldevs(IntPtr alldevs);
  [DllImport("wpcap.dll", CharSet=CharSet.Ansi)] public static extern IntPtr pcap_open_live(string dev, int snaplen, int promisc, int to_ms, StringBuilder errbuf);
  [DllImport("wpcap.dll")] public static extern int pcap_next_ex(IntPtr p, ref IntPtr hdr, ref IntPtr data);
  [DllImport("wpcap.dll")] public static extern int pcap_datalink(IntPtr p);
  [DllImport("wpcap.dll", CharSet=CharSet.Ansi)] public static extern int pcap_compile(IntPtr p, ref bpf_program_t fp, string str, int optimize, uint netmask);
  [DllImport("wpcap.dll")] public static extern int pcap_setfilter(IntPtr p, ref bpf_program_t fp);
}
'@

  Get-Service npcap, npf | Where-Object Status -ne 'Running' | Start-Service
  $wmiConfig = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | Where-Object { $_.IPAddress -contains $LocalIP } | Select-Object -First 1
  $adapterAlias = if ($wmiConfig) { (Get-WmiObject Win32_NetworkAdapter -Filter "Index=$($wmiConfig.Index)").NetConnectionID }

  $devListPtr = [IntPtr]::Zero
  $errBuf = New-Object Text.StringBuilder 256

  if ([Npcap]::pcap_findalldevs([ref]$devListPtr, $errBuf) -eq 0 -and $devListPtr -ne [IntPtr]::Zero) {
    $currentPtr = $devListPtr
    $firstDev = $null
    $selectedDev = $null

    while ($currentPtr -ne [IntPtr]::Zero) {
      $namePtr = [Runtime.InteropServices.Marshal]::ReadIntPtr($currentPtr, 8)
      $descPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr($currentPtr, 16)
      $name = [Runtime.InteropServices.Marshal]::PtrToStringAnsi($namePtr)
      $desc = [Runtime.InteropServices.Marshal]::PtrToStringAnsi($descPtr)

      if (-not $name) { break }
      if (-not $firstDev) { $firstDev = $name }

      $isLoopback = $LocalIP.StartsWith('127.') -and ($desc -match 'loopback')
      $isMatchingAdapter = $adapterAlias -and ($desc -match [regex]::Escape($adapterAlias))

      if ($isLoopback -or $isMatchingAdapter) {
        $selectedDev = $name
        break
      }
      $currentPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr($currentPtr, 0)
    }

    [Npcap]::pcap_freealldevs($devListPtr)
    if (-not $selectedDev) { $selectedDev = $firstDev }

    if ($selectedDev) {
      $capHandle = [Npcap]::pcap_open_live($selectedDev, 65535, 1, 500, $errBuf)
      if ($capHandle -ne [IntPtr]::Zero) {
        $filterProg = New-Object bpf_program_t
        $protoName = if ($IsUdp) { 'udp' } else { 'tcp' }
        $filterStr = "$protoName and host $RemoteIP and port $RemotePort"

        if ([Npcap]::pcap_compile($capHandle, [ref]$filterProg, $filterStr, 1, 0xffffffff) -ge 0) {
          $null = [Npcap]::pcap_setfilter($capHandle, [ref]$filterProg)
        }
        $dataLink = [Npcap]::pcap_datalink($capHandle)
        Write-Output "[INFO] Capturando con Npcap ($selectedDev)..."
      }
    }
  }
} catch {}

# Fallback a Raw Socket si Npcap no pudo iniciarse
if ($capHandle -eq [IntPtr]::Zero) {
  try {
    $rawSocket = New-Object Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork, [Net.Sockets.SocketType]::Raw, [Net.Sockets.ProtocolType]::IP)
    $rawSocket.Bind((New-Object Net.IPEndPoint([Net.IPAddress]::Parse($LocalIP), 0)))
    $null = $rawSocket.IOControl([Net.Sockets.IOControlCode]::ReceiveAll, [BitConverter]::GetBytes([int]1), $null)
    $rawSocket.ReceiveTimeout = 1000
    Write-Output '[INFO] Capturando con raw socket (solo paquetes Send)...'
  } catch {
    Write-Output '[ERR] No se pudo iniciar Npcap ni raw socket.'
    exit 1
  }
}

# Bucle principal de lectura
$hdrPtr = [IntPtr]::Zero
$dataPtr = [IntPtr]::Zero

while ($true) {
  if ($capHandle -ne [IntPtr]::Zero) {
    if ([Npcap]::pcap_next_ex($capHandle, [ref]$hdrPtr, [ref]$dataPtr) -le 0) { continue }
    $packetLen = [Runtime.InteropServices.Marshal]::ReadInt32($hdrPtr, 8)
    if ($packetLen -le 0) { continue }

    [Runtime.InteropServices.Marshal]::Copy($dataPtr, $buffer, 0, $packetLen)
    $etherType = $buffer[12] * 256 + $buffer[13]
    $baseOffset = if ($dataLink -eq 0) { 4 } elseif ($etherType -eq 0x8100) { 18 } else { 14 }
  } else {
    try { $packetLen = $rawSocket.Receive($buffer) } catch { $packetLen = 0 }
    if ($packetLen -lt 20) { continue }
    $baseOffset = 0
  }

  $formattedLine = Format-Packet $buffer $packetLen $baseOffset
  if ($formattedLine) {
    Write-Output $formattedLine
    [Console]::Out.Flush()
  }
}
`.trim();
}

function runPowershellEngine(connection) {
  const script = buildSnifferScript(connection);
  const encodedScript = Buffer.from(script, "utf16le").toString("base64");
  const { proto, localIp, localPort, remoteIp, remotePort } = connection;

  console.log("[*] Motor: PowerShell embebido (Npcap / Raw Socket)");
  console.log(
    `[*] Filtro: ${proto} ${localIp || "?"}:${localPort || "?"} <-> ${remoteIp}:${remotePort}`,
  );
  console.log("[*] Capturando (Ctrl+C para salir)...\n");

  const child = spawn(
    "powershell.exe",
    ["-NoProfile", "-NoLogo", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodedScript],
    { stdio: ["ignore", "pipe", "inherit"] },
  );

  const rl = readline.createInterface({ input: child.stdout });

  rl.on("line", (line) => {
    const match = line.match(/^\[(\d{2}:\d{2}:\d{2})\]\t\[(Send|Recv)\]\t([A-Za-z0-9+/=]+)$/);
    if (match) {
      const direction = match[2];
      const payload = Buffer.from(match[3], "base64");
      printLine(direction, payload);
    } else if (line.trim()) {
      console.log(line);
    }
  });

  child.on("exit", () => process.exit(0));
  process.on("SIGINT", () => {
    console.log("\n[*] Detenido.");
    child.kill();
    process.exit(0);
  });

  if (process.env.PACKETLOGGER_TIMEOUT) {
    const timeoutMs = Number(process.env.PACKETLOGGER_TIMEOUT) * 1000;
    setTimeout(() => {
      console.log("\n[*] Tiempo agotado.");
      child.kill();
      process.exit(0);
    }, timeoutMs);
  }
}

// ---------- Formateo de salida y flujo principal --------------------------

function printLine(direction, payload) {
  const time = new Date().toTimeString().slice(0, 8);
  const hex = payload.toString("hex").replace(/(..)/g, "$1 ").trim();

  // Si es un paquete estructurado con longitud (4 bytes) + Header ID (2 bytes)
  if (payload.length >= 6 && payload.readUInt32BE(0) === payload.length - 4) {
    const length = payload.readUInt32BE(0);
    const headerId = payload.readUInt16BE(4);
    const body = payload.subarray(6);

    // Extraer cadenas ASCII legibles (precedidas por uint16 de longitud) o texto visible
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
      `${c.proto.toUpperCase()}  ${c.localIp}:${c.localPort}  <->  ${c.remoteIp}:${c.remotePort}`,
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

module.exports = { loadConnections, groupByProcess, rawMenu, menu, buildSnifferScript };
