"use strict";

// ==========================================
// Escaneo de memoria del proceso (ReadProcessMemory) vía koffi (FFI).
// Port de app/processio.py (scan_process_rc4_cells) y app/capture.py (find_rc4_state).
// Requiere ejecutarse como Administrador para abrir procesos ajenos.
// ==========================================

const koffi = require("koffi");
const {
  isPermutation,
  scanRc4CellsInChunk,
  scanPermutationInChunk,
  crackTableFromStreamStart,
} = require("./rc4.js");

const kernel32 = koffi.load("kernel32.dll");

const OpenProcess = kernel32.func(
  "void* OpenProcess(uint32 dwDesiredAccess, int bInheritHandle, uint32 dwProcessId)",
);
const VirtualQueryEx = kernel32.func(
  "size_t VirtualQueryEx(void* hProcess, uintptr_t lpAddress, _Out_ void* lpBuffer, size_t dwLength)",
);
const ReadProcessMemory = kernel32.func(
  "bool ReadProcessMemory(void* hProcess, uintptr_t lpBaseAddress, _Out_ void* lpBuffer, size_t nSize, size_t* lpNumberOfBytesRead)",
);
const CloseHandle = kernel32.func("bool CloseHandle(void* hObject)");
const GetLastError = kernel32.func("uint32 GetLastError()");

const PROCESS_VM_READ = 0x0010;
const PROCESS_QUERY_INFORMATION = 0x0400;

const MEM_COMMIT = 0x1000;
const MEM_PRIVATE = 0x20000;

const READABLE_PROTECTS = new Set([
  0x02, // PAGE_READONLY
  0x04, // PAGE_READWRITE
  0x08, // PAGE_WRITECOPY
  0x20, // PAGE_EXECUTE_READ
  0x40, // PAGE_EXECUTE_READWRITE
  0x80, // PAGE_EXECUTE_WRITECOPY
]);

// MEMORY_BASIC_INFORMATION en Windows 10+ x64 (incluye PartitionId).
const MBI_SIZE = 48;

function openProcess(pid) {
  const h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid);
  if (!h) {
    const err = GetLastError();
    const msg =
      err === 5
        ? "acceso denegado — ejecuta el proxy como Administrador"
        : err === 87
          ? "parámetro inválido — el PID no existe (¿reiniciaste el juego?)"
          : `código de error ${err}`;
    throw new Error(`No se pudo abrir el proceso ${pid} (${msg}).`);
  }
  return h;
}

// Regiones de memoria comprometidas y legibles del proceso.
function listReadableRegions(handle, maxRegions = 20000, privateOnly = false) {
  const regions = [];
  let address = 0n;
  const buf = Buffer.alloc(MBI_SIZE);
  while (regions.length < maxRegions) {
    const ret = VirtualQueryEx(handle, address, buf, MBI_SIZE);
    if (ret === 0) break;
    const baseAddress = buf.readBigUInt64LE(0);
    const regionSize = buf.readBigUInt64LE(24);
    const state = buf.readUInt32LE(32);
    const protect = buf.readUInt32LE(36);
    const type = buf.readUInt32LE(40);
    if (
      state === MEM_COMMIT &&
      READABLE_PROTECTS.has(protect) &&
      regionSize > 0n &&
      !(privateOnly && type !== MEM_PRIVATE)
    ) {
      regions.push({ base: baseAddress, size: regionSize });
    }
    address = baseAddress + regionSize;
    if (address <= baseAddress) break;
  }
  return regions;
}

function readProcessMemory(handle, address, size) {
  const buf = Buffer.alloc(size);
  const ok = ReadProcessMemory(handle, address, buf, size, null);
  if (!ok) return null;
  return buf;
}

// Escanea la memoria del proceso en busca de tablas RC4 como celdas int32.
// Devuelve [{ address: BigInt, sbox: [256] }].
function scanProcessRc4Cells(pid, maxBytes = 512 * 1024 * 1024, progress = null) {
  const handle = openProcess(pid);
  if (!handle) throw new Error(`No se pudo abrir el proceso ${pid} (¿Administrador?).`);
  try {
    const found = [];
    let scanned = 0;
    let regions = 0;
    const regionsList = listReadableRegions(handle);
    for (const { base, size } of regionsList) {
      if (scanned >= maxBytes) break;
      const chunkSize = Math.min(Number(size), 32 * 1024 * 1024);
      const chunk = readProcessMemory(handle, base, chunkSize);
      if (!chunk) continue;
      scanned += chunk.length;
      regions++;
      if (progress) progress(scanned);
      found.push(...scanRc4CellsInChunk(chunk, base));
      if (found.length >= 50) break;
    }
    return { found, scanned, regions, totalRegions: regionsList.length };
  } finally {
    CloseHandle(handle);
  }
}

// Escaneo de respaldo: tabla RC4 como 256 bytes contiguos (permutación).
function scanProcessPermutations(pid, maxBytes = 256 * 1024 * 1024, progress = null) {
  const handle = openProcess(pid);
  if (!handle) throw new Error(`No se pudo abrir el proceso ${pid} (¿Administrador?).`);
  try {
    const found = [];
    let scanned = 0;
    let regions = 0;
    const regionsList = listReadableRegions(handle, 20000, true);
    for (const { base, size } of regionsList) {
      if (scanned >= maxBytes) break;
      const chunkSize = Math.min(Number(size), 32 * 1024 * 1024);
      const chunk = readProcessMemory(handle, base, chunkSize);
      if (!chunk) continue;
      scanned += chunk.length;
      regions++;
      if (progress) progress(scanned);
      found.push(...scanPermutationInChunk(chunk, base));
      if (found.length >= 50) break;
    }
    return { found, scanned, regions, totalRegions: regionsList.length };
  } finally {
    CloseHandle(handle);
  }
}

// Busca la tabla RC4 en memoria y la verifica contra el inicio del flujo cifrado.
// `enc` es un Buffer con los primeros bytes cifrados del flujo Send (desde el inicio).
// Devuelve { address, sbox, i, j, score } o lanza Error.
function findRc4State(pid, enc, progress = null) {
  if (enc.length < 6) {
    throw new Error(
      "Pocos bytes cifrados para crackear: reconecta el juego con la captura activa.",
    );
  }
  const handle = openProcess(pid);
  if (!handle) throw new Error(`No se pudo abrir el proceso ${pid} (¿Administrador?).`);
  try {
    // 1) celdas int32 (método principal, como G-Mem)
    let tables = scanProcessRc4Cells(pid, 512 * 1024 * 1024, progress);
    if (!tables.found.length) {
      // 2) respaldo: bytes contiguos
      if (progress)
        progress(
          `Sin celdas int32 (${(tables.scanned / 1048576) | 0} MB en ${tables.regions} regiones). Probando bytes contiguos...`,
        );
      tables = scanProcessPermutations(pid, 256 * 1024 * 1024, progress);
    }
    if (!tables.found.length) {
      throw new Error(
        `No se encontró la tabla RC4 en memoria (${(tables.scanned / 1048576) | 0} MB leídos, ` +
          `${tables.regions}/${tables.totalRegions} regiones legibles). ` +
          `Si dice "0 regiones legibles": ejecuta el proxy como Administrador.`,
      );
    }
    for (let idx = 0; idx < tables.found.length; idx++) {
      const { address, sbox } = tables.found[idx];
      if (progress) progress(`Probando tabla ${idx + 1}/${tables.found.length}...`);
      // Re-leer la ventana para obtener el estado fresco (la tabla muta constantemente).
      const window = readProcessMemory(handle, address, 1024);
      let s = sbox;
      if (window && window.length >= 1024) {
        const low = [];
        for (let i = 0; i < 1024; i += 4) low.push(window[i]);
        if (isPermutation(low)) s = low;
      }
      const result = crackTableFromStreamStart(enc, s);
      if (result) {
        return { address, sbox: s, i: result.i, j: result.j, score: result.score };
      }
    }
    throw new Error(
      `Se hallaron ${tables.found.length} tablas RC4 pero ninguna descifró el inicio del flujo.`,
    );
  } finally {
    CloseHandle(handle);
  }
}

module.exports = {
  openProcess,
  listReadableRegions,
  readProcessMemory,
  scanProcessRc4Cells,
  scanProcessPermutations,
  findRc4State,
};
