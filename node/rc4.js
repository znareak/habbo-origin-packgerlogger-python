"use strict";

// ==========================================
// Port a Node.js de la lógica de RC4 / escaneo del Packet Logger Python:
//   app/crypto.py   -> RC4State
//   app/processio.py -> scan_rc4_cells_in_chunk
//   app/capture.py  -> _frame_score, _crack_table_from_stream_start
// ==========================================

const BINARY_MAX_MESSAGE_LENGTH = 1 << 20; // 1 MB (como capture.py)

class RC4State {
  constructor(sbox, i = 0, j = 0) {
    this.sbox = sbox ? Array.from(sbox) : Array.from({ length: 256 }, (_, k) => k);
    this.i = i & 0xff;
    this.j = j & 0xff;
  }

  static fromKey(key) {
    const st = new RC4State();
    let j = 0;
    for (let i = 0; i < 256; i++) {
      j = (j + st.sbox[i] + key[i % key.length]) & 0xff;
      const t = st.sbox[i];
      st.sbox[i] = st.sbox[j];
      st.sbox[j] = t;
    }
    return st;
  }

  crypt(data) {
    const out = Buffer.alloc(data.length);
    const s = this.sbox;
    let i = this.i,
      j = this.j;
    for (let k = 0; k < data.length; k++) {
      i = (i + 1) & 0xff;
      j = (j + s[i]) & 0xff;
      const t = s[i];
      s[i] = s[j];
      s[j] = t;
      out[k] = data[k] ^ s[(s[i] + s[j]) & 0xff];
    }
    this.i = i;
    this.j = j;
    return out;
  }

  // Deshace una iteración del PRGA (para descifrar hacia atrás).
  stepBack() {
    const s = this.sbox;
    const i = this.i & 0xff,
      j = this.j & 0xff;
    const t = s[i];
    s[i] = s[j];
    s[j] = t;
    this.j = (j - s[i]) & 0xff;
    this.i = (i - 1) & 0xff;
  }

  cryptBackward(data) {
    const out = Buffer.alloc(data.length);
    for (let k = data.length - 1; k >= 0; k--) {
      const s = this.sbox;
      const i = this.i & 0xff,
        j = this.j & 0xff;
      out[k] = data[k] ^ s[(s[i] + s[j]) & 0xff];
      this.stepBack();
    }
    return out;
  }

  copy() {
    return new RC4State(this.sbox, this.i, this.j);
  }
}

// Prefiltro rápido (suma 0..255 = 32640) + verificación exacta.
function isPermutation(bytes) {
  if (bytes.length !== 256) return false;
  let sum = 0;
  for (let i = 0; i < 256; i++) sum += bytes[i];
  if (sum !== 32640) return false;
  const seen = new Uint8Array(256);
  for (let i = 0; i < 256; i++) {
    if (seen[bytes[i]]) return false;
    seen[bytes[i]] = 1;
  }
  return true;
}

// Cuántos mensajes con framing válido consecutivos hay en `data`.
function frameScore(data) {
  let index = 0,
    score = 0;
  while (index + 6 <= data.length) {
    const length = data.readInt32BE(index);
    if (length < 2 || length > BINARY_MAX_MESSAGE_LENGTH) break;
    if (index + 4 + length > data.length) break;
    score++;
    index += 4 + length;
  }
  return score;
}

// Busca corridas de 256 celdas int32 con byte bajo distinto y 3 altos a cero.
// Así guarda el cliente Flash la tabla RC4 (256 enteros de 32 bits).
// Devuelve [{ address, sbox: [256 valores] }].
function scanRc4CellsInChunk(chunk, baseAddress) {
  const found = [];
  const n = chunk.length;
  if (n < 1024) return found;

  let i = 0;
  while (i + 1024 <= n) {
    if (chunk[i + 1] === 0 && chunk[i + 2] === 0 && chunk[i + 3] === 0) {
      let valid = true;
      const values = new Uint8Array(256);
      for (let j = 0; j < 256; j++) {
        const b = i + j * 4;
        if (chunk[b + 1] !== 0 || chunk[b + 2] !== 0 || chunk[b + 3] !== 0) {
          valid = false;
          break;
        }
        values[j] = chunk[b];
      }
      if (valid && isPermutation(values)) {
        found.push({ address: baseAddress + i, sbox: Array.from(values) });
        if (found.length >= 50) return found;
        i += 1024; // saltar esta corrida ya encontrada
        continue;
      }
      i += 4;
    } else {
      i += 4;
    }
  }
  return found;
}

// Método de G-Earth: con los primeros bytes cifrados del flujo, probar la tabla
// deshaciendo el RC4 hasta el inicio (i == 0 y j == 0 al deshacer).
// Devuelve { i, j, score } del estado al FINAL del buffer, o null.
function crackTableFromStreamStart(enc, sbox) {
  const length = enc.length;
  const iSnapshot = length % 256;
  for (let j = 0; j < 256; j++) {
    const state = new RC4State(sbox, iSnapshot, j);
    for (let k = 0; k < length; k++) state.stepBack();
    if (state.i !== 0 || state.j !== 0) continue;
    const zero = new RC4State(state.sbox, 0, 0);
    const score = frameScore(zero.crypt(enc));
    if (score >= 1) return { i: iSnapshot, j, score };
  }
  return null;
}

// Busca la tabla RC4 como 256 bytes CONTIGUOS que forman una permutación de 0..255.
// (respaldo por si el cliente la guarda en bytes contiguos y no como celdas int32).
function scanPermutationInChunk(chunk, baseAddress) {
  const found = [];
  const n = chunk.length;
  if (n < 256) return found;
  let sum = 0;
  for (let k = 0; k < 256; k++) sum += chunk[k];
  for (let i = 0; i + 256 <= n; i++) {
    if (sum === 32640) {
      const w = chunk.subarray(i, i + 256);
      if (isPermutation(w)) {
        found.push({ address: baseAddress + i, sbox: Array.from(w) });
        if (found.length >= 50) return found;
      }
    }
    if (i + 256 < n) sum += chunk[i + 256] - chunk[i];
  }
  return found;
}

module.exports = {
  RC4State,
  isPermutation,
  frameScore,
  scanRc4CellsInChunk,
  scanPermutationInChunk,
  crackTableFromStreamStart,
  BINARY_MAX_MESSAGE_LENGTH,
};
