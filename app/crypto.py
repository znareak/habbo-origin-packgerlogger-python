"""Criptografia desde cero (sin librerias externas): RC4 y MD5."""
from __future__ import annotations

import struct
from typing import List, Optional

_MD5_K = (
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A,
    0xA8304613, 0xFD469501, 0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821, 0xF61E2562, 0xC040B340,
    0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8,
    0x676F02D9, 0x8D2A4C8A, 0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70, 0x289B7EC6, 0xEAA127FA,
    0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92,
    0xFFEFF47D, 0x85845DD1, 0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
)
_MD5_S = (
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
)


def md5(data: bytes) -> bytes:
    """MD5 (RFC 1321) implementado desde cero."""

    def left_rotate(value: int, count: int) -> int:
        value &= 0xFFFFFFFF
        return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF

    a0 = 0x67452301
    b0 = 0xEFCDAB89
    c0 = 0x98BADCFE
    d0 = 0x10325476

    message = bytearray(data)
    message.append(0x80)
    while len(message) % 64 != 56:
        message.append(0)
    message += struct.pack("<Q", (len(data) * 8) & 0xFFFFFFFFFFFFFFFF)

    for offset in range(0, len(message), 64):
        words = list(struct.unpack("<16I", bytes(message[offset:offset + 64])))
        a, b, c, d = a0, b0, c0, d0
        for i in range(64):
            if i < 16:
                f = (b & c) | ((~b) & d)
                g = i
            elif i < 32:
                f = (d & b) | ((~d) & c)
                g = (5 * i + 1) % 16
            elif i < 48:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | (~d))
                g = (7 * i) % 16
            temp = d
            d = c
            c = b
            b = (b + left_rotate((a + f + _MD5_K[i] + words[g]) & 0xFFFFFFFF, _MD5_S[i])) & 0xFFFFFFFF
            a = temp
        a0 = (a0 + a) & 0xFFFFFFFF
        b0 = (b0 + b) & 0xFFFFFFFF
        c0 = (c0 + c) & 0xFFFFFFFF
        d0 = (d0 + d) & 0xFFFFFFFF
    return struct.pack("<4I", a0, b0, c0, d0)


class RC4State:
    """Estado RC4: tabla S e indices i, j."""

    __slots__ = ("sbox", "i", "j")

    def __init__(self, sbox: Optional[List[int]] = None, i: int = 0, j: int = 0):
        self.sbox = list(range(256)) if sbox is None else list(sbox)
        self.i = i & 0xFF
        self.j = j & 0xFF

    @classmethod
    def from_key(cls, key: bytes) -> "RC4State":
        """Inicializa el estado con una clave (KSA)."""
        state = cls()
        j = 0
        for i in range(256):
            j = (j + state.sbox[i] + key[i % len(key)]) & 0xFF
            state.sbox[i], state.sbox[j] = state.sbox[j], state.sbox[i]
        return state

    def crypt(self, data: bytes) -> bytes:
        """Cifra/descifra avanzando el estado (XOR con el keystream)."""
        out = bytearray(len(data))
        sbox = self.sbox
        i, j = self.i, self.j
        for index, byte in enumerate(data):
            i = (i + 1) & 0xFF
            j = (j + sbox[i]) & 0xFF
            sbox[i], sbox[j] = sbox[j], sbox[i]
            out[index] = byte ^ sbox[(sbox[i] + sbox[j]) & 0xFF]
        self.i, self.j = i, j
        return bytes(out)

    def step_back(self) -> None:
        """Deshace una iteracion del PRGA (para descifrar hacia atras)."""
        i, j = self.i & 0xFF, self.j & 0xFF
        sbox = self.sbox
        sbox[i], sbox[j] = sbox[j], sbox[i]
        self.j = (j - sbox[i]) & 0xFF
        self.i = (i - 1) & 0xFF

    def copy(self) -> "RC4State":
        return RC4State(list(self.sbox), self.i, self.j)

    def crypt_backward(self, data: bytes) -> bytes:
        """Descifra `data` retrocediendo por el flujo."""
        out = bytearray(len(data))
        sbox = self.sbox
        for index in range(len(data) - 1, -1, -1):
            i, j = self.i & 0xFF, self.j & 0xFF
            out[index] = data[index] ^ sbox[(sbox[i] + sbox[j]) & 0xFF]
            self.step_back()
        return bytes(out)


def is_permutation(data: bytes) -> bool:
    """True si `data` son 256 bytes que forman una permutacion de 0..255.

    Prefiltro rapido con la suma (0+1+...+255 = 32640, calculada en C) y
    comprobacion exacta con set (tambien en C): permite escanear millones de
    ventanas de memoria por segundo.
    """
    if len(data) != 256:
        return False
    if sum(data) != 32640:
        return False
    return len(set(data)) == 256
