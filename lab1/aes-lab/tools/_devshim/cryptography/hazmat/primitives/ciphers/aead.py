"""AESGCM —— 按 NIST SP 800-38D 完整实现的 GCM。

垫片里唯一一个「认真实现」的算法，因为本实验的任务六要靠它演示
「分组可以搬、但标签会揭穿」，行为必须真实。

结构：
    H  = E_K(0^128)
    J0 = nonce || 0^31 || 1                    （96 位 nonce）
    C  = GCTR_K(inc32(J0), P)
    S  = GHASH_H(A || pad || C || pad || len(A)_64 || len(C)_64)
    T  = MSB_t(GCTR_K(J0, S))

GF(2^128) 乘法用 SP 800-38D 6.3 的位串算法，约简多项式 R = 0xE1 || 0^120。
"""

from __future__ import annotations

from ....exceptions import InvalidTag  # noqa: F401  (对外暴露)
from ._core import aes_encrypt_block

_BLOCK = 16
_R = 0xE1 << 120


def _gf_mul(x: int, y: int) -> int:
    """GF(2^128) 乘法（SP 800-38D 6.3）。"""
    z = 0
    v = y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _R
        else:
            v >>= 1
    return z


def _ghash(h: int, data: bytes) -> int:
    assert len(data) % _BLOCK == 0
    y = 0
    for i in range(0, len(data), _BLOCK):
        y ^= int.from_bytes(data[i : i + _BLOCK], "big")
        y = _gf_mul(y, h)
    return y


def _inc32(block: bytes) -> bytes:
    n = (int.from_bytes(block[-4:], "big") + 1) % (1 << 32)
    return block[:-4] + n.to_bytes(4, "big")


def _gctr(key: bytes, icb: bytes, data: bytes) -> bytes:
    if not data:
        return b""
    out = bytearray()
    cb = icb
    for i in range(0, len(data), _BLOCK):
        ks = aes_encrypt_block(cb, key)
        chunk = data[i : i + _BLOCK]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
        cb = _inc32(cb)
    return bytes(out)


def _pad16(data: bytes) -> bytes:
    if len(data) % _BLOCK == 0:
        return b""
    return b"\x00" * (_BLOCK - len(data) % _BLOCK)


class AESGCM:
    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("AESGCM 密钥长度必须是 16 / 24 / 32 字节")
        if len(key) != 16:
            raise NotImplementedError("垫片只实现了 AES-128-GCM")
        self._key = bytes(key)

    # -- 内部 -------------------------------------------------------------
    def _j0(self, nonce: bytes) -> bytes:
        if len(nonce) == 12:
            return nonce + b"\x00\x00\x00\x01"
        # 非 96 位 nonce：GHASH 派生（本实验用不到，略）
        raise NotImplementedError("垫片只支持 96 位 nonce")

    def _tag(self, j0: bytes, aad: bytes, ct: bytes) -> bytes:
        h = int.from_bytes(aes_encrypt_block(b"\x00" * _BLOCK, self._key), "big")
        lengths = (len(aad) * 8).to_bytes(8, "big") + (len(ct) * 8).to_bytes(8, "big")
        s = _ghash(h, aad + _pad16(aad) + ct + _pad16(ct) + lengths)
        return _gctr(self._key, j0, s.to_bytes(_BLOCK, "big"))

    # -- 公开 API ---------------------------------------------------------
    def encrypt(self, nonce: bytes, data: bytes, associated_data: bytes | None) -> bytes:
        aad = associated_data or b""
        j0 = self._j0(nonce)
        ct = _gctr(self._key, _inc32(j0), data)
        return ct + self._tag(j0, aad, ct)

    def decrypt(self, nonce: bytes, data: bytes, associated_data: bytes | None) -> bytes:
        aad = associated_data or b""
        if len(data) < _BLOCK:
            raise InvalidTag("密文长度不足，缺少认证标签")
        ct, tag = data[:-_BLOCK], data[-_BLOCK:]
        j0 = self._j0(nonce)
        expect = self._tag(j0, aad, ct)
        # 认证标签用常数时间比较；这里是垫片，直接比
        if tag != expect:
            raise InvalidTag("认证标签校验失败")
        return _gctr(self._key, _inc32(j0), ct)
