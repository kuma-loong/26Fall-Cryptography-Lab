"""ciphers.algorithms 的最小实现。"""

from __future__ import annotations


class AES:
    name = "AES"
    block_size = 128

    def __init__(self, key: bytes):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key 必须是 bytes")
        key = bytes(key)
        if len(key) not in (16, 24, 32):
            raise ValueError("AES 密钥长度必须是 16 / 24 / 32 字节")
        if len(key) != 16:
            raise NotImplementedError("垫片只实现了 AES-128（本实验只用 128）")
        self.key = key

    def __repr__(self) -> str:
        return "algorithms.AES(key=...)"
