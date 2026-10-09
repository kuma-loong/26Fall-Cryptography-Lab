"""ciphers.modes 的最小实现（ECB / CBC）。"""

from __future__ import annotations


class ECB:
    name = "ECB"

    def __repr__(self) -> str:
        return "<ECB>"


class CBC:
    name = "CBC"

    def __init__(self, initialization_vector: bytes):
        if len(initialization_vector) != 16:
            raise ValueError("CBC 的 IV 必须是 16 字节")
        self.initialization_vector = bytes(initialization_vector)

    def __repr__(self) -> str:
        return "<CBC>"
