"""padding.PKCS7 的最小实现。"""

from __future__ import annotations


class _Padder:
    def __init__(self, block_bits: int) -> None:
        self._bs = block_bits // 8
        self._buf = bytearray()
        self._done = False

    def update(self, data: bytes) -> bytes:
        if self._done:
            raise ValueError("已经 finalize 过了")
        self._buf += data
        return b""

    def finalize(self) -> bytes:
        if self._done:
            raise ValueError("已经 finalize 过了")
        self._done = True
        data = bytes(self._buf)
        n = self._bs - (len(data) % self._bs)
        return data + bytes([n]) * n


class _Unpadder:
    def __init__(self, block_bits: int) -> None:
        self._bs = block_bits // 8
        self._buf = bytearray()
        self._done = False

    def update(self, data: bytes) -> bytes:
        if self._done:
            raise ValueError("已经 finalize 过了")
        self._buf += data
        return b""

    def finalize(self) -> bytes:
        if self._done:
            raise ValueError("已经 finalize 过了")
        self._done = True
        data = bytes(self._buf)
        if not data or len(data) % self._bs:
            raise ValueError("数据长度不是分组长度的整数倍")
        n = data[-1]
        if not 1 <= n <= self._bs:
            raise ValueError(f"填充字节非法：0x{n:02x}（PKCS#7）")
        if data[-n:] != bytes([n]) * n:
            raise ValueError(f"填充内容不一致（PKCS#7），密文可能已被篡改")
        return data[:-n]


class PKCS7:
    def __init__(self, block_size: int) -> None:
        if block_size % 8 or not 0 < block_size <= 2048:
            raise ValueError("block_size 必须是 8 的倍数且在 (0, 2048] 内")
        self.block_size = block_size

    def padder(self) -> _Padder:
        return _Padder(self.block_size)

    def unpadder(self) -> _Unpadder:
        return _Unpadder(self.block_size)
