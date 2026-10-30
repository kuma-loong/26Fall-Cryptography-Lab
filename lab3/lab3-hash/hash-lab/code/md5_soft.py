"""纯 Python 的 MD5，支持从中间状态继续计算。

标准库里 hashlib.md5 只能从头算。长度扩展攻击需要：

    已知 H(m) 和 len(m)，从 H(m) 这个状态继续压 suffix

所以本文件把 MD5 的内部状态暴露出来：

    h = md5(state=bytes.fromhex(旧摘要), count=已处理的比特数)
    h.update(要追加的字节)
    h.hexdigest()

参数说明：
    state  16 字节，四个 32 位字按小端序排列
    count  已经处理过的比特数，必须是 512 的倍数

普通用法和 hashlib 一样：

    md5(b"abc").hexdigest()

本文件是参照实现，学生不需要修改。
"""

from __future__ import annotations

import math
import struct

__all__ = ["md5", "padding"]

# RFC 1321 的四个初始状态字
_INIT = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)

# 每轮的左移位数
_S = (
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
)

# K[i] = floor(abs(sin(i + 1)) * 2^32)
_K = tuple(int(abs(math.sin(i + 1)) * 4294967296) & 0xFFFFFFFF for i in range(64))

_MASK = 0xFFFFFFFF


def _rotl(x: int, n: int) -> int:
    x &= _MASK
    return ((x << n) | (x >> (32 - n))) & _MASK


def _compress(state: tuple[int, int, int, int], block: bytes) -> tuple[int, int, int, int]:
    """压一个 64 字节块，返回新的四个状态字。"""
    a, b, c, d = state
    m = struct.unpack("<16I", block)

    for i in range(64):
        if i < 16:
            f = (b & c) | (~b & d)
            g = i
        elif i < 32:
            f = (d & b) | (~d & c)
            g = (5 * i + 1) % 16
        elif i < 48:
            f = b ^ c ^ d
            g = (3 * i + 5) % 16
        else:
            f = c ^ (b | (~d))
            g = (7 * i) % 16

        f = (f + a + _K[i] + m[g]) & _MASK
        a, d, c, b = d, c, b, (b + _rotl(f, _S[i])) & _MASK

    return (
        (state[0] + a) & _MASK,
        (state[1] + b) & _MASK,
        (state[2] + c) & _MASK,
        (state[3] + d) & _MASK,
    )


def padding(msg_len: int) -> bytes:
    """MD5 对 msg_len 字节消息追加的填充。

    结构：0x80 + 若干 0x00 + 8 字节小端序的消息比特数。
    填充后总长度是 64 的倍数。
    """
    if msg_len < 0:
        raise ValueError("msg_len 不能是负数")
    zero_count = (56 - (msg_len + 1) % 64) % 64
    bit_len = (msg_len * 8) & 0xFFFFFFFFFFFFFFFF
    return b"\x80" + b"\x00" * zero_count + struct.pack("<Q", bit_len)


class MD5:
    def __init__(self, data: bytes = b"", *, state: bytes | None = None, count: int = 0):
        if state is None:
            self._state = _INIT
        else:
            if len(state) != 16:
                raise ValueError("state 必须是 16 字节")
            self._state = struct.unpack("<4I", state)
        if count < 0 or count % 8:
            raise ValueError("count 必须是非负的比特数")
        self._count = count          # 已经压过的比特数
        self._buffer = b""
        if data:
            self.update(data)

    def update(self, data: bytes) -> "MD5":
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("update 只接受 bytes")
        self._buffer += bytes(data)
        while len(self._buffer) >= 64:
            block = self._buffer[:64]
            self._buffer = self._buffer[64:]
            self._state = _compress(self._state, block)
            self._count += 512
        return self

    def digest(self) -> bytes:
        state = self._state
        tail = self._buffer
        total_bits = self._count + len(tail) * 8
        data = tail + padding(total_bits // 8)
        for i in range(0, len(data), 64):
            state = _compress(state, data[i:i + 64])
        return struct.pack("<4I", *state)

    def hexdigest(self) -> str:
        return self.digest().hex()


def md5(data: bytes = b"", *, state: bytes | None = None, count: int = 0) -> MD5:
    """返回一个 MD5 对象。参数含义见模块开头。"""
    return MD5(data, state=state, count=count)


if __name__ == "__main__":
    import hashlib

    for n in (0, 1, 3, 55, 56, 63, 64, 65, 127, 128, 1000):
        msg = b"a" * n
        mine = md5(msg).hexdigest()
        ref = hashlib.md5(msg).hexdigest()
        assert mine == ref, (n, mine, ref)
    print("md5_soft 自检通过：11 个长度与 hashlib 一致")
