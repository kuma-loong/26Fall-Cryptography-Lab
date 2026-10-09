"""ciphers 包：Cipher 类。

行为对齐真实 cryptography：
  · 构造时校验 mode 与 algorithm；
  · update() 攒缓冲，finalize() 时要求总长度是分组长度的整数倍，否则 ValueError；
  · ECB / CBC 都**不做填充** —— 填充是调用方的事（用 padding.PKCS7）。
"""

from __future__ import annotations

from . import algorithms, modes
from ._core import aes_decrypt_block, aes_encrypt_block

__all__ = ["Cipher", "algorithms", "modes"]

_BLOCK = 16


class _Ctx:
    def __init__(self, algorithm: algorithms.AES, mode) -> None:
        self._alg = algorithm
        self._mode = mode
        self._buf = bytearray()
        self._done = False

    # -- 子类实现 ---------------------------------------------------------
    def _process(self, data: bytes) -> bytes:
        raise NotImplementedError

    # -- 公共 API ----------------------------------------------------------
    def update(self, data: bytes) -> bytes:
        if self._done:
            raise ValueError("上下文已经 finalize 过了")
        self._buf += data
        return b""

    def finalize(self) -> bytes:
        if self._done:
            raise ValueError("上下文已经 finalize 过了")
        self._done = True
        data = bytes(self._buf)
        if len(data) % _BLOCK:
            raise ValueError(
                f"数据长度 {len(data)} 不是分组长度的整数倍"
                "（ECB/CBC 不自动填充，需要调用方自己用 PKCS7 补齐）"
            )
        return self._process(data)


class _ECBEnc(_Ctx):
    def _process(self, data: bytes) -> bytes:
        return b"".join(
            aes_encrypt_block(data[i : i + _BLOCK], self._alg.key)
            for i in range(0, len(data), _BLOCK)
        )


class _ECBDec(_Ctx):
    def _process(self, data: bytes) -> bytes:
        return b"".join(
            aes_decrypt_block(data[i : i + _BLOCK], self._alg.key)
            for i in range(0, len(data), _BLOCK)
        )


class _CBCEnc(_Ctx):
    def _process(self, data: bytes) -> bytes:
        prev = self._mode.initialization_vector
        out = []
        for i in range(0, len(data), _BLOCK):
            blk = bytes(a ^ b for a, b in zip(data[i : i + _BLOCK], prev))
            prev = aes_encrypt_block(blk, self._alg.key)
            out.append(prev)
        return b"".join(out)


class _CBCDec(_Ctx):
    def _process(self, data: bytes) -> bytes:
        prev = self._mode.initialization_vector
        out = []
        for i in range(0, len(data), _BLOCK):
            c = data[i : i + _BLOCK]
            dec = aes_decrypt_block(c, self._alg.key)
            out.append(bytes(a ^ b for a, b in zip(dec, prev)))
            prev = c
        return b"".join(out)


class Cipher:
    def __init__(self, algorithm, mode):
        if not isinstance(algorithm, algorithms.AES):
            raise TypeError("本垫片只支持 algorithms.AES")
        if not isinstance(mode, (modes.ECB, modes.CBC)):
            raise TypeError("本垫片只支持 modes.ECB / modes.CBC")
        self.algorithm = algorithm
        self.mode = mode

    def encryptor(self) -> _Ctx:
        return _CBCEnc(self.algorithm, self.mode) if isinstance(self.mode, modes.CBC) \
            else _ECBEnc(self.algorithm, self.mode)

    def decryptor(self) -> _Ctx:
        return _CBCDec(self.algorithm, self.mode) if isinstance(self.mode, modes.CBC) \
            else _ECBDec(self.algorithm, self.mode)
