"""垫片内部的 AES 单块加解密：复用 tools/aes_ref.py。

垫片目录可能被以任何方式放到 PYTHONPATH 上，所以这里按相对路径把
tools/ 加进 sys.path 再 import。
"""

from __future__ import annotations

import sys
from pathlib import Path


def _find_tools_dir() -> Path:
    """从当前文件往上找，定位放有 aes_ref.py 的 tools/ 目录。"""
    for parent in Path(__file__).resolve().parents:
        if (parent / "aes_ref.py").is_file():
            return parent
    raise RuntimeError("找不到 tools/aes_ref.py，垫片无法定位 AES 内核")


_TOOLS = _find_tools_dir()
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from aes_ref import _expand_key, decrypt_block, encrypt_block  # noqa: E402

__all__ = ["aes_encrypt_block", "aes_decrypt_block"]


def aes_encrypt_block(block: bytes, key: bytes) -> bytes:
    return encrypt_block(block, _expand_key(key))


def aes_decrypt_block(block: bytes, key: bytes) -> bytes:
    return decrypt_block(block, _expand_key(key))
