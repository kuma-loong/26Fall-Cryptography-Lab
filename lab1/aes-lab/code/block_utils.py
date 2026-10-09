"""分组工具：只做字节搬运，不含任何密钥、不含任何加解密。

【为什么单独一个文件】
本实验的主角是 Mallory —— 一个**没有密钥**的攻击者。
Mallory 的全部本事就是「把 16 字节的块搬来搬去」。
所以描述 Mallory 的那个程序（task4_forge.py）只允许 import 这个文件。

这个文件里没有任何 import cryptography 的语句，也没有 KEY 这个变量。
可以自己确认这一点 —— 这正是「不需要密钥也能伪造」的字面含义。
"""

from __future__ import annotations

BLOCK_SIZE = 16


def to_blocks(data: bytes) -> list[bytes]:
    """把字节串切成 16 字节的分组列表。"""
    if len(data) % BLOCK_SIZE:
        raise ValueError(f"数据长度 {len(data)} 不是 {BLOCK_SIZE} 的整数倍")
    return [data[i : i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]


def from_blocks(blocks: list[bytes]) -> bytes:
    """把分组列表拼回字节串。"""
    for b in blocks:
        if len(b) != BLOCK_SIZE:
            raise ValueError(f"分组长度必须是 {BLOCK_SIZE}，收到 {len(b)}")
    return b"".join(blocks)


def hexdump(data: bytes, indent: str = "    ") -> str:
    """逐分组打印十六进制与对应的可读字符。"""
    lines = []
    for i, blk in enumerate(to_blocks(data)):
        ascii_part = "".join(chr(x) if 32 <= x < 127 else "·" for x in blk)
        lines.append(f"{indent}分组{i:>2}: {blk.hex()}  |{ascii_part}|")
    return "\n".join(lines)


def describe_block(block: bytes) -> str:
    """给出单个分组的可读形式。"""
    return "".join(chr(x) if 32 <= x < 127 else "·" for x in block)


def blocks_equal(a: bytes, b: bytes) -> bool:
    return a == b
