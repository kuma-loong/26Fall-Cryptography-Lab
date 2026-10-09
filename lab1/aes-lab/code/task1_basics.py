"""任务一：看清密文的分组结构。

这一关不攻击任何东西，只是把密文掰开看清楚。后面每一步攻击都建立在这里
建立的直觉上：**AES 是按 16 字节一块一块加密的。**

用法：
    python task1_basics.py
"""

from __future__ import annotations

from block_utils import describe_block, to_blocks
from ecb_common import (
    DEMO_KEY,
    ecb_decrypt,
    ecb_encrypt,
    format_aligned,
    format_naive,
)

SEP = "=" * 64


def section(title: str) -> None:
    print()
    print(SEP)
    print(title)
    print(SEP)


def main() -> None:
    sender, to, date, place = "Alice", "Bob", "2026-03-15", "Library"

    # ---- 1. 加密并打印十六进制 -------------------------------------------
    section("1. 加密一条消息，打印十六进制密文")
    plain_naive = format_naive(sender, to, date, place).encode("latin-1")
    cipher = ecb_encrypt(DEMO_KEY, plain_naive)
    print(f"明文：{plain_naive.decode('latin-1')!r}")
    print(f"明文长度：{len(plain_naive)} 字节")
    print()
    print(f"密文（hex）：{cipher.hex()}")
    print(f"密文长度：{len(cipher)} 字节")

    # ---- 2. 长度与分组数 --------------------------------------------------
    section("2. 密文长度、分组数、以及填充")
    n = len(cipher)
    print(f"hex 字符串长度：{len(cipher.hex())} 个字符（每字节 2 个字符）")
    print(f"密文字节数    ：{n}")
    print(f"分组数        ：{n // 16}")
    print()
    pad = n - len(plain_naive)
    print(f"明文 {len(plain_naive)} 字节 -> 密文 {n} 字节")
    print(f"其中 {pad} 字节是 PKCS#7 填充，用来把明文凑满 16 的整数倍。")
    print("思考：如果明文长度恰好是 16 的整数倍，会补多少？")

    # ---- 3. 切片：取出各个分组 -------------------------------------------
    section("3. 用切片取出每一个分组")
    blocks = to_blocks(cipher)
    for i, blk in enumerate(blocks):
        print(f"  第 {i} 个分组：[{i*16}:{(i+1)*16}]  {blk.hex()}  |{describe_block(blk)}|")
    print()
    print(f"第一个分组：cipher[0:16]   = {cipher[0:16].hex()}")
    print(f"最后一个分组：cipher[-16:] = {cipher[-16:].hex()}")

    # ---- 4. 换密钥看变化 --------------------------------------------------
    section("4. 改动一个字节，看密文怎么变")
    other_key = bytes([DEMO_KEY[0] ^ 0x01]) + DEMO_KEY[1:]
    cipher2 = ecb_encrypt(other_key, plain_naive)
    print(f"原密钥密文：{cipher.hex()}")
    print(f"改 1 位的密钥密文：{cipher2.hex()}")
    print()
    print("结论：密钥变 1 位，密文**整条**都变了 —— 解密结果无从预测。")
    print("      单看一个分组，AES 是足够强的。问题不在 AES，在工作模式。")

    # ---- 5. bytes 不可变 --------------------------------------------------
    section("5. bytes 是不可变的，bytearray 可以改")
    print(f"type(cipher) = {type(cipher)}")
    try:
        cipher[0] = 0x00
    except TypeError as e:
        print(f"尝试 cipher[0] = 0x00  ->  TypeError: {e}")
    print()
    print("所以「搬运分组」不能就地改，只能重新拼：")
    swapped = cipher[16:32] + cipher[0:16] + cipher[32:]
    print(f"  把第 0、1 分组交换位置 -> {swapped.hex()}")
    print()
    print("解密试试：")
    try:
        got = ecb_decrypt(DEMO_KEY, swapped)
        print(f"  {got.decode('latin-1')!r}")
        print()
        print("  -> 解密**没有报错**。ECB 里每个分组独立解密，换位置照样解得出来。")
        print("     这就是它能被搬运的根本原因。")
    except Exception as e:
        print(f"  {type(e).__name__}: {e}")

    print()
    print(SEP)
    print("任务一到此结束。记住这三件事：")
    print("  1. 密文 = 16 字节一组的方块，可以直接切片");
    print("  2. 分组之间彼此独立，换位置也能解密");
    print("  3. 变密钥 -> 整条变；换分组 -> 局部变。后者就是攻击的入口。")
    print(SEP)


if __name__ == "__main__":
    main()
