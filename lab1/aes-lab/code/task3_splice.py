"""任务三：第一次搬运分组 —— 以及为什么它一开始不成功。

这是全实验最关键的一关。你会看到：
  · 格式 A（自然写法）下，搬运分组的结果「读起来不对劲」；
  · 原因不是 AES 太强，而是**字段边界和分组边界没有对齐**；
  · 改成格式 B（定长对齐）之后，同样的搬运立刻变得干净利落。

⚠️ 搬运分组只用 block_utils。解密那一步只是为了让你看到结果 ——
   真实攻击里解密是 Bob 做的，Mallory 看不到明文，也不需要看到。

用法：
    python task3_splice.py
"""

from __future__ import annotations

from block_utils import describe_block, from_blocks, to_blocks
from ecb_common import (
    DEMO_KEY,
    ecb_decrypt,
    ecb_encrypt,
    format_aligned,
    format_naive,
    pretty_aligned,
)

SEP = "=" * 64


def section(title: str) -> None:
    print()
    print(SEP)
    print(title)
    print(SEP)


def show_blocks(cipher: bytes, label: str) -> None:
    print(f"{label}（{len(cipher)} 字节 = {len(cipher)//16} 个分组）")
    for i, blk in enumerate(to_blocks(cipher)):
        print(f"  分组{i}: {blk.hex()}  |{describe_block(blk)}|")


def bob_says(cipher: bytes, aligned: bool = False) -> None:
    """模拟 Bob 解密并打印。"""
    try:
        plain = ecb_decrypt(DEMO_KEY, cipher)
    except Exception as e:
        print(f"  Bob 解密失败：{type(e).__name__}: {e}")
        return
    print("  Bob 看到：")
    print("  " + "-" * 56)
    text = pretty_aligned(plain) if aligned else plain.decode("latin-1")
    for line in text.split("\n"):
        print(f"  {line}")
    print("  " + "-" * 56)


def main() -> None:
    # =======================================================================
    section("准备：格式 A（自然写法）下加密两条消息")
    # =======================================================================
    a1 = format_naive("Alice", "Bob", "2026-03-15", "Library").encode("latin-1")
    a2 = format_naive("Alice", "Bob", "2026-03-15", "Gym").encode("latin-1")
    a3 = format_naive("Alice", "Bob", "2026-03-22", "Library").encode("latin-1")

    c1 = ecb_encrypt(DEMO_KEY, a1)
    c2 = ecb_encrypt(DEMO_KEY, a2)
    c3 = ecb_encrypt(DEMO_KEY, a3)

    print(f"M1 明文 {len(a1)} 字节：{a1.decode('latin-1')!r}")
    print(f"M2 明文 {len(a2)} 字节：{a2.decode('latin-1')!r}")
    print()
    print("两个长度**不一样**。先注意这一点，它等下会咬人。")
    print()
    show_blocks(c1, "M1 密文")
    print()
    show_blocks(c2, "M2 密文")

    # =======================================================================
    section("尝试 1：把 M2 的最后一个分组接到 M1 上")
    # =======================================================================
    print("按题目最直觉的做法：M1 的最后一个分组换成 M2 的最后一个分组。")
    print()
    b1, b2 = to_blocks(c1), to_blocks(c2)
    forged_1 = from_blocks(b1[:3] + [b2[-1]])
    print(f"M1 有 {len(b1)} 个分组，M2 有 {len(b2)} 个分组。")
    print(f"于是拼出来的是：{b1[0].hex()[:16]}... + {b1[1].hex()[:16]}... + "
          f"{b1[2].hex()[:16]}... + {b2[-1].hex()[:16]}...")
    print()
    bob_says(forged_1)
    print()
    print(">>> 结果确实「不太对劲」。地点变成了 `Libr3-15`，还多出一行 `Place: Gym`。")
    print(">>> 原因是：分组边界切在了地点字段的中间。")
    print("    M1 的第 3 分组装的是 `ary` 加填充，M2 的最后分组装的是")
    print("    `3-15\\nPlace: Gym` 加填充 —— 两者内容根本不是同一个字段。")

    # =======================================================================
    section("尝试 2：换成 M3 的分组 2（换日期）")
    # =======================================================================
    print("M1 和 M3 长度相同，只差日期。这次换的是分组 2。")
    print()
    b3 = to_blocks(c3)
    forged_2 = from_blocks(b1[:2] + [b3[2]] + b1[3:])
    bob_says(forged_2)
    print()
    print(">>> 这次成功了 —— 日期从 03-15 变成 03-22。")
    print(">>> 但注意：分组 2 里同时装着日期的尾巴和地点的开头，")
    print("    这次能对是因为两条消息的地点和长度都一样。运气成分太大。")

    # =======================================================================
    section("诊断：为什么时好时坏？")
    # =======================================================================
    print("把 M1 的明文按 16 字节切开看：")
    print()
    for i in range(0, len(a1), 16):
        blk = a1[i : i + 16]
        print(f"  分组{i//16}: |{describe_block(blk)}|")
    print()
    print("字段和分组是这样的关系（竖线是分组边界）：")
    print()
    print("  From: Alice\\nTo: | Bob\\nDate: 2026-0 | 3-15\\nPlace: Libr | ar(y)+填充")
    print("  ^^^^^ 发件人 ^^^^  ^^ 收件人 ^^^^^  ^^ 日期 ^^^^^  ^^^ 地点 ^^^")
    print()
    print("看出来了吗：**分组边界切在了字段的中间**。")
    print("「From: Alice」后面那个换行和「To:」被切到了下一组，")
    print("地点的前半截在第 3 组、后半截在第 4 组。")
    print()
    print("每个字段都被分组边界**从中间切断**了。所以任何一次搬运，")
    print("都会同时动到相邻的两个字段 —— 除非碰巧两条消息在切点两侧完全一样。")

    # =======================================================================
    section("修复：把消息格式改成定长对齐（格式 B）")
    # =======================================================================
    print("让每个字段**恰好占一个分组**：")
    print()
    print("  \"From: \" (6) + 名字(10)      = 16   <- 分组 0")
    print("  \"To: \"   (4) + 名字(12)      = 16   <- 分组 1")
    print("  \"Date: \" (6) + 日期(10)      = 16   <- 分组 2")
    print("  \"Place: \"(7) + 地点(8)       = 15   <- 分组 3（PKCS#7 再补 1 字节）")
    print()

    d1 = format_aligned("Alice", "Bob", "2026-03-15", "Library").encode("latin-1")
    d2 = format_aligned("Alice", "Bob", "2026-03-15", "Gym").encode("latin-1")
    e1 = ecb_encrypt(DEMO_KEY, d1)
    e2 = ecb_encrypt(DEMO_KEY, d2)

    print(f"明文长度：{len(d1)} 字节（+1 字节填充 = {len(e1)} 字节 = {len(e1)//16} 个分组）")
    print()
    for i in range(0, len(d1), 16):
        print(f"  分组{i//16}: |{describe_block(d1[i:i+16])}|")
    print()
    print("现在每个分组就是一个完整的字段。")
    print()
    show_blocks(e1, "M1 密文（格式 B）")
    print()
    show_blocks(e2, "M2 密文（格式 B）")
    print()
    print("看出来了吗：两条消息只在**分组 3** 不同，前三个分组一模一样。")

    # =======================================================================
    section("再试一次：把 M2 的分组 3 搬进 M1")
    # =======================================================================
    f1, f2 = to_blocks(e1), to_blocks(e2)
    forged_3 = from_blocks(f1[:3] + [f2[3]])
    print(f"取块配方：M1.分组0 + M1.分组1 + M1.分组2 + M2.分组3")
    print()
    print(f"伪造密文：{forged_3.hex()}")
    print()
    bob_says(forged_3, aligned=True)
    print()
    print(">>> 干净利落。地点从 Library 变成了 Gym，消息完全通顺，")
    print(">>> 而 Mallory 从头到尾**没有密钥**。")

    # =======================================================================
    section("任务三结论")
    # =======================================================================
    print("1. ECB 下密文分组是可以被当作积木搬运的；")
    print("2. 搬运能不能「看起来自然」，取决于**字段边界是否与分组边界对齐**；")
    print("3. 对齐本来是为了让程序好解析，却同时给攻击者递上了刀 ——")
    print("   这说明「消息格式」本身就是安全设计的一部分，不是无关的细节。")
    print()
    print("下一步：python task4_forge.py   （做成一个能交互的伪造工具）")


if __name__ == "__main__":
    main()
