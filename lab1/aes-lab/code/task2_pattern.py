"""任务二：ECB 的模式泄露 —— 不解密就能看出来的事。

ECB 是**确定性**加密：同样的明文分组，永远得到同样的密文分组。
所以攻击者不需要密钥，只要把密文分组横向比一比，就能看出
「哪几条消息是同一个人发的」「哪几条是同一天」。

注意：这一关仍然**没有用到任何加解密函数**，纯粹在用眼睛比对密文。

用法：
    python task2_pattern.py
"""

from __future__ import annotations

from collections import defaultdict

from block_utils import describe_block, to_blocks
from ecb_common import load_history

SEP = "=" * 72
FIELDS = ["分组0 (From)", "分组1 (To)", "分组2 (Date)", "分组3 (Place)"]


def section(title: str) -> None:
    print()
    print(SEP)
    print(title)
    print(SEP)


def main() -> None:
    history = load_history()

    # ---- 1. 列出密文分组 --------------------------------------------------
    section("1. 历史密文库：每条消息切成 4 个密文分组")
    print(f"{'消息':<5}{'发件人':<8}{'收件人':<8}{'日期':<13}{'地点':<10}")
    print("-" * SEP.__len__())
    for m in history:
        print(f"{m['id']:<5}{m['sender']:<8}{m['to']:<8}{m['date']:<13}{m['place']:<10}")

    print()
    print("密文分组（十六进制）：")
    for m in history:
        blocks = to_blocks(bytes.fromhex(m["ciphertext_hex"]))
        print(f"  {m['id']}: " + "  ".join(b.hex()[:16] + "..." for b in blocks))

    # ---- 2. 逐分组找重复 --------------------------------------------------
    section("2. 相同的密文分组 —— 泄露了什么？")
    leaks = {
        0: ("发件人", lambda m: m["sender"]),
        1: ("收件人", lambda m: m["to"]),
        2: ("日期", lambda m: m["date"]),
        3: ("地点", lambda m: m["place"]),
    }

    for idx in range(4):
        label, getter = leaks[idx]
        buckets: dict[bytes, list[str]] = defaultdict(list)
        for m in history:
            blk = to_blocks(bytes.fromhex(m["ciphertext_hex"]))[idx]
            buckets[blk].append(m["id"])

        print()
        print(f"【{FIELDS[idx]}】不同的密文分组共 {len(buckets)} 种")
        if len(buckets) == len(history):
            print("  （本组没有重复）")
            continue
        print(f"  {'密文分组':<36}{'出现的消息':<18}{'共同的' + label}")
        print("  " + "-" * 68)
        for blk, ids in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
            if len(ids) > 1:
                common = {getter(m) for m in history if m["id"] in ids}
                print(f"  {blk.hex():<36}{', '.join(ids):<18}{'/'.join(sorted(common))}")

    # ---- 3. 把结论说白 ----------------------------------------------------
    section("3. 攻击者由此知道了什么")
    print("Mallory 手上只有密文，没有密钥。但把分组一比，他就能确定：")
    print()
    print("  · M1 / M2 / M3 / M6 这四条的发件人分组完全相同 -> 同一个人发的；")
    print("  · M1 / M2 / M3 的收件人分组相同                -> 同一个收件人；")
    print("  · M1 / M2 / M4 / M6 的日期分组相同              -> 同一天；")
    print("  · M1 / M3 / M6 的地点分组相同                   -> 同一个地点。")
    print()
    print("而且他还能进一步推断：M1 和 M2 只在**最后一个分组**上不同，")
    print("说明这两条消息只有地点不一样，其余完全相同。")
    print()
    print("这类信息叫「模式泄露」。它不涉及破解 AES —— 密钥依然是安全的，")
    print("但**消息的结构**已经摆在明面上了。")
    print()
    print(SEP)
    print("任务二结论：ECB 是确定性的，确定性就是可比较性，")
    print("           可比较性就是信息泄露。")
    print(SEP)


if __name__ == "__main__":
    main()
