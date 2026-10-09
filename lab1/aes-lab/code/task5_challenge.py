"""任务五【挑战题】：把攻击做到极致。

挑战 1：一次改**多个**字段，消息仍然通顺。
挑战 2：从**至少 3 条**不同消息里各取分组，拼出一条**从来没有存在过**的消息。

拼装本身只用 block_utils —— 不需要密钥。
本文件 import ecb_common **只是为了把结果显示给你看**（扮演 Bob 解密）。
真正的攻击工具是 task4_forge.py，那个文件确实不碰密钥。

用法：
    python task5_challenge.py
"""

from __future__ import annotations

from block_utils import from_blocks, to_blocks
from ecb_common import DEMO_KEY, ecb_decrypt, load_history, pretty_aligned

SEP = "=" * 68
FIELDS = ["From", "To", "Date", "Place"]
KEYNAME = {"From": "sender", "To": "to", "Date": "date", "Place": "place"}


def section(title: str) -> None:
    print()
    print(SEP)
    print(title)
    print(SEP)


def build(history: list[dict], recipe: list[tuple[str, int]]) -> bytes:
    """recipe: [(消息编号, 分组下标), ...]"""
    index = {m["id"]: m for m in history}
    blocks = []
    for mid, idx in recipe:
        blocks.append(to_blocks(bytes.fromhex(index[mid]["ciphertext_hex"]))[idx])
    return from_blocks(blocks)


def report(history: list[dict], recipe: list[tuple[str, int]], title: str) -> None:
    index = {m["id"]: m for m in history}
    forged = build(history, recipe)

    print(title)
    print()
    print("取块配方：")
    for i, (mid, idx) in enumerate(recipe):
        m = index[mid]
        field = FIELDS[idx]
        value = m[KEYNAME[field]]
        print(f"  分组{i} <- {mid}.分组{idx}   （{field} = {value}）")
    print()
    print(f"伪造密文：{forged.hex()}")
    print()

    try:
        plain = ecb_decrypt(DEMO_KEY, forged)
    except Exception as e:
        print(f"解密失败（填充校验不过）：{type(e).__name__}: {e}")
        return

    print("Bob 解密后看到：")
    print("-" * 60)
    print(pretty_aligned(plain))
    print("-" * 60)

    # 逐字段核对来源
    print()
    print("字段溯源：")
    for i, (mid, idx) in enumerate(recipe):
        m = index[mid]
        field = FIELDS[idx]
        print(f"  {field:<6} = {m[KEYNAME[field]]:<12} 来自 {mid}")
    print()
    print("这条消息**没有任何人发送过** —— 它是四个分组的拼装件，")
    print("但格式完整、语义自洽、解密不报错。")


def main() -> None:
    history = load_history()

    # =======================================================================
    section("历史密文库")
    # =======================================================================
    print(f"{'编号':<6}{'发件人':<8}{'收件人':<8}{'日期':<13}{'地点':<10}")
    print("-" * 50)
    for m in history:
        print(f"{m['id']:<6}{m['sender']:<8}{m['to']:<8}{m['date']:<13}{m['place']:<10}")

    # =======================================================================
    section("挑战 1：一次改多个字段")
    # =======================================================================
    print("目标：把 M1（Alice -> Bob, 03-15, Library）改成")
    print("      「Carol 在 03-22 通知 Bob 去 Gym」。")
    print()
    report(
        history,
        [("M4", 0), ("M1", 1), ("M3", 2), ("M2", 3)],
        ">>> 一次改掉发件人、日期、地点三个字段",
    )

    # =======================================================================
    section("挑战 2：用至少 3 条消息的密文块拼一条全新消息")
    # =======================================================================
    print("要求分组来自 >= 3 条不同消息。下面这条来自 4 条不同消息：")
    print()
    report(
        history,
        [("M5", 0), ("M6", 1), ("M3", 2), ("M2", 3)],
        ">>> 四个分组，四条不同的来源消息",
    )

    # =======================================================================
    section("思考：为什么格式化反而帮了攻击者？")
    # =======================================================================
    print("「每个字段占一个分组」本来是**程序员的善意** ——")
    print("解析简单、不用处理变长字段、不容易出 bug。")
    print()
    print("但在 ECB 下，这个善意直接把消息变成了**一盒可以随意调换的乐高积木**。")
    print("分组边界 = 字段边界，攻击者连猜都不用猜，");
    print("每一条历史密文都成了一个「字段素材库」，供他随时取用。")
    print()
    print("这就是安全设计里反复出现的一件事：")
    print("**局部看起来最合理的选择，放在整体里可能是最危险的。**")
    print()
    print(SEP)


if __name__ == "__main__":
    main()
