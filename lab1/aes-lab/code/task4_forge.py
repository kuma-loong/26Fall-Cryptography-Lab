"""任务四【主交付物】：交互式密文伪造工具。

Mallory 的程序。给它一条目标消息和一个字段，它从历史密文库里挑一个分组
搬过来，输出一条**新的密文**。全程不需要密钥。

用法：
    python task4_forge.py                                交互模式
    python task4_forge.py -t M1 -f Place -s M2           直接指定
    python task4_forge.py -t M1 -f Place -s M2 -o data/x.ct

⚠️ 脚本自检：本文件**只** import block_utils，不 import ecb_common。
   跑下面这行可以确认「没有密钥也能伪造」：
       python -c "import ast,sys; print([n.names[0].name for n in ast.walk(ast.parse(open('task4_forge.py',encoding='utf-8').read())) if isinstance(n, ast.ImportFrom)])"
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from block_utils import describe_block, from_blocks, to_blocks

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
HISTORY_FILE = DATA_DIR / "history.json"

# 四个字段分别在哪一个分组里。这是格式 B 的定义。
FIELD_TO_BLOCK = {"From": 0, "To": 1, "Date": 2, "Place": 3}
FIELD_LABEL = {"From": "发件人", "To": "收件人", "Date": "日期", "Place": "地点"}
FIELD_KEY = {"From": "sender", "To": "to", "Date": "date", "Place": "place"}

SEP = "=" * 68


def load_history() -> list[dict]:
    if not HISTORY_FILE.exists():
        raise SystemExit(
            f"找不到 {HISTORY_FILE}\n"
            f"请先运行：python alice_encrypt.py --build-history"
        )
    return json.loads(HISTORY_FILE.read_text(encoding="utf-8"))["messages"]


def blocks_of(msg: dict) -> list[bytes]:
    return to_blocks(bytes.fromhex(msg["ciphertext_hex"]))


def show_library(history: list[dict]) -> None:
    print(f"{'编号':<6}{'发件人':<8}{'收件人':<8}{'日期':<13}{'地点':<10}{'分组0(前8字节)'}")
    print("-" * 66)
    for m in history:
        b0 = blocks_of(m)[0].hex()[:16]
        print(f"{m['id']:<6}{m['sender']:<8}{m['to']:<8}{m['date']:<13}{m['place']:<10}{b0}")


def find(history: list[dict], mid: str) -> dict:
    for m in history:
        if m["id"] == mid:
            return m
    raise SystemExit(f"历史库里没有 {mid}（可选：{', '.join(m['id'] for m in history)}）")


def pick(prompt: str, options: list[str]) -> str:
    """简单的命令行选择器。

    接受的写法：完整编号（M1 / Place）、序号（从 1 起）、大小写变体。
    直接回车取第一个选项 —— 调用方会在提示里写明默认值是哪个。
    """
    while True:
        try:
            raw = input(prompt).strip()
        except EOFError:
            # 管道里没有输入了（比如 echo "M1" | python task4_forge.py 给少了）
            raise SystemExit("\n（输入结束，已退出）") from None

        if raw == "":
            return options[0]
        for opt in options:                      # 大小写不敏感
            if raw == opt or raw.lower() == opt.lower():
                return opt
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1]         # 允许只输序号

        print(f"  无效输入，请输入序号（1-{len(options)}）"
              f"或其中之一：{', '.join(options)}")


def forge(history: list[dict], target_id: str, field: str, source_id: str) -> tuple[bytes, str]:
    """核心：把 source 的对应分组搬到 target 上。"""
    target = find(history, target_id)
    source = find(history, source_id)

    idx = FIELD_TO_BLOCK[field]
    t_blocks = blocks_of(target)
    s_blocks = blocks_of(source)

    forged_blocks = list(t_blocks)
    forged_blocks[idx] = s_blocks[idx]
    forged = from_blocks(forged_blocks)

    recipe_lines = []
    for i, b in enumerate(forged_blocks):
        origin = source_id if i == idx else target_id
        mark = "  <-- 换掉了" if i == idx else ""
        recipe_lines.append(f"  分组{i}: {b.hex()}   来自 {origin}.分组{i}{mark}")

    return forged, "\n".join(recipe_lines)


def interactive(history: list[dict]) -> tuple[str, str, str]:
    print()
    print(SEP)
    print("Mallory 的密文伪造工具")
    print(SEP)
    print("手上只有这些密文，没有密钥。")
    print()
    show_library(history)

    print()
    target_id = pick(
        "\n[1/3] 要伪造哪一条消息？（输入编号如 M1，或序号 1；回车默认 M1）\n> ",
        [m["id"] for m in history],
    )

    print()
    field = pick(
        f"[2/3] 要改哪个字段？可选 From(发件人) / To(收件人) / Date(日期) / Place(地点)\n"
        f"      （回车默认 From）\n> ",
        list(FIELD_TO_BLOCK.keys()),
    )

    # 列出候选来源：把该字段分组和别人不一样的挑出来
    target = find(history, target_id)
    idx = FIELD_TO_BLOCK[field]
    t_blk = blocks_of(target)[idx]

    print()
    print(f"[3/3] 从哪一条消息里取「{FIELD_LABEL[field]}」这个分组？")
    print()
    print(f"      {'编号':<6}{'该字段的内容':<16}{'分组是否与目标不同'}")
    print("      " + "-" * 50)
    candidates = []
    for m in history:
        blk = blocks_of(m)[idx]
        same = (blk == t_blk)
        value = m[FIELD_KEY[field]]
        print(f"      {m['id']:<6}{value:<16}{'相同（换了等于没换）' if same else '不同'}")
        if not same:
            candidates.append(m["id"])

    if not candidates:
        raise SystemExit("没有任何一条消息在该字段上与目标不同，换个字段试试。")

    print()
    # 选项给全部消息（和上面表格一一对应），选到「相同」的再提示重选。
    # 如果只把 candidates 当选项，学生照着表格输 M3 会得到"无效输入" —— 明明表里有。
    while True:
        source_id = pick("> ", [m["id"] for m in history])
        if source_id in candidates:
            return target_id, field, source_id
        print(f"  {source_id} 在该字段上与目标相同，换了等于没换。"
              f"请从 {'、'.join(candidates)} 里选。")


def main() -> None:
    ap = argparse.ArgumentParser(description="Mallory 的密文伪造工具（不需要密钥）")
    ap.add_argument("-t", "--target", help="要伪造的消息编号，如 M1")
    ap.add_argument("-f", "--field", choices=list(FIELD_TO_BLOCK.keys()), help="要改的字段")
    ap.add_argument("-s", "--source", help="取块来源的消息编号，如 M2")
    ap.add_argument("-o", "--out", default=None, help="输出密文文件（默认 data/forged.ct）")
    args = ap.parse_args()

    history = load_history()

    if args.target and args.field and args.source:
        target_id, field, source_id = args.target, args.field, args.source
    else:
        target_id, field, source_id = interactive(history)

    target = find(history, target_id)
    source = find(history, source_id)

    forged, recipe = forge(history, target_id, field, source_id)

    print()
    print(SEP)
    print("伪造完成")
    print(SEP)
    print(f"目标消息 {target_id}：{target['sender']} -> {target['to']}  "
          f"{target['date']}  {target['place']}")
    print(f"取块来源 {source_id}：{source['sender']} -> {source['to']}  "
          f"{source['date']}  {source['place']}")
    print(f"改动的字段：{FIELD_LABEL[field]}（分组 {FIELD_TO_BLOCK[field]}）")
    print()
    print("取块配方：")
    print(recipe)
    print()
    print(f"伪造密文：{forged.hex()}")

    out = Path(args.out) if args.out else DATA_DIR / "forged.ct"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(forged.hex(), encoding="utf-8")

    print()
    print(f"已写入：{out}")
    print()
    print(SEP)
    print("现在**关掉这个程序**，让 Bob 去解密：")
    print(f"    python bob_decrypt.py -i {out}")
    print()
    print("注意：Mallory 到这里就下班了。他不知道解密结果长什么样 ——")
    print("      他也没必要知道。消息是谁伪造的，Bob 从密文上完全看不出来。")
    print(SEP)


if __name__ == "__main__":
    main()
