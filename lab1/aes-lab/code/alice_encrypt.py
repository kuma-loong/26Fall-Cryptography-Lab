"""Alice 的加密程序 —— 扮演**有密钥的一方**。

用法：
    python alice_encrypt.py --build-history          建立历史密文库
    python alice_encrypt.py -s Alice -t Bob -d 2026-03-15 -p Library
                                                     加密一条新消息

它把明文加密成密文文件，写到 data/ 下。**输出里只有密文，没有密钥。**

对照实验：这个程序和 bob_decrypt.py 才持有密钥；
攻击者程序（task4_forge.py）不 import 本文件，也不 import ecb_common。
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from block_utils import hexdump
from ecb_common import (
    DATA_DIR,
    DEMO_KEY,
    ecb_encrypt,
    format_aligned,
    format_naive,
    save_history,
)


def main() -> None:
    ap = argparse.ArgumentParser(description="Alice 的加密程序（AES-ECB）")
    ap.add_argument("--build-history", action="store_true", help="建立历史密文库 data/history.json")
    ap.add_argument("--format", choices=["aligned", "naive"], default="aligned",
                    help="消息格式：aligned=定长对齐（默认），naive=自然写法")
    ap.add_argument("-s", "--sender", default=None)
    ap.add_argument("-t", "--to", default=None)
    ap.add_argument("-d", "--date", default=None)
    ap.add_argument("-p", "--place", default=None)
    ap.add_argument("-o", "--out", default=None, help="输出文件名（默认 data/message.ct）")
    args = ap.parse_args()

    if args.build_history:
        path = save_history(args.format)
        print(f"已生成历史密文库：{path}")
        print(f"格式：{args.format}")
        print(f"条数：6")
        print()
        print("文件里只有密文和公开的字段标注，**没有密钥**。")
        return

    if not all([args.sender, args.to, args.date, args.place]):
        ap.error("需要同时提供 -s -t -d -p，或者用 --build-history")

    maker = format_aligned if args.format == "aligned" else format_naive
    plain = maker(args.sender, args.to, args.date, args.place).encode("latin-1")
    cipher = ecb_encrypt(DEMO_KEY, plain)

    out = Path(args.out) if args.out else DATA_DIR / "message.ct"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(cipher.hex(), encoding="utf-8")

    print("=" * 60)
    print("明文")
    print("=" * 60)
    print(plain.decode("latin-1"))
    print()
    print(f"明文长度：{len(plain)} 字节")
    print("=" * 60)
    print("密文（AES-128-ECB）")
    print("=" * 60)
    print(hexdump(cipher))
    print()
    print(f"密文长度：{len(cipher)} 字节 = {len(cipher) // 16} 个分组")
    print(f"已写入：{out}")

    sidecar = out.with_suffix(".json")
    sidecar.write_text(
        json.dumps({"sender": args.sender, "to": args.to, "date": args.date,
                    "place": args.place, "format": args.format}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"字段标注（收件人侧留档）：{sidecar}")


if __name__ == "__main__":
    main()
