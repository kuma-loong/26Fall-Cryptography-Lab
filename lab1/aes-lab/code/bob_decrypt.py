"""Bob 的解密程序 —— 扮演**收到密文的接收方**。

用法：
    python bob_decrypt.py                      解密 data/message.ct
    python bob_decrypt.py -i data/forged.ct    解密指定文件

它会解密并打印明文。如果密文被改坏（填充校验不过），会如实报错。

⚠️ 只有 Bob 有密钥。Mallory 的伪造程序（task4_forge.py）不 import 本文件。
   Bob 看到的明文会「像模像样」，是因为 ECB 不提供任何完整性保护 ——
   解密程序根本不知道这条密文是不是原装的。
"""

from __future__ import annotations

import argparse
from pathlib import Path

from ecb_common import DATA_DIR, DEMO_KEY, ecb_decrypt, parse_aligned, pretty_aligned


def main() -> None:
    ap = argparse.ArgumentParser(description="Bob 的解密程序（AES-ECB）")
    ap.add_argument("-i", "--in", dest="infile", default=None, help="密文文件（默认 data/message.ct）")
    ap.add_argument("--hex-out", action="store_true", help="同时打印明文的十六进制")
    args = ap.parse_args()

    path = Path(args.infile) if args.infile else DATA_DIR / "message.ct"
    if not path.exists():
        raise SystemExit(f"找不到 {path}\n请先用 alice_encrypt.py 生成密文。")

    cipher = bytes.fromhex(path.read_text(encoding="utf-8").strip())

    print("=" * 60)
    print(f"Bob 收到密文：{path}")
    print(f"长度 {len(cipher)} 字节 = {len(cipher) // 16} 个分组")
    print("=" * 60)

    try:
        plain = ecb_decrypt(DEMO_KEY, cipher)
    except Exception as e:
        print()
        print(f"解密失败：{type(e).__name__}: {e}")
        print()
        print("这通常意味着密文被改动过，填充校验不通过。")
        return

    print()
    print("解密结果：")
    print("-" * 60)
    try:
        print(pretty_aligned(plain))
    except Exception:
        print(plain.decode("latin-1"))
    print("-" * 60)

    if args.hex_out:
        print()
        print("明文十六进制：")
        print(plain.hex())

    # 顺带把字段解析出来，方便对照
    try:
        fields = parse_aligned(plain)
        print()
        print("字段解析：")
        for k, v in fields.items():
            print(f"  {k:<8} = {v}")
    except Exception:
        pass

    print()
    print("⚠️ Bob 无法判断这条密文是不是原装的 —— ECB 没有任何完整性保护。")


if __name__ == "__main__":
    main()
