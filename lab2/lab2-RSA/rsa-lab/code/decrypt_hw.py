"""任务四的黑盒：文件容器 + AES + PKCS#1 解码函数。

【这份「黑盒」里有什么，没有什么】
有（这些与攻击无关，属于「解密那一层」）：
    load_container()     解开 base64 / MPI 长度前缀 / 切出 IV 与密文体
    pkcs1v15_decode()    剥掉 RSA 的 EME-PKCS1-v1_5 填充
    aes_cbc_decrypt()    AES-256-CBC 解密
    unpad()              去掉 PKCS#7 填充

**没有**（这些是**你自己的攻击**的收尾，要你自己写）：
    用**你算出来的** d 做那一次模幂 `pow(c, d, n)`，
    再用 e 把**整块 EM** 加密回去确认它就是 c。

    ⚠ 确认的是整块 EM（`pow(os2ip(em), e, n) == c`），
      不是剥完填充的会话密钥 —— 填充在 RSA 块**内部**，
      拿会话密钥去加密对正确的私钥也恒为 False。

所以你需要在 `task4_decrypt.py` 里写的只有 4~6 行。
这 4 行是整场攻击唯一的情绪落点 —— 那份 PDF 是**你**打开的。

【--auto 是兜底】
如果卡住了，`python decrypt_hw.py --auto` 会读你的 `weak_devices.json`，
逐个私钥试过去，报告哪一把能用。它用的仍然是**你自己恢复的私钥**，
不会替你作弊。

用法：
    python decrypt_hw.py                    # 显示黑盒说明
    python decrypt_hw.py --auto             # 兜底：用 weak_devices.json 里的私钥试
    python decrypt_hw.py -k <设备号>         # 指定用哪台设备的私钥（哪台自己试）
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from aes_soft import cbc_decrypt
from pbp_common import parse_pbp
from rsa_common import (
    DATA,
    DASH,
    byte_len,
    i2osp,
    pkcs1v15_decode,
    section,
)

BLOCK = 16


# ---------------------------------------------------------------------------
# 容器
# ---------------------------------------------------------------------------


def load_container(path: Path | str) -> tuple[int, bytes, bytes]:
    """把 PBP 文件拆成 (RSA 密文整数 c, IV, AES 密文体)。

    这就是「RSA 密文、IV、AES 密文体」三段结构里，你需要的第一段。
    剩下的 base64、MPI 长度前缀、字节切片都由这个函数做完。
    """
    info = parse_pbp(path)
    return int(info["rsa_ct"]), bytes(info["iv"]), bytes(info["body"])


# ---------------------------------------------------------------------------
# 填充
# ---------------------------------------------------------------------------


def unpad(data: bytes, block: int = BLOCK) -> bytes:
    """去掉 PKCS#7 填充。填充非法时抛 ValueError。"""
    if not data or len(data) % block:
        raise ValueError("数据长度不是分组长度的整数倍")
    n = data[-1]
    if n == 0 or n > block:
        raise ValueError(f"填充字节非法：0x{n:02x}")
    if data[-n:] != bytes([n]) * n:
        raise ValueError(f"填充字节非法：末尾 {n} 字节不全是 0x{n:02x}")
    return data[:-n]


def aes_cbc_decrypt(session_key: bytes, iv: bytes, body: bytes) -> bytes:
    """AES-256-CBC 解密，并去掉 PKCS#7 填充。"""
    if len(session_key) != 32:
        raise ValueError(
            f"会话密钥应为 32 字节（AES-256），实际 {len(session_key)} 字节。"
            f"是不是 PKCS#1 解码那一步没做对？"
        )
    return unpad(cbc_decrypt(session_key, iv, body))


# ---------------------------------------------------------------------------
# 兜底：拿你自己的私钥逐个试
# ---------------------------------------------------------------------------


def try_keys(container_path: Path, keys_json: Path) -> int:
    """用 weak_devices.json 里的每一把私钥试解，报告哪一把能用。

    返回那把私钥所属的设备号；都失败则返回 -1。
    """
    import json

    c, iv, body = load_container(container_path)
    data = json.loads(keys_json.read_text(encoding="utf-8"))

    section("兜底模式：用 weak_devices.json 里的私钥逐个试")
    print(f"RSA 密文   : {c.bit_length()} 位")
    print(f"IV         : {iv.hex()}")
    print(f"AES 密文体 : {len(body):,} 字节")
    print()

    for dev in sorted(data.get("keys", {}), key=lambda s: int(s)):
        k = data["keys"][dev]
        n = int(k["n"], 16)
        d = int(k["d"], 16)
        if c >= n:
            print(f"  设备 {dev:>4} : 密文比模数大，跳过")
            continue
        try:
            em = i2osp(pow(c, d, n), byte_len(n))
            session_key = pkcs1v15_decode(em)
        except ValueError:
            print(f"  设备 {dev:>4} : PKCS#1 解码失败（这把钥匙不对）")
            continue
        try:
            plain = aes_cbc_decrypt(session_key, iv, body)
        except ValueError as exc:
            print(f"  设备 {dev:>4} : AES 解密失败（{exc}）")
            continue

        print(f"  设备 {dev:>4} : ✓ 成功")
        print()
        print(DASH)
        print(f"使用设备 #{dev} 的私钥解开。")
        print(DASH)
        out = container_path.parent / "homework.pdf"
        out.write_bytes(plain)
        print(f"已写出：{out}  ({len(plain):,} 字节)")
        import hashlib
        print(f"SHA-256：{hashlib.sha256(plain).hexdigest()}")
        return int(dev)

    print()
    print("没有一把私钥能解开。可能的原因：")
    print("  · weak_devices.json 里的 d 算错了（跑 python verify.py 查）")
    print("  · 你漏掉了收件方那台设备（收件方就在可分解的那几台里面）")
    return -1


def main() -> None:
    ap = argparse.ArgumentParser(description="任务四的黑盒：PBP 解码与 AES")
    ap.add_argument("-i", "--input", type=Path,
                    default=DATA / "homework.pdf.enc.asc")
    ap.add_argument("-k", "--keys", type=Path,
                    default=DATA / "weak_devices.json")
    ap.add_argument("--auto", action="store_true",
                    help="兜底：用 weak_devices.json 里的私钥逐个试")
    ap.add_argument("--info", action="store_true", help="只打印容器结构")
    args = ap.parse_args()

    if args.info:
        c, iv, body = load_container(args.input)
        section("容器结构")
        print(f"RSA 密文       : {c.bit_length()} 位（{byte_len(c)} 字节）")
        print(f"IV             : {iv.hex()}")
        print(f"AES 密文体     : {len(body):,} 字节（{len(body) // BLOCK} 个分组）")
        return

    if args.auto:
        sys.exit(0 if try_keys(args.input, args.keys) >= 0 else 1)

    section("任务四的黑盒")
    print("本模块提供（与攻击无关的部分）：")
    print("    load_container(path)            -> (RSA 密文 c, IV, AES 密文体)")
    print("    pkcs1v15_decode(em)             -> 会话密钥")
    print("    aes_cbc_decrypt(key, iv, body)  -> 明文")
    print("    unpad(data)                     -> 去掉 PKCS#7 填充")
    print()
    print("你要写的（属于你自己那次攻击的收尾）：")
    print("    用你自己算出的 d，做一次 pow(c, d, n)")
    print("    然后用 e 把整块 EM 加密回去，确认就是 c")
    print("    （是整块 EM，不是剥完填充的会话密钥 —— 填充在块内部）")
    print()
    print("打开 code/task4_decrypt.py 开始。")
    print()
    print("卡住了就 python decrypt_hw.py --auto —— 它用你自己恢复的私钥兜底。")


if __name__ == "__main__":
    main()
