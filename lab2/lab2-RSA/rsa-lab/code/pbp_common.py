"""PBP（Pretty Bad Privacy）文件格式的解析器。只读，不提供加密。

PBP 是一个教学用的加密工具：它把一份文件加密给某把 RSA 公钥。
任务四要把它解开，拿回里面那份作业 PDF。

【本文件是「黑盒」的一部分】
拆容器这件事（base64、MPI 长度前缀、切 IV、切 AES 密文体）与密码学攻击
本身无关，所以直接给你。你要自己写的是**真正属于这次攻击的那几行** ——
取出 RSA 密文整数，用你自己算出来的私钥做一次模幂。

【线上格式】
    -----BEGIN PRETTY BAD ENCRYPTED MESSAGE-----
    <base64 正文>
    -----END PRETTY BAD ENCRYPTED MESSAGE-----

base64 解出来的正文是三段首尾相接的字节：

    ┌────────────────────┬──────────┬─────────────────────────────┐
    │ MPI(RSA 密文)      │ IV       │ AES-256-CBC 密文体          │
    │ 4 字节小端长度 +   │ 16 字节  │ 长度是 16 的整数倍          │
    │ 大端整数           │          │                             │
    └────────────────────┴──────────┴─────────────────────────────┘

其中 RSA 密文是「用接收方的 RSA 公钥、按 PKCS#1 v1.5 加密的 256-bit
AES 会话密钥」；AES 密文体是「用那个会话密钥加密的、带 PKCS#7 填充的
原文件」。

【MPI 是什么】
SSH 协议里的一个老约定：先把长度按**小端**写 4 个字节，再跟上一个
**大端**的整数。两端字节序不一致，是当年为省几个字节留下的历史包袱。
本实验用的文件长度大概率是 128（1024-bit 模数），但注意它记录的
是**实际用到的字节数**，不是模数的字节数。

用法：
    python pbp_common.py            # 跑自校验
    python pbp_common.py 密文文件    # 解析并打印结构，做人工核对
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path

from rsa_common import DATA, section

PBP_HEADER = "-----BEGIN PRETTY BAD ENCRYPTED MESSAGE-----"
PBP_FOOTER = "-----END PRETTY BAD ENCRYPTED MESSAGE-----"

IV_LEN = 16


# ---------------------------------------------------------------------------
# MPI
# ---------------------------------------------------------------------------


def mpi_decode(raw: bytes) -> tuple[int, bytes]:
    """解一个 SSH 风格的 MPI。返回 (整数值, 剩余字节)。

    长度前缀是 4 字节**小端**，整数本身是**大端**。
    """
    if len(raw) < 4:
        raise ValueError(f"MPI 太短：只剩 {len(raw)} 字节，连 4 字节长度前缀都不够")
    n = int.from_bytes(raw[:4], "little")
    if len(raw) < 4 + n:
        raise ValueError(
            f"MPI 长度前缀说有 {n} 字节，但后面只剩 {len(raw) - 4} 字节"
        )
    return int.from_bytes(raw[4 : 4 + n], "big"), raw[4 + n :]


def mpi_encode(z: int) -> bytes:
    """把一个整数编成 MPI。本模块只读，但自校验需要它造测试数据。"""
    body = z.to_bytes((z.bit_length() + 7) // 8, "big")
    return len(body).to_bytes(4, "little") + body


# ---------------------------------------------------------------------------
# 读文件
# ---------------------------------------------------------------------------


def read_pbp_text(path: Path | str) -> str:
    """读入 PBP 文件的文本，并检查头尾标记。返回 base64 正文。"""
    path = Path(path)
    text = path.read_text(encoding="ascii")
    lines = text.splitlines()

    if not lines or lines[0].strip() != PBP_HEADER:
        got = lines[0].strip() if lines else "（空文件）"
        raise ValueError(f"{path} 的开头不是 PBP 头标记，实际是：{got}")
    if lines[-1].strip() != PBP_FOOTER:
        got = lines[-1].strip() if lines else "（空文件）"
        raise ValueError(f"{path} 的结尾不是 PBP 尾标记，实际是：{got}")

    body = "\n".join(lines[1:-1])
    if not body.strip():
        raise ValueError(f"{path} 的头尾标记之间没有内容")
    return body


def parse_pbp(path: Path | str) -> dict[str, object]:
    """把一个 PBP 文件完整拆开。

    返回一个字典：
        rsa_ct      RSA 密文，整数
        rsa_ct_len  MPI 长度前缀里写的字节数
        iv          AES-CBC 的初始向量，16 字节
        body        AES 密文体（已被 PKCS#7 填充，长度是 16 的整数倍）
        blob        base64 解出来的完整字节串（调试用）
    """
    b64 = read_pbp_text(path)
    # 先把换行空白全去掉再解。注意不能直接开 validate=True —— 那个开关
    # 会把换行符也算作非法字符，而 PBP 正文本来就是折行的。
    try:
        blob = base64.b64decode("".join(b64.split()), validate=True)
    except ValueError as exc:
        raise ValueError(f"{path} 的 base64 正文解不开：{exc}") from None

    rsa_ct, rest = mpi_decode(blob)
    rsa_ct_len = len(blob) - len(rest) - 4

    if len(rest) < IV_LEN:
        raise ValueError(
            f"MPI 之后只剩 {len(rest)} 字节，装不下 {IV_LEN} 字节的 IV"
        )
    iv, body = rest[:IV_LEN], rest[IV_LEN:]

    if not body:
        raise ValueError("IV 之后没有 AES 密文体")
    if len(body) % 16:
        raise ValueError(f"AES 密文体长度 {len(body)} 不是 16 的整数倍")

    return {
        "rsa_ct": rsa_ct,
        "rsa_ct_len": rsa_ct_len,
        "iv": iv,
        "body": body,
        "blob": blob,
    }


# ---------------------------------------------------------------------------
# 自校验
# ---------------------------------------------------------------------------


def _self_test() -> bool:
    ok = True
    section("pbp_common 自校验")

    # 1. MPI 往返，含几个边界
    cases = [0, 1, 0xFF, 0x100, 2**1024 - 1]
    rt = all(mpi_decode(mpi_encode(z)) == (z, b"") for z in cases)
    print(f"1. MPI 编解码往返（0 / 1 / 255 / 256 / 2^1024-1）   "
          f"{'通过' if rt else '失败'}")
    ok &= rt

    # 2. MPI 长度前缀是小端：长度 258 应该编成 02 01 00 00
    enc = mpi_encode(int.from_bytes(b"\x01" * 258, "big"))
    le_ok = enc[:4] == b"\x02\x01\x00\x00"
    print(f"2. 长度前缀确实是小端（258 -> 02 01 00 00）   "
          f"{'通过' if le_ok else '失败（实际 ' + enc[:4].hex() + '）'}")
    ok &= le_ok

    # 3. 残缺的 MPI 必须报错，而不是悄悄返回错的值
    bad = 0
    for raw in (b"", b"\x01\x02", b"\x05\x00\x00\x00\xaa"):   # 太短 / 长度不够
        try:
            mpi_decode(raw)
        except ValueError:
            bad += 1
    mpi_ok = bad == 3
    print(f"3. 残缺 MPI 全部被拒（{bad}/3）   {'通过' if mpi_ok else '失败'}")
    ok &= mpi_ok

    # 4. 真实文件的结构
    target = DATA / "homework.pdf.enc.asc"
    if not target.is_file():
        print(f"4. 跳过：找不到 {target}")
    else:
        info = parse_pbp(target)
        ct_len, body_len = info["rsa_ct_len"], len(info["body"])
        print(f"4. 解析 {target.name}")
        print(f"     MPI 长度前缀    : {ct_len} 字节")
        print(f"     IV              : {info['iv'].hex()}")
        print(f"     AES 密文体      : {body_len:,} 字节"
              f"（{body_len // 16:,} 个分组）")
        print(f"     合计            : {len(info['blob']):,} 字节")
        struct_ok = (
            ct_len in (127, 128)          # 1024-bit 模数，1023/1024 位都合法
            and info["rsa_ct"] < 2**1024
            and body_len % 16 == 0
        )
        print(f"     结构自洽        : {'通过' if struct_ok else '失败'}")
        ok &= struct_ok

    return ok


def main() -> None:
    if len(sys.argv) > 1:
        path = Path(sys.argv[1])
        info = parse_pbp(path)
        section(f"{path}")
        print(f"RSA 密文      : {hex(info['rsa_ct'])[:50]}…"
              f"（{info['rsa_ct'].bit_length()} 位）")
        print(f"MPI 长度前缀  : {info['rsa_ct_len']} 字节")
        print(f"IV            : {info['iv'].hex()}")
        print(f"AES 密文体    : {len(info['body']):,} 字节")
        print(f"解出的总字节  : {len(info['blob']):,}")
        return

    passed = _self_test()
    print()
    if passed:
        print("全部通过：PBP 解析器可用于任务四。")
    else:
        print("存在失败项。")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
