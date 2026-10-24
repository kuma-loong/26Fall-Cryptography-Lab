"""本实验用到的公共工具：读语料、进制转换、承诺值、PKCS#1 解码。

【这个文件里**故意没有**什么】
没有 `egcd`，没有 `modinv`，**也没有 `totient`**。这三个函数是
**任务一要你自己写的**，它们在 `task1_math.py` 里：
前两个是整个攻击链的收尾（把 e 变成 d），第三个（φ）是 d 的分母。

本文件只放「与攻击无关的杂活」：读文件、整数与字节串互转、
版本号样式。看懂看不懂都不影响你完成任务。

（唯一的例外是 `pkcs1v15_decode()`：它是任务四黑盒的一部分。
见它的 docstring。）

【零依赖】
本模块只用 Python 标准库。本实验包**不需要 pip install 任何东西** ——
连 AES 都是随包附带的一份纯标准库实现（`aes_soft.py`）。
"""

from __future__ import annotations

import hashlib
import math
import sys
import unicodedata
from pathlib import Path

# ---------------------------------------------------------------------------
# Windows 控制台编码
# ---------------------------------------------------------------------------
#
# 中文 Windows 的控制台默认是 GBK。本实验的输出里有 ² ≈ · 这类符号，
# GBK 编码不了，会直接抛 UnicodeEncodeError 把程序打断；
# 学生把输出重定向到文件时（python x.py > out.txt）更容易踩到。
#
# 在 import 时就统一切到 UTF-8。放在这里而不是各个入口脚本里，
# 是因为每个入口脚本都会 import 本模块 —— 一处生效，处处生效。

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# 路径与输出样式
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"

SEP = "=" * 64
DASH = "-" * 64


# ---------------------------------------------------------------------------
# 公开指数
# ---------------------------------------------------------------------------
#
# 【为什么它是一个显式常量，而不是在某个函数里现取】
# 任务二里你要做 d = modinv(e, φ(n))，任务三里要对每一台可分解的设备
# 重复这件事。如果 e 是凭空冒出来的（比如从某个黑盒里读出来的），
# 你就没法独立完成任务二 —— 你会一直在猜「这个数是哪来的」。
#
# 65537 = 2¹⁶ + 1，是**费马素数**。它几乎是所有真实 RSA 实现的默认值，
# 理由有三条，都写在《实验原理》里：
#   · 二进制是 10000000000000001，只有两个 1，模幂的乘法次数极少
#   · 足够大，不会被小指数攻击（e = 3 是有名的坑）
#   · 与任何偶数 φ(n) 都互素（它是奇数，且不是 φ 的因子）
PUBLIC_E = 65537


def section(title: str) -> None:
    """打印一条分节横幅，让长输出有骨架。"""
    print()
    print(SEP)
    print(title)
    print(SEP)


def display_width(s: str) -> int:
    """字符串在终端里占几格。

    汉字、全角标点在等宽字体下占**两格**，ASCII 占一格。想用
    f"{s:<20}" 对齐中文列是没用的 —— 那个对齐按字符个数算，
    而每个汉字的显示宽度是 2，列会歪掉。
    """
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)


def pad(s: str, width: int) -> str:
    """按**显示宽度**左对齐补空格。中文表格必须用它，不能用 :<N。"""
    return s + " " * max(0, width - display_width(s))


# ---------------------------------------------------------------------------
# 读取模数清单
# ---------------------------------------------------------------------------


def load_moduli(path: Path | str = DATA / "moduli.txt") -> list[int]:
    """读入模数清单，返回整数列表。**行号就是设备编号**。

    文件格式：一行一个十六进制模数，没有前缀、没有分隔符。
    这与真实世界的弱密钥语料（如 UCSD CSE 207B 用的那份）逐位对齐。

    空行与以 # 开头的注释行会被跳过；其余行必须能按十六进制解析。

    【别加长度校验】真实语料的行长**不统一**。本实验的合成语料里，
    1000 个模数的位长是 1023 和 1024 混排的，所以行长有 256 和 255 两种。
    如果你在这里加一句「每行必须 256 个字符」，程序会整体报错。
    """
    path = Path(path)
    out: list[int] = []
    for lineno, line in enumerate(path.read_text(encoding="ascii").splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        try:
            out.append(int(s, 16))
        except ValueError:
            raise ValueError(
                f"{path} 第 {lineno} 行不是合法的十六进制数：{s[:40]}"
            ) from None
    if not out:
        raise ValueError(f"{path} 里一个模数都没有")
    return out


# ---------------------------------------------------------------------------
# 整数 <-> 字节串。RFC 8017 管这两个叫 I2OSP / OS2IP
# ---------------------------------------------------------------------------


def i2osp(x: int, length: int) -> bytes:
    """Integer-to-Octet-String：整数转定长大端字节串。"""
    if x < 0:
        raise ValueError("I2OSP 只接受非负整数")
    if x >= 256**length:
        raise ValueError(f"整数太大，装不进 {length} 字节")
    return x.to_bytes(length, "big")


def os2ip(octets: bytes) -> int:
    """Octet-String-to-Integer：大端字节串转整数。"""
    return int.from_bytes(octets, "big")


def byte_len(n: int) -> int:
    """模数 n 占多少字节（就是 RFC 8017 里的 k）。"""
    return (n.bit_length() + 7) // 8


# ---------------------------------------------------------------------------
# 数论：这里已经没有数论函数了
# ---------------------------------------------------------------------------
#
# egcd / modinv / totient 三个都搬去了 task1_math.py —— 它们是任务一的
# 内容。特别是 totient：它的 p == q 分支是全包后果最重的陷阱，学生
# **必须自己写一遍**，而不是调用一个别人写好的。
#
# 搬家的代价是「原本构造上保证正确的东西变成了可能写错的东西」，
# 所以 task1_math.py 的 _self_test 里专门加了一段 φ 的检查，用一个
# **独立的预言机**（φ(7,7) == 42，手算得来）当场抓住写错的分支。


# ---------------------------------------------------------------------------
# 承诺值
# ---------------------------------------------------------------------------


def private_key_commitment(n: int, e: int, d: int) -> str:
    """给**整把私钥**（含 d）算一个承诺值。

    承诺值 = SHA-256(n ‖ e ‖ d) 的前 16 位十六进制，三段都是定长大端，
    长度都取 k = n 的字节数。

    【它有什么用】
    《实验指导书》附录 B 里只给承诺值，不给 d 本身。学生自己算出 d 之后
    用这个函数算一遍，和附录 B 对得上就说明算对了 —— 既能自查，又不会
    把答案直接送到眼前。

    这是一种「**可以验证、但不泄露**」的常见做法：验证者不需要知道
    原象，只需要能被原象复现。
    """
    k = byte_len(n)
    if d < 0 or d >= 256**k:
        raise ValueError(f"d 超出 {k} 字节能表示的范围（d 是负数？参数顺序搞错了？）")
    h = hashlib.sha256()
    h.update(i2osp(n, k))
    h.update(i2osp(e, k))
    h.update(i2osp(d, k))
    return h.hexdigest()[:16]


# ---------------------------------------------------------------------------
# PKCS#1 v1.5 解码（RFC 8017 第 7.2 节）—— 任务四黑盒的一部分
# ---------------------------------------------------------------------------


def pkcs1v15_decode(em: bytes) -> bytes:
    """EME-PKCS1-v1_5 解码：EM = 0x00 || 0x02 || PS || 0x00 || M。

    任务四你会用到它：私钥运算 `pow(c, d, n)` 的结果直接展开是一坨
    定了长的字节，里面混着随机填充。这个函数把填充剥掉，留下真正的
    会话密钥。**它不属于你的攻击** —— 属于「解密那一层」，所以给你。

    结构不对时抛 ValueError，并且**每一处错误都给出不同的信息**。
    这在生产代码里是绝对不行的：那等于给攻击者送一个**填充预言机**
    （padding oracle）—— 他能靠错误信息的差异，一个字节一个字节地
    把明文试出来，全程不需要私钥。这是 Bleichenbacher 在 1998 年
    对 SSL 的攻击，2017 年又以 ROBOT 的名字复活过一次。

    所以本实验是故意把这段「反面教材」摆在这里的。**值得停下来想一想**：
    如果这段代码要上生产，应该怎么改？提示：答案不是「把错误信息
    改得含糊一点」这么简单 —— 时间差异同样会泄漏信息。
    """
    if len(em) < 11:
        raise ValueError("EM 太短，不可能是合法的 PKCS#1 v1.5 编码")
    if em[0] != 0x00:
        raise ValueError(f"EM 第 1 字节应为 0x00，实际 0x{em[0]:02x}")
    if em[1] != 0x02:
        raise ValueError(f"EM 第 2 字节应为 0x02（块类型 2），实际 0x{em[1]:02x}")
    sep = em.find(b"\x00", 2)
    if sep < 0:
        raise ValueError("EM 里找不到分隔用的 0x00 字节")
    if sep - 2 < 8:
        raise ValueError(f"PS 填充串太短：{sep - 2} 字节，至少需要 8 字节")
    return em[sep + 1 :]


# ---------------------------------------------------------------------------
# 自校验
# ---------------------------------------------------------------------------


def _self_test() -> bool:
    ok = True
    section("rsa_common 自校验")

    # 注：原来这里的 1、2 两项是 φ(n) 的两种情形。φ 搬到 task1_math.py
    # 之后，那两项也随之搬了过去（而且加了更强的检查）—— 不在这里保留
    # 一份，正是为了让「φ 写错了就该在任务一报警」这件事只有一处真相。

    # 1. 承诺值必须**稳定** —— 同一个输入永远同一个值，否则附录 B 无意义
    fixed = private_key_commitment(3233, 17, 413)
    stable = fixed == private_key_commitment(3233, 17, 413)
    print(f"1. 承诺值可复现（n=3233,e=17,d=413 -> {fixed}）   "
          f"{'通过' if stable else '失败'}")
    ok &= stable

    # 2. 承诺值必须**敏感到每一位** —— 否则改错了答案还对得上
    diff = private_key_commitment(3233, 17, 413) != private_key_commitment(3233, 17, 414)
    print(f"2. 承诺值对 d 的 1 位改动敏感        {'通过' if diff else '失败'}")
    ok &= diff

    # 3. I2OSP/OS2IP 往返
    rt = all(os2ip(i2osp(v, 8)) == v for v in (0, 1, 255, 256, 2**64 - 1))
    print(f"3. I2OSP / OS2IP 往返               {'通过' if rt else '失败'}")
    ok &= rt

    # 4. 语料读得进来，而且位长是混排的（真实感）
    try:
        moduli = load_moduli()
        bits = sorted({m.bit_length() for m in moduli})
        mixed = bits == [1023, 1024]
        print(f"4. 读到 {len(moduli)} 个模数，位长 {bits}   "
              f"{'通过（1023/1024 混排，符合预期）' if mixed else '注意：位长不是预期的混排'}")
        ok &= len(moduli) == 1000
    except (OSError, ValueError) as exc:
        print(f"4. 读语料失败：{exc}")
        print("   —— 先跑 python run_all.py 的第 0 步，或确认 data/moduli.txt 在")
        ok = False

    return ok


if __name__ == "__main__":
    import sys as _sys
    _sys.exit(0 if _self_test() else 1)
