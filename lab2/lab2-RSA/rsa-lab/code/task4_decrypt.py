"""任务四：用你自己恢复的私钥，解开那份密钥轮换通知。【4 处填空】

【这一刻是整场攻击的终点】
前面三个任务你做的都是「拿到数字」：写模逆 → 找到共享素因子 →
恢复若干把私钥。本任务把那些数字变成**一份能打开的 PDF**。

【黑盒与你的分工】
`decrypt_hw.py` 负责与攻击无关的部分：base64、MPI 长度前缀、切 IV、
AES-256-CBC、PKCS#1 编码。这些是「解密那一层」，直接给你。

**你**负责属于自己的那几行 —— 它们正是攻击链的收尾，
也就是本节要填的**四处空**（一空一步，按顺序来）：

    1. 用你算出的 d 做模幂            em_int = pow(c, d, n)
    2. 还原成定长字节串                em = i2osp(em_int, byte_len(n))
    3. 剥掉 PKCS#1 填充，拿会话密钥      pkcs1v15_decode(em)
    4. **反向确认**：把整块 EM 用 e 加密回去，应当等于 c

第 4 步是「这把钥匙真的是我算出来的」的证明 —— 它比任何叙述都有力。

【怎么知道用哪一把私钥】
你手上有 6 把。收件方是其中一台，但你不知道是哪一台。
**不需要猜**：逐个试过去，只有正确的那把能让 PKCS#1 填充合法。
这是「用性质筛选」而不是「用猜测筛选」—— 和 verify.py 的思路一致。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from decrypt_hw import aes_cbc_decrypt, load_container
from fill import Blanks, run
from rsa_common import (
    DATA,
    DASH,
    byte_len,
    i2osp,
    os2ip,
    pkcs1v15_decode,
    section,
)

FILL = Blanks()          # ★ 不要给 FILL 赋值

ENC = DATA / "homework.pdf.enc.asc"
KEYS = DATA / "weak_devices.json"
OUT = DATA / "homework.pdf"


def decrypt_with(c: int, iv: bytes, body: bytes,
                 n: int, e: int, d: int) -> bytes | None:
    """用一把私钥试着解开。失败返回 None。

    【三种「不是这把」的情形，都要处理】
      · c >= n                —— 模数不对。RSA 的模幂要求密文小于模数。
      · PKCS#1 填充非法        —— 这把钥匙不是收件方的（或者 d 算错了）。
                                 pkcs1v15_decode 会抛 ValueError，
                                 用 try/except 把它变成 return None。
      · 反向确认不成立          —— 同上，但更隐蔽。

    最后一种尤其要留着：万一 d 错了而填充恰好合法（概率极低但非零），
    只有反向确认能拦住它。

    ⚠ **易错点：反向确认要加密的是整块 em，不是 session_key。**
      session_key 只是 EM 这个定长块**里面**的一段：

          EM = 0x00 || 0x02 || PS || 0x00 || session_key
          └────────────────── RSA 作用在这一整块上 ──────────────────┘

      所以：

          pow(os2ip(em), e, n) == c            ✓ 正确
          pow(os2ip(session_key), e, n) == c   ✗ 永远是 False

      后者对一把**完全正确**的私钥也会返回 False。你会以为 d 错了，
      然后去改一个本来没错的地方 —— 这是本任务最浪费时间的坑。
    """
    if c >= n:
        return None

    # TODO(1): 私钥运算。一行。
    #          提示：pow(密文, 私钥 d, 模数 n)
    #          结果的类型是 int —— 模幂出来是一个整数，离「会话密钥」
    #          还差好几步。
    em_int = pow(c, d, n)

    # TODO(2): 把上面那个整数还原成**定长**字节串 —— 这就是 EM 块。
    #          提示：rsa_common 里 import 进来了一对互逆的工具，
    #                i2osp(整数, 字节数) 和 byte_len(模数) ——
    #                后者就是「n 占多少字节」，也就是 EM 该有多长。
    #          ⚠ 必须用**定长**的那一个。图省事写成「最短能装下就行」的
    #            话，EM 开头的 0x00 会被吃掉 —— 而 PKCS#1 要求第 1 字节
    #            正是 0x00。后果是**每一把**钥匙都判为填充不合法，
    #            你会顺着错误信息去怀疑 d 算错了，方向完全跑偏。
    em = i2osp(em_int, byte_len(n))

    try:
        # TODO(3): 把 EM 里那块随机的 PKCS#1 填充剥掉，留下真正的会话密钥。
        #          一行。提示：rsa_common 里已经 import 进来了，名字是
        #          pkcs1v15 开头、decode 结尾。参数就是 em。
        session_key = pkcs1v15_decode(em)
    except ValueError:
        return None            # 填充不合法 —— 这把钥匙不是收件方的

    # TODO(4): 反向确认：把整块 em 用**公钥**加密回去，应当等于 c。
    #          这里要写的是一个「**不成立**」的条件（成立就 return None）。
    #          提示：pow(os2ip(em), e, n) 与 c 的比较，用 !=
    if pow(os2ip(em), e, n) != c:
        return None

    # ⚠ 是 aes_cbc_decrypt（解密 + 去 PKCS#7 填充），不是 aes_soft.cbc_decrypt
    #   （只解密、保留填充）。用错会多出 1~16 字节填充，
    #   PDF 阅读器**照样打得开**，但字节数和 SHA-256 对不上附录 B。
    #   这是一个「看起来成功了」的失败 —— 最需要警惕的一类。
    return aes_cbc_decrypt(session_key, iv, body)


def main() -> None:
    if not KEYS.is_file():
        print(f"找不到 {KEYS}")
        print("先完成任务三：python task3_scan.py")
        raise SystemExit(1)

    keys = json.loads(KEYS.read_text(encoding="utf-8"))
    c, iv, body = load_container(ENC)

    section("任务四：解开 PBP 文件")
    print(f"RSA 密文       : {c.bit_length()} 位")
    print(f"IV             : {iv.hex()}")
    print(f"AES 密文体     : {len(body):,} 字节")
    print()
    print(f"手上有 {len(keys['keys'])} 把私钥，逐个试过去：")
    print()

    winner = None
    for dev in sorted(keys["keys"], key=lambda s: int(s)):
        k = keys["keys"][dev]
        n, e, d = int(k["n"], 16), int(k["e"]), int(k["d"], 16)
        try:
            plain = decrypt_with(c, iv, body, n, e, d)
        except Exception as exc:                       # noqa: BLE001
            # 注意这里**不需要**为「空没填」开特例。
            # 姊妹包 rsa-lab2 用 raise NotImplementedError 标记未完成，
            # 而 NotImplementedError 是 Exception 的子类 —— 于是这句
            # `except Exception` 会把「还没填」当成「这把钥匙不对」吞掉，
            # 程序一路跑到底才报一个莫名其妙的错。
            # 本包的 BlankNotFilled 继承 BaseException，宽 except 抓不到它，
            # 所以它会直接穿出去、在 fill.run() 那里变成一句精确的提示。
            # ——这就是「异常该继承谁」的一个真实后果。
            print(f"  设备 {dev:>4} : 异常 {type(exc).__name__}: {exc}")
            continue
        if plain is None:
            print(f"  设备 {dev:>4} : 不是这把")
            continue
        print(f"  设备 {dev:>4} : ✓ 成功")
        winner = (dev, plain)
        break

    if winner is None:
        print()
        print("没有一把私钥能解开。检查：")
        print("  · python verify.py —— 你的 d 是不是算错了")
        print("  · 兜底：python decrypt_hw.py --auto")
        raise SystemExit(1)

    dev, plain = winner
    OUT.write_bytes(plain)

    print()
    print(DASH)
    print(f"使用设备 #{dev} 的私钥 —— 这把私钥是你自己算出来的。")
    print(DASH)
    print()
    print(f"已写出    : {OUT}")
    print(f"字节数    : {len(plain):,}")
    print(f"SHA-256   : {hashlib.sha256(plain).hexdigest()}")
    print()
    print(f"打开它    : start {OUT.name}        （Windows）")
    print(f"            open  {OUT.name}        （macOS）")
    print()
    print("到《实验指导书》附录 B 核对这个 SHA-256。")
    print()
    print("回头看一遍你做过的事：")
    print("  · 你没有分解任何 1024 位的数")
    print("  · 你只做了一次 499,500 对的最大公约数扫描")
    print("  · 加上 1000 次开方检查（找完全平方）")
    print("  · 然后把所有可分解设备的私钥全部恢复了出来")
    print("  这就是共享素因子的全部威力。")
    print()
    print("现在读那份 PDF。它是一份真实的运维通知 ——")
    print("注意它怎么区分那三类发现，以及它对「发现者有什么义务」的说法。")


if __name__ == "__main__":
    run(main)
