"""任务二：扫一遍语料，并把第一台设备真正拆开。【6 处填空】

【这一步在整个攻击里的位置】
任务一是数学（把 e 变成 d），本任务是中间那一跳，任务三是完整交付。
这一跳只有一次 gcd —— 但它是整个实验最「一击致命」的地方：

    分解两个 512 位素数的乘积，现代密码学认为做不到；
    求两个这样的乘积的最大公约数，是**微秒级**的。

这就是共享素因子的全部威力。你不需要变强，你只需要发现
「这两台设备的素数是从同一个池子里捞的」。

【本节要填 6 处空】
填空 1、2、3、4 在 scan_pairs 里（扫描），填空 5、6 在 break_pair 里（拆开）。

【预计耗时】
1000 个模数 = 499,500 对，本机约 6.5 秒。程序转几秒是正常的，
不是死循环。

⚠ **必须用 math.gcd**，不要用你自己写的欧几里得循环。
   数学步骤一模一样，但手写的 Python 版每对要约一百多微秒，
   C 实现的 math.gcd 只要十几微秒 —— 差约 10 倍。整个扫描会从
   6.5 秒变成一分钟出头。**这个对比是本任务最直观的一个结论**：
   攻击之所以可怕，一半在于数学，另一半在于它便宜到可以当日常巡检跑。

⚠ 本节还会用到任务一写的 `totient` 和 `modinv` —— 就在本文件顶部
   从 task1_math 里 import 进来了。上面那一关没过，这一关一定过不去。
"""

from __future__ import annotations

import argparse
import json
import math
import time
from pathlib import Path

from fill import Blanks, run
from rsa_common import (
    DATA,
    DASH,
    PUBLIC_E,
    load_moduli,
    private_key_commitment,
    section,
)
from task1_math import modinv, totient

FILL = Blanks()          # ★ 不要给 FILL 赋值


# ---------------------------------------------------------------------------
# 填空 1、2、3、4
# ---------------------------------------------------------------------------


def scan_pairs(moduli: list[int]) -> tuple[list[tuple[int, int, int]], float]:
    """两两求 gcd，返回 (命中列表, 用时秒数)。

    命中列表的每一项是 (设备 i, 设备 j, g)，其中 i < j。

    【两个容易写错的地方】

    1. 内层从 i+1 开始，不是从 0 开始 —— 否则每个无序对会被算两遍，
       而且会出现 (i, i) 这种自己跟自己求 gcd 的项（那永远是 n 本身，
       会被误报成「重复模数」）。

    2. 条件写 `g > 1` 就够了，**不要**写 `g != 1 and g != n`。
       现在先把所有异常都抓出来，怎么分类是任务三的事。
       在这里就把 g == n 过滤掉，你会永远不知道语料里还有重复模数 ——
       而「你漏报了一类异常」和「语料里没有这一类」，看起来是一样的。

        ⚠ 这一条是**本任务最容易犯、后果最大**的错。滤掉 g == n 之后：
        扫描会安静地少报一条命中、任务三的两个集合会各少一台、
        「命中 5 条 / 涉及 7 台」两个数一起错 —— 而程序全程不报错。

    【为什么要计时】
    重活是那个双重循环（约 50 万次 gcd），把它的耗时测出来，
    你才知道「这个攻击便宜到什么程度」。计时只包住双重循环，
    别把打印也算进去 —— 打印的开销会污染这个数。
    """
    hits: list[tuple[int, int, int]] = []
    n = len(moduli)
    t0 = time.perf_counter()

    for i in range(n):
        # TODO(1): 内层循环该从哪儿开始？
        #          提示：无序对 (i, j) 和 (j, i) 是一回事，只该算一次；
        #                而且绝不能让自己跟自己配（gcd(n, n) = n，
        #                会被误读成「模数重复」）。
        start = i + 1
        for j in range(start, n):

            # TODO(2): 求这两个模数的最大公约数。
            #          提示：math 模块里的 gcd，参数是 moduli[i] 和 moduli[j]
            g = math.gcd(moduli[i], moduli[j])

            # TODO(3): 什么样的 g 值得记下来？
            #          提示：一个条件表达式。现在**先把所有异常都抓出来**，
            #                怎么分类是任务三的事 —— 别在这里就滤掉 g == n。
            if g > 1:
                # TODO(4): 把这一对记下来 —— 设备号 i、设备号 j，以及 g。
                #          提示：往 hits 里加一个三元组 (i, j, g)
                hits.append((i, j, g))

    elapsed = time.perf_counter() - t0
    return hits, elapsed


# ---------------------------------------------------------------------------
# 填空 5、6
# ---------------------------------------------------------------------------


def break_pair(n_a: int, n_b: int, e: int = PUBLIC_E) -> dict[str, int]:
    """给定一对**共享素因子**的模数，算出 n_a 的完整私钥。

    返回 {"p", "q", "d", "phi", "g"}。

    【推导】
    设 n_a = p·q_a、n_b = p·q_b，两台设备复用了同一个素数 p。那么

        gcd(n_a, n_b) = p

    因为 p 同时整除两个数，而 q_a、q_b 是各自独立取的素数，
    几乎不可能也相等。拿到 p 之后 q_a = n_a // p，于是 n_a 被完全分解。

    接着就是任务一的收尾：

        φ(n_a) = (p − 1)(q_a − 1)
        d      = e⁻¹ mod φ(n_a)

    【填空 5：三种情形必须分开，这是本任务最重要的判断】
    g 有三种可能，处理方式完全不同：

        g == 1        两台设备没有共享素因子。这一对拆不开，应当抛
                      ValueError。⚠ 如果你不检查、硬往下算，p 会是 1，
                      φ 会变成 0，然后 modinv 会报一个**莫名其妙的错**
                      —— 错误信息会指向 modinv，而真正的问题在这里。

        g == n_a      说明 n_a 的因子全在 n_b 里 —— 实践中这几乎只有
                      一种可能：**两个模数完全相同**（复制粘贴、镜像部署、
                      随机数发生器状态被完整复用）。这时你拿到的是 n
                      本身，不是 p：p = g = n_a，q = n_a // g = 1。
                      继续往下算会得到一把错的私钥，而且**不一定报错**。
                      这一对是**不可分解的**，必须单独抛 ValueError。

        1 < g < n_a   这才是我们要的情形：g 就是共享的那个素数。

    【为什么第 2 种情形值得单独写一条】
    它是本实验的核心教学点：**「异常」不等于「可分解」**。
    你发现了有设备在用同一个模数 —— 这是个严重的安全问题 ——
    但仅凭这份语料，你仍然拿不到它的私钥。
    攻击者知道了「重复」，却仍然不知道因子。

    报告里有一问就落在这里：既然拆不开，为什么这仍然算一个必须上报的发现？
    """
    g = math.gcd(n_a, n_b)

    # TODO(5): 把三种情形分开。这里面要有：
    #            · g == 1      -> raise ValueError(...)，说清是「不共享素因子」
    #            · g == n_a    -> raise ValueError(...)，说清是「模数完全相同，
    #                             异常但拆不开」
    #            · 其余情形     -> p, q = g, n_a // g
    #          注意：这里是一整块代码，不是一行。把 FILL[5] 整个换掉，
    #                换成好几条语句（if / raise / 赋值），别只换成一个表达式。
    if g == 1:
        raise ValueError("不共享素因子，无法从这一对恢复私钥")
    if g == n_a:
        raise ValueError("模数完全相同，异常但拆不开")
    p, q = g, n_a // g

    phi = totient(p, q)              # ← 用你自己在任务一写的那两个
    # TODO(6): 私钥指数 d = e⁻¹ mod φ(n)。
    #          提示：任务一的 modinv，参数顺序是 (a, m) —— 谁是模数别搞反。
    d = modinv(e, phi)
    return {"p": p, "q": q, "d": d, "phi": phi, "g": g}


# ---------------------------------------------------------------------------
# 主流程：骨架已给，一般不需要改
# ---------------------------------------------------------------------------


def main() -> None:
    ap = argparse.ArgumentParser(description="任务二：两两 GCD 扫描 + 拆开一对")
    ap.add_argument("-i", "--input", type=Path, default=DATA / "moduli.txt")
    ap.add_argument("-o", "--output", type=Path, default=DATA / "hits.json",
                    help="命中的落盘位置（任务三要从这里接着做）")
    ap.add_argument("--show", type=int, default=10, help="最多打印几条命中")
    ap.add_argument("--no-write", action="store_true", help="只打印，不写文件")
    args = ap.parse_args()

    moduli = load_moduli(args.input)

    section(f"任务二：扫描 {len(moduli)} 个模数")
    n = len(moduli)
    print(f"两两组合数：C({n}, 2) = {n * (n - 1) // 2:,}")
    print("（本机约 6~7 秒，请稍等）")
    print()

    hits, elapsed = scan_pairs(moduli)

    print(f"{'命中':<6}{'设备 i':>8}{'设备 j':>8}   gcd 的位长")
    print(DASH)
    for i, j, g in hits[: args.show]:
        print(f"{'':<6}{i:>8}{j:>8}   {g.bit_length()} 位")
    if len(hits) > args.show:
        print(f"...（共 {len(hits)} 条）")
    print()
    print(f"命中条数：{len(hits)}")
    print(f"扫描用时：{elapsed:.2f} 秒")

    if not hits:
        print()
        print("没有命中 —— scan_pairs 是不是写错了？")
        print("（比如条件写成了 g != 1 之外的东西，或者内层循环用了 range(n)）")
        raise SystemExit(1)

    # ---- 落盘，供任务三接着用 ----
    if not args.no_write:
        payload = {
            "n": n,
            "public_e": PUBLIC_E,
            "scan_seconds": round(elapsed, 4),
            "hits": [{"i": i, "j": j, "g": hex(g)} for i, j, g in hits],
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8")
        print(f"已写出：{args.output}（任务三会读它）")

    # ---- 挑一对来拆 ----
    #
    # 这里特意挑**第一条 1 < g < n 的命中**，而不是第一条命中。
    # 因为第一条命中可能是 g == n 的那种（重复模数），那种拆不开 ——
    # 而「拆不开」正是任务二要你亲手撞一次的东西。
    section("拆开其中一对")
    target = None
    for i, j, g in hits:
        if 1 < g < moduli[i]:
            target = (i, j, g)
            break
    if target is None:
        print("所有命中都是 g == n 或 g == 1，没有可分解的配对。")
        raise SystemExit(1)

    i, j, g = target
    n_a = moduli[i]
    print(f"选中设备 {i} 与设备 {j}")
    print(f"  n_{i} 位长         : {n_a.bit_length()}")
    print(f"  gcd(n_{i}, n_{j})  : {g.bit_length()} 位  ← 这就是共享的那个素数")
    print("  位长正好是模数的一半，符合「两个 512 位素数之积」的预期")
    print()

    info = break_pair(n_a, moduli[j], PUBLIC_E)
    p, q, d, phi = info["p"], info["q"], info["d"], info["phi"]

    print(f"  p                : {p.bit_length()} 位")
    print(f"  q                : {q.bit_length()} 位")
    print(f"  p · q == n_{i}    : {'是' if p * q == n_a else '否 ← 错了！'}")
    print(f"  φ(n)             : {phi.bit_length()} 位")
    print(f"  d                : {d.bit_length()} 位")
    print(f"  d 的承诺值        : {private_key_commitment(n_a, PUBLIC_E, d)}")

    # ---- 往返验证：这是「这把私钥是对的」的唯一证据 ----
    #
    # 逻辑：随便取一个 m，用公钥加密再用私钥解密，应当回到 m。
    # 这比「d 看起来像个大数」强得多 —— 它验证的是**性质**，不是外观。
    section("往返验证：公钥加密 → 私钥解密")
    ok = True
    for m in (7, 12345, 2**64 + 1, 2**128 - 1):
        if m >= n_a:
            continue
        c = pow(m, PUBLIC_E, n_a)
        back = pow(c, d, n_a)
        good = back == m
        ok &= good
        print(f"  m = {m:<20} -> c = {str(c)[:22]}... -> m' = {back:<20} "
              f"{'✓' if good else '✗'}")
    print()
    if ok:
        print("往返全部成功 —— 这把私钥是正确的。")
        print("注意你刚刚做到的事：没有分解任何 1024 位的数，")
        print("只用了两次 gcd（一次在扫描里、一次在 break_pair 里）。")
        print()
        print("你已经拆开了第一台设备。接下来任务三把同一套动作套到")
        print("所有设备上 —— 看看一共能拆开几台，最后拿回那份加密的通知。")
        print()
        print("先别急着问「一共几台」：那个数要你自己从任务三的输出里数出来。")
    else:
        print("往返失败。常见原因（按可能性排序）：")
        print("  · d 是负数 —— 任务一的 modinv 忘了 % m（填空 7）")
        print("  · φ 的分支写错了 —— 检查 totient 的 p != q 那一条（填空 8）")
        print("  · g 的分支写错了 —— 检查 g == n_a 那一条有没有拦住重复模数")
        print("  · modinv 两个参数顺序反了 —— 是 (e, φ)，不是 (φ, e)")
        raise SystemExit(1)


if __name__ == "__main__":
    run(main)
