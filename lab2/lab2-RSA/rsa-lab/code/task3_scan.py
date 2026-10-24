"""任务三【主交付物】：把 5 条命中翻译成结论，并恢复全部可分解设备的私钥。【9 处填空】

产出 `data/weak_devices.json`。这个文件是本次实验的交付物。

【你已经有了一半】
任务二的 `scan_pairs()` 已经把命中找出来了，也在 `data/hits.json` 里存着。
本任务要做的是把这 5 条命中**翻译成结论**：

    哪些设备可分解（能算出私钥）
    哪些设备异常但不可分解（只能确认它有问题）
    哪些设备完全正常

【⚠ 本任务最关键的一件事：命中是「对」，不是「设备」】
学生每年都栽在这里。先自己想一遍再往下做：

    5 条命中，涉及几台设备？其中几台能真正拆开？

这两个数**不一样**，而且还有第三个数也不一样。三个数分别是多少，
`main()` 跑完会打印出来 —— 但你要先自己算，再看。

【四类，必须分清】

    g == 1        与谁都不共享素因子 —— 正常设备，但**不含完全平方**（见下）
    1 < g < n     共享素因子 —— 可分解，两台设备一起被拆开
    g == n        双方模数完全相同 —— 异常，但**不可分解**
    n 是完全平方   两两 GCD 对它完全沉默 —— 要靠 isqrt 单独找

最后一类最容易漏：它跟谁都不共享素因子，所以扫描里**一条命中都没有**。
如果你只做扫描，会得到 5 台可分解设备。正确答案是 6 台。
"""

from __future__ import annotations

import argparse
import json
import math
import time
from math import isqrt
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
from task2_pair import scan_pairs

FILL = Blanks()          # ★ 不要给 FILL 赋值


# ---------------------------------------------------------------------------
# 填空 1、2、3：分类
# ---------------------------------------------------------------------------


def classify(moduli: list[int],
             hits: list[tuple[int, int, int]]) -> dict[str, object]:
    """把「对」翻译成「设备」。

    返回一个字典，至少包含这四项：

        shared        list[int]   —— 共享素因子的设备（1 < g < n），**去重、升序**
        duplicate     list[int]   —— 模数被复制的设备（g == n），去重、升序
        hit_pairs     int         —— len(hits)
        hits          list[tuple] —— 原样的命中列表

    【怎么从「对」得到「设备」】
    遍历 hits，对每一条 (i, j, g) 判断这是哪一类：

        1 < g < moduli[i]     共享素因子 —— **i 和 j 都算**
        g == moduli[i]        模数相同   —— i 和 j 都算重复

    【三条命中会指向同一组设备，这一点必须想清楚再写】
    假设设备 7、8、9 共用一个素数 p，那么它们之间两两都会命中：

        (7, 8, p)   (7, 9, p)   (8, 9, p)      —— 3 条命中，3 台设备

    所以「命中条数」和「设备台数」**不是一回事**。这是三个数分家的
    第一个原因，也是填空 2 那两行（为什么要用 set）想让你想清楚的地方。

    【为什么要和「完全平方」分开】
    那一类设备**在 hits 里根本不会出现**。所以本函数的输出，
    再加上 `find_perfect_squares()` 的结果，才是完整的可分解名单。
    这是三个数分家的第二个原因。
    """
    shared: set[int] = set()
    duplicate: set[int] = set()

    for i, j, g in hits:
        # TODO(1): 这一条命中属于哪一类？
        #          提示：一个条件表达式。你在任务二的 break_pair 里写过
        #                一模一样的判断 —— g 要**严格**介于 1 和 moduli[i] 之间。
        #
        #          ⚠ 这是全包价值最高的一处空，两个方向都错得很响：
        #              · 写成 g > 1              → 重复模数那一类被并进「可分解」，
        #                                          「6 台」变成「8 台」，而且 verify.py
        #                                          会报「你把它当成了可分解的」
        #              · 只写 g != moduli[i]     → 同上，少了上界
        #            想清楚：g == 1 不会出现在 hits 里（任务二只收 g > 1），
        #            所以「不是这一类」就只剩 g == moduli[i] 那一种。
        if 1 < g < moduli[i]:

            # TODO(2): 把**设备 i 和设备 j** 都记为「共享素因子」。
            #          提示：往 shared 里放两个元素（一次调用放两个，
            #                或者两行各放一个，都行）。
            #          ⚠ 这里的容器是 set 不是 list —— 想清楚为什么。
            #            设备 7 会在 (7,8) (7,9) 两条命中里各出现一次；
            #            用 list 的话它被数两遍，台数就偏大了。
            shared.update((i, j))

        else:
            # TODO(3): 把设备 i 和设备 j 都记为「模数重复」。
            #          和上一处写法完全一样，换个容器而已。
            duplicate.update((i, j))

    return {
        "shared": sorted(shared),
        "duplicate": sorted(duplicate),
        "hit_pairs": len(hits),
        "hits": hits,
        "n": len(moduli),
    }


# ---------------------------------------------------------------------------
# 填空 4、5：完全平方
# ---------------------------------------------------------------------------


def find_perfect_squares(moduli: list[int]) -> list[int]:
    """找出所有 n = p² 的设备。

    【为什么必须单独做这一步】
    两两 GCD 对这类设备**完全沉默**：它的两个素因子是同一个 p，
    而别的设备都是独立随机的，没有任何一台会持有 p。
    所以 gcd(它, 任何别的设备) == 1，扫描一条命中都不会给它。

    【怎么判断】
        r = isqrt(n)
        如果 r * r == n，那 r 就是它的素因子（两个都等于 r）

    ⚠ **必须用 math.isqrt，不能用 int(n ** 0.5)**。
       n 有 1024 位，而 float 只有 53 位精度，`n ** 0.5` 会给出一个
       完全错误的近似值，然后你拿它平方去比 n，永远不相等。
       而且它**不报错** —— 只是安静地什么都找不到，你会以为语料里没有。

       这正是「静默失败」，本实验里最贵的一类 bug。
       检测它的唯一办法是：先自己算一遍应该有几台。
    """
    out: list[int] = []
    for dev, n in enumerate(moduli):
        # TODO(4): 求 n 的**整数**平方根。
        #          提示：文件开头已经从 math 里 import 了 isqrt
        #          ⚠ 不要写 int(n ** 0.5) —— 理由见上面那一段，
        #            那是本包最典型的一个静默失败。
        r = isqrt(n)

        # TODO(5): r 是 n 的平方根，但这还不够 —— 只有 r 平方**正好等于**
        #          n 时，n 才是完全平方数。把「判断 + 记录」这一整块写出来。
        #          提示：两条语句。
        #                · 一个 if，比较 r * r 和 n
        #                · 成立时，把设备号 dev 追加进 out
        #          ⚠ 判断要用**精确的整数比较**（r * r == n）。
        #            判错的后果两个方向都很响：一台都找不到（你会以为
        #            语料里没有），或者 1000 台全被报成完全平方。
        if r * r == n:
            out.append(dev)
    return out


# ---------------------------------------------------------------------------
# 填空 6、7、8、9：恢复私钥
# ---------------------------------------------------------------------------


def recover_keys(moduli: list[int],
                 shared: list[int],
                 squares: list[int]) -> dict[str, dict[str, object]]:
    """给每台可分解的设备算出完整私钥。

    返回 {设备号字符串: {"n": hex, "e": int, "d": hex, "commitment": str}}。

    【共享素因子的设备】和【完全平方的设备】走的是**两条路**，
    因为「p 从哪来」不一样：

        共享素因子   跟**别人**的模数求 gcd 才拿到 p
        完全平方      p = isqrt(n)，自己就能开出来，不需要别人

    但拿到 p 之后的收尾是一样的：算 φ(n)，再把 e 变成 d。

    【⚠ 完全平方这条路的陷阱】
    拿到 p 之后，最自然的写法是 phi = (p - 1) * (q - 1)。
    但 p = q 时这是**错的** —— φ(p²) = p² − p = p(p − 1)，
    不是 (p−1)²。两者差一个 p−1，也就是一个 512 位的数。

    算错了会怎样？d 会是一个看起来完全正常的数，
    程序**不报任何错**，只是最后解不开。

    ⚠ 所以**别在这里手写公式** —— 任务一里你已经写好了一个 totient，
    它认得 p == q 和 p != q 两种情形。这里要做的只是**选对分支去调用它**。

    （如果你在任务一的 totient 里把 p == q 那一支写错了，现在就是它还债
      的时候 —— 而且这次不会有任务一那样的即时报警了。这正是任务一那个
      自检块存在的理由。）
    """
    keys: dict[str, dict[str, object]] = {}

    # ---- 共享素因子：要借助邻居 ----
    for dev in shared:
        n = moduli[dev]
        # 找一台能拆开它的搭档（这段给你，不是填空）
        partner = next(j for j in range(len(moduli))
                       if j != dev and 1 < math.gcd(n, moduli[j]) < n)

        # TODO(6): 求 n 和设备 partner 的最大公约数 —— 那就是共享的素数 p。
        #          提示：math.gcd(n, moduli[partner])
        #          ⚠ 第二个参数必须是**搭档**的模数。写成 gcd(n, n) 或
        #            把 partner 当成下标以外的什么东西，都不会当场报错 ——
        #            它会安静地把 p 变成错的，然后在 φ 和 modinv 里炸，
        #            错误信息指向任务一，而问题在这里。
        p = math.gcd(n, moduli[partner])

        # TODO(7): n 被 p 整除，商就是另一个素因子。
        #          提示：整除 //，不是真除 /。
        #          ⚠ 用 / 不会当场报错：商悄悄变成 float，φ 跟着变成
        #            8.5e+307 这种科学计数法的 float，然后在 modinv 里
        #            以一条「float 不能当整数用」的 TypeError 收场。
        #            报错指向任务一，真正的问题在这里。
        q = n // p

        phi = totient(p, q)              # ← p != q 的普通情形

        # TODO(8): 把公开指数 e 变成私钥 d。一行。
        #          提示：用你自己在任务一写的那个函数，参数是
        #                公开指数和 φ(n)（两者都在上面）
        d = modinv(PUBLIC_E, phi)

        keys[str(dev)] = {
            "n": hex(n), "e": PUBLIC_E, "d": hex(d),
            "commitment": private_key_commitment(n, PUBLIC_E, d),
            "source": "shared",
        }

    # ---- 完全平方：自己开方 ----
    for dev in squares:
        n = moduli[dev]
        p = q = isqrt(n)

        # TODO(9): 算 φ(n)。一行。
        #          ⚠ 注意上面那两行：p 和 q 是**同一个数**。
        #            上面共享素因子那条路上，φ 那行是给你写好的
        #            （那里 p != q，没有歧义）；这一条路上故意留空，
        #            因为这里才是要你判断的地方 —— 见上面【陷阱】那一段。
        #          提示：还是那个你自己写的 totient。想清楚它里面
        #                哪一支会被走到。
        phi = totient(p, q)

        d = modinv(PUBLIC_E, phi)
        keys[str(dev)] = {
            "n": hex(n), "e": PUBLIC_E, "d": hex(d),
            "commitment": private_key_commitment(n, PUBLIC_E, d),
            "source": "square",
        }

    return keys


# ---------------------------------------------------------------------------
# 写交付物。这一段骨架给全了 —— 输出格式必须严格一致，否则 decrypt_hw.py
# 和 verify.py 读不了。你只要把上面 9 个空填对就行。
# ---------------------------------------------------------------------------


def build_output(moduli: list[int],
                 cls: dict[str, object],
                 squares: list[int],
                 keys: dict[str, dict[str, object]]) -> dict[str, object]:
    """拼出 weak_devices.json 的完整内容。

    【JSON 契约 —— 字段名、类型都定死了，不要改】

    {
      "n":                        int      语料规模
      "public_e":                 int      公开指数
      "factorable_devices":       [int]    可分解设备，升序
      "duplicate_devices":        [int]    模数重复的设备，升序
      "anomalous_not_factorable": [int]    异常**且拆不开**的设备
      "perfect_square_device":    int?     完全平方设备，没有则 null
      "shared_factor_devices":    [int]    靠共享素因子可分解的，升序
      "keys": {                            只含**可分解**的设备
          "<设备号>": {"n": "0x…", "e": int, "d": "0x…",
                      "commitment": "16 位十六进制", "source": "shared"|"square"}
      }
    }

    注意设备号在**列表里是数字**、在 **keys 的键里是字符串**
    （JSON 的对象键只能是字符串）。这不是笔误。

    【「异常」有两个含义，别搞混 —— 这是本实验最核心的一个区分】

        anomalous_not_factorable   异常的**且拆不开的**
        factorable_devices         可分解的（含共享素因子与完全平方）

    共享素因子和完全平方**也是异常**，但它们**可以**恢复私钥 ——
    所以它们在前者里没有位置，在后者里。

    「异常」说的是**这个模数不该这么生成**；
    「可分解」说的是**攻击者能不能拿到它的私钥**。

    模数重复是这两者分道扬镳的地方：它异常，但攻击者拿不到私钥。
    """
    shared = list(cls["shared"])
    duplicate = list(cls["duplicate"])

    return {
        "n": len(moduli),
        "public_e": PUBLIC_E,
        "factorable_devices": sorted(set(shared) | set(squares)),
        "duplicate_devices": sorted(duplicate),
        "anomalous_not_factorable": sorted(duplicate),
        "perfect_square_device": squares[0] if squares else None,
        "shared_factor_devices": sorted(shared),
        "keys": keys,
    }


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------


def load_hits(path: Path, moduli: list[int], adopt: bool):
    """读任务二留下的 hits.json。读不到就报错，并给出补救办法。"""
    if path.is_file():
        blob = json.loads(path.read_text(encoding="utf-8"))
        hits = [(h["i"], h["j"], int(h["g"], 16)) for h in blob["hits"]]
        return hits, blob.get("scan_seconds")

    if not adopt:
        print(f"找不到 {path}")
        print()
        print("它应该在任务二里生成。缺了它有两种可能：")
        print("  · 你换了机器 / 换了目录 —— 重跑一次任务二即可")
        print("  · 任务二你还没跑完 —— 用下面这条命令当场补上：")
        print()
        print("      python task3_scan.py --adopt-hits")
        print()
        print("（--adopt-hits 会调用「你自己写的」scan_pairs 重扫一遍，")
        print("  大约 6~7 秒。它不改变任何答案，只是替你补上那一步。）")
        raise SystemExit(1)

    print(f"找不到 {path} —— 按 --adopt-hits 的意思，现在重扫一遍。")
    print("（用的是你任务二写的 scan_pairs）")
    print()
    t0 = time.perf_counter()
    hits, elapsed = scan_pairs(moduli)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "n": len(moduli), "public_e": PUBLIC_E,
        "scan_seconds": round(elapsed, 4),
        "hits": [{"i": i, "j": j, "g": hex(g)} for i, j, g in hits],
    }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"重扫用时 {elapsed:.2f} 秒，命中 {len(hits)} 条，已写回 {path}")
    print()
    return hits, elapsed


def main() -> None:
    ap = argparse.ArgumentParser(description="任务三：分类、完全平方检测、恢复私钥")
    ap.add_argument("-i", "--input", type=Path, default=DATA / "moduli.txt")
    ap.add_argument("-o", "--output", type=Path, default=DATA / "weak_devices.json")
    ap.add_argument("--hits", type=Path, default=DATA / "hits.json")
    ap.add_argument("--adopt-hits", action="store_true",
                    help="hits.json 丢了？用它现场重扫一遍（约 7 秒）")
    ap.add_argument("--no-write", action="store_true", help="只打印，不写文件")
    args = ap.parse_args()

    moduli = load_moduli(args.input)
    n = len(moduli)

    section(f"任务三：分析 {n} 个模数")
    hits, scan_seconds = load_hits(args.hits, moduli, args.adopt_hits)
    if scan_seconds is not None:
        print(f"（hits.json 记录的扫描用时：{scan_seconds:.2f} 秒）")
    print(f"命中 {len(hits)} 条")

    cls = classify(moduli, hits)
    shared, duplicate = cls["shared"], cls["duplicate"]

    print()
    print(f"{'类别':<30}{'台数':>6}")
    print(DASH)
    print(f"{'g == 1（正常，不含平方）':<30}{n - len(set(shared) | set(duplicate)):>6}")
    print(f"{'1 < g < n（共享素因子）':<30}{len(shared):>6}")
    print(f"{'g == n（模数重复）':<30}{len(duplicate):>6}")

    # ---- 完全平方：两两 GCD 看不见的那一类 ----
    section("完全平方检测（扫描对它是沉默的）")
    squares = find_perfect_squares(moduli)
    print(f"用 isqrt 检查全部 {n} 个模数")
    if squares:
        for dev in squares:
            r = isqrt(moduli[dev])
            print(f"  设备 {dev}：n = {r.bit_length()} 位素数的平方  "
                  f"（n 位长 {moduli[dev].bit_length()}）")
        print()
        print(f"找到 {len(squares)} 台 —— 这一类在扫描里一条命中都没有。")
    else:
        print("没有找到完全平方模数。")
        print("⚠ 如果你确信语料里有，检查是不是用了 n ** 0.5 而不是 math.isqrt。")

    total = sorted(set(shared) | set(squares))

    # ---- 三个数，摆在一起 ----
    touched = sorted(set(shared) | set(duplicate))
    section("★ 三个数，别混")
    print(f"  命中条数      {len(hits)} 条")
    print(f"  命中涉及设备  {len(touched)} 台   {touched}")
    print(f"  真正可分解    {len(total)} 台   {total}")
    print()
    print(f"  {len(touched)} 台里，重复的那 {len(duplicate)} 台拆不开；")
    print(f"  {len(total)} 台里，完全平方那 {len(squares)} 台一条命中都没有。")
    print("  【命中集合与可分解集合，是两个不同的集合。】")

    # ---- 恢复私钥 ----
    section("恢复私钥")
    keys = recover_keys(moduli, shared, squares)
    print(f"{'设备':>6}  {'来源':<8}{'d 的位长':>10}   承诺值")
    print(DASH)
    for dev in total:
        k = keys[str(dev)]
        print(f"{dev:>6}  {k['source']:<8}{int(k['d'], 16).bit_length():>10}   "
              f"{k['commitment']}")

    # ---- 写文件 ----
    out = build_output(moduli, cls, squares, keys)
    if args.no_write:
        print()
        print("（--no-write：没有写文件）")
        return

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(out, indent=2, ensure_ascii=False, sort_keys=False) + "\n",
        encoding="utf-8")
    section("交付物")
    print(f"已写出：{args.output}")
    print(f"字节数：{args.output.stat().st_size:,}")
    print()
    print("下一步：python verify.py   —— 自查（不告诉你答案，只检查性质）")


if __name__ == "__main__":
    run(main)
