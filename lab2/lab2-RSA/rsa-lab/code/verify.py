"""自查工具：检查你交出来的 weak_devices.json 有没有问题。

【它和「对答案」不是一回事 —— 这一点很重要】
本工具**不告诉你正确答案**，也不告诉你有几台设备。
它只检查你那份结果**自身是否自洽**：

    · 每一把私钥真的能做往返加解密吗？（这是 d 对不对的直接证据）
    · d 落在 [0, φ(n)) 里吗？
    · 承诺值和内容对得上吗？
    · 你有没有把「模数重复」那几台当成可分解的？
    · 你报的台数，和从语料**独立重算**出来的台数一致吗？

性质检查能抓住绝大多数实际错误，而且**不需要知道答案**。
这是一种通用的思维：**验证一个结论，往往只需要检查它满不满足应有的性质，
不需要知道结论本身**。

【一个设计上的选择：它不读你 JSON 里的 p、q】
本包的 weak_devices.json **不含** p 和 q（见 task3_scan.py 的 JSON 契约）——
它只交 n、e、d、承诺值。所以本工具要验 p·q = n 时，是自己从
data/moduli.txt **重新算一遍因子**（gcd 邻居、isqrt 开方），
再拿去和你的 d 对。

这样更可靠：如果工具是拿你的 p、q 去验你的 d，那你 p、q 错的时候，
两边会一起错、互相印证通过。独立重算就不会。

【什么时候会告诉你台数】
加 `--appendix-b` 时，才会拿你算出来的承诺值去和《实验指导书》附录 B 对，
那时它会告诉你「一个不多、一个不少」。
默认不开，是希望你先把分析做完 —— 数不对本身就是一条线索
（比如你只找到 5 台，那说明有一类设备你还没找到发现它的手段）。

用法：
    python verify.py                    # 只做性质检查
    python verify.py --appendix-b       # 额外核对附录 B 的承诺值
    python verify.py -i 别的文件.json    # 换输入文件
"""

from __future__ import annotations

import argparse
import hashlib
import json
from math import gcd, isqrt
from pathlib import Path

from rsa_common import DASH, DATA, SEP, load_moduli, \
    private_key_commitment, section

# ---------------------------------------------------------------------------
# 附录 B 的真值。只在 --appendix-b 时才用，用之前不会打印出来。
#
# ⚠ **这里绝不能出现「设备号 → 承诺值」的对应表。**
#   那份对应表就等于任务三的答案：看一眼就知道哪几台可分解。
#   所以下面只有两种东西：
#     · 集合承诺值 —— 只能回答「一个不多、一个不少」，反推不出成员
#     · 一组**不带设备号**的单把私钥承诺值 —— 排序后放，
#       你算出某台的 d 之后看它在不在这堆里，就知道了，但看不出是哪台
#  「可以验证、但不可反推」，和真实世界发布校验和是同一套思路。
# ---------------------------------------------------------------------------

# 一个不多、一个不少
APPENDIX_B_FACTORABLE_SET = \
    "09a8f58cf59d6085f84d5f82815d413a4946a6dcd4eb4705180d9444ba10a84b"
APPENDIX_B_DUPLICATE_SET = \
    "a6f9983507b74906a1a825a0907e81b91fd5e6630083ce1fb0802e7c18f4f207"
APPENDIX_B_SQUARE_SET = \
    "064c3e311ef63912b0cc91db9681ce2d301c3e76c447febf8faa303de38cc005"

# 全部 6 把私钥的「设备号 ‖ 承诺值」总账
APPENDIX_B_LEDGER_SET = \
    "c09a70578f5e2abda10a3178714e9f6289a8a7c702718150c1291167a6a90b3c"

# 6 把私钥各自的承诺值，**不含设备号**，按字典序排列
APPENDIX_B_KEY_COMMITMENTS = [
    "03371cecdb6387e1",
    "1a6a777e738b0d5d",
    "6b7ea890b40fb4b0",
    "7c2b2f26bdfe447b",
    "9b8bf2362f8a5442",
    "a6283bd6d83be7a6",
]


# ---------------------------------------------------------------------------
# 从语料**独立**重算因子 —— 不读学生 JSON 里的任何自述
# ---------------------------------------------------------------------------
#
# 【为什么必须独立重算】
# 本包的 JSON 契约里没有 p、q。如果工具想把 d 的范围检查做对，
# 它得知道 φ(n)；而 φ 要从 p、q 来。既然 JSON 里没有，那就自己算。
#
# 这不是绕远路，是唯一正确的做法：**验证方不能向被验证方索取证据**。
# 学生把 p、q 算错了，如果工具用他给的 p、q 去验他给的 d，
# 两边会一起错、互相印证通过 —— 那这个检查就白做了。

def derive_factors(n: int, all_moduli: list[int], exclude: int) -> tuple[int, int]:
    """从语料里把 n 的两个素因子重算出来。

    两条路，和任务三里你自己走的两条一模一样：
        n 是完全平方  →  p = isqrt(n)
        否则          →  和别的模数求 gcd，找出共享的那个素因子

    重算不上就抛 ValueError —— 调用方负责把话说清楚。
    """
    r = isqrt(n)
    if r * r == n:
        return r, r
    for j, other in enumerate(all_moduli):
        if j == exclude:
            continue
        g = gcd(n, other)
        if 1 < g < n:
            return g, n // g
    raise ValueError("这台设备的模数既不是完全平方，也不和谁共享素因子")


# ---------------------------------------------------------------------------
# 素性检测：确定性 Miller-Rabin
# ---------------------------------------------------------------------------
#
# 本实验不需要 512 位素数的完整证明，但需要一个「不会把合数说成素数」的
# 检查 —— 学生对拍时常见的错误之一就是 p 不是素数（比如把 gcd 的结果
# 当成了 p，而那个 gcd 其实是 n 的一个合数因子）。

_SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]


def is_prime(n: int) -> bool:
    """确定性 Miller-Rabin（对 < 3.3×10^24 的数用前 12 个底就足够）。"""
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in _SMALL_PRIMES:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def explain_d_out_of_range() -> str:
    """d 不在 [0, φ) 时，给一句最有用的排查方向。

    【⚠ 这里**没有** p == q 的分支 —— 不是漏写，是故意的】

    φ(p²) 写成 (p−1)² 是本包后果最重的陷阱，所以这里最容易想到的写法
    是「p == q 时提示 φ 的公式」。但那个分支**永远执行不到**：

        φ_错 = (p−1)²   <   p(p−1) = φ_对

    错的那个更小，于是按它算出来的 d 一定落在 [0, φ_对) 里 ——
    下面那句范围检查（0 <= d < phi）根本不会触发，轮不到这条提示发言。

    真正抓住 φ(p²) 写错的是**往返加解密**，提示挂在 check_keys 那一项上。

    （这条注释是写给下一个读这段代码的人的：不要再把那个分支加回来。
      一个永远不执行的检查比没有检查更糟 —— 它让人以为这里已经验过了。）
    """
    return ("d 不在 [0, φ(n)) 里。如果 d 是负数：任务一的 modinv 忘了把结果 "
            "% m —— 注意这种情况 a·d ≡ 1 仍然成立、Bézout 也成立，"
            "所以只有范围检查能发现它。")


# ---------------------------------------------------------------------------
# 检查
# ---------------------------------------------------------------------------


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warns: list[str] = []
        self.passes: list[str] = []

    def err(self, msg: str, hint: str = "") -> None:
        self.errors.append(msg + (f"\n      → {hint}" if hint else ""))

    def warn(self, msg: str) -> None:
        self.warns.append(msg)

    def good(self, msg: str) -> None:
        self.passes.append(msg)

    @property
    def ok(self) -> bool:
        return not self.errors


def check_shape(data: dict, rep: Report) -> bool:
    """字段齐全、类型正确。JSON 契约在 task3_scan.py 的 build_output() 里。"""
    required = {
        "n": int,
        "public_e": int,
        "factorable_devices": list,
        "duplicate_devices": list,
        "anomalous_not_factorable": list,
        "perfect_square_device": (int, type(None)),
        "shared_factor_devices": list,
        "keys": dict,
    }
    missing = [k for k in required if k not in data]
    if missing:
        rep.err(f"缺少字段：{missing}",
                "对照 task3_scan.py 里 build_output() 的 JSON 契约")
        return False

    bad = [(k, type(data[k]).__name__, t) for k, t in required.items()
           if not isinstance(data[k], t)]
    if bad:
        for k, got, want in bad:
            want_s = getattr(want, "__name__", str(want))
            rep.err(f"字段 {k!r} 类型不对：收到 {got}，期望 {want_s}",
                    "device 号在**列表里是数字**、在 keys 的**键里是字符串**"
                    "（JSON 的对象键只能是字符串，这不是笔误）")
        return False

    rep.good("字段齐全、类型正确")
    return True


def check_keys(data: dict, rep: Report) -> None:
    """每一把私钥：d 落在 [0, φ)、承诺值可复现、往返加解密成立。

    φ 是**从语料重算**出来的，不是从 JSON 里读的 —— 理由见 derive_factors。
    """
    moduli = load_moduli()
    e = data["public_e"]
    keys = data["keys"]
    bad_missing, bad_range, bad_rt, bad_commit, bad_e = [], [], [], [], []
    n_ok = 0

    for dev in data["factorable_devices"]:
        k = keys.get(str(dev))
        if k is None:
            bad_missing.append(dev)
            continue
        try:
            n, d = int(k["n"], 16), int(k["d"], 16)
            ke = int(k["e"])
        except (KeyError, ValueError, TypeError):
            bad_missing.append(dev)
            continue

        if ke != e:
            bad_e.append(dev)

        # 语料里的 n 才是权威；对不上说明写错了设备号或者抄错了模数
        if not (0 <= dev < len(moduli)) or moduli[dev] != n:
            bad_missing.append(dev)
            continue

        try:
            p, q = derive_factors(n, moduli, dev)
        except ValueError as exc:
            rep.err(f"设备 {dev}：{exc}",
                    "这台不该出现在 factorable_devices 里")
            continue

        # ⚠ 这里**内联**算 φ，绝不 `from task1_math import totient`。
        #   学生的 totient 正是被验证的对象之一 —— 拿它来验它自己算出的 d，
        #   两边会一起错、互相印证通过。验证方必须有一条独立的通路。
        #   （同样的理由见文件上方 derive_factors 那一段。）
        phi = p * (p - 1) if p == q else (p - 1) * (q - 1)

        # ⚠ 顺序很重要，而且必须**短路**。
        #   d 不在 [0, φ) 时，后面的两项检查都不能再跑：
        #     · private_key_commitment() 对负数会抛 ValueError ——
        #       本函数以前就是这么崩掉的，于是「最有价值的那条提示」
        #       反而变成了一个和密码学毫无关系的 traceback
        #     · pow(x, 负数, n) 求的是模逆，对一个本来就不合法的 d
        #       没有意义，还会在 x 不可逆时抛 ValueError
        #   所以先判范围；不合法就到此为止，把话说清楚。
        if not 0 <= d < phi:
            bad_range.append(dev)
            continue

        # 往返验证：这是「d 是对的」最直接的证据，不需要知道答案
        m = 1234567890 % n
        if pow(pow(m, e, n), d, n) != m:
            bad_rt.append(dev)
            continue

        if k.get("commitment") != private_key_commitment(n, e, d):
            bad_commit.append(dev)
            continue

        n_ok += 1

    if bad_missing:
        rep.err(f"这些设备在 keys 里没有条目（或格式/模数对不上）：{bad_missing}",
                'keys 的值是 {"n": "0x…", "e": 65537, "d": "0x…", '
                '"commitment": "…", "source": "shared"|"square"}')
    if bad_e:
        rep.err(f"这些设备的 e 不是语料里的公开指数：{bad_e}")
    for dev in bad_range:
        rep.err(f"设备 {dev} 的 d 不在 [0, φ(n)) 内",
                explain_d_out_of_range())
    if bad_rt:
        # ★ 这是全包里**唯一**能抓住「φ(p²) 写成 (p−1)²」的检查。
        #   范围检查抓不住（错的那个 φ 更小，d 照样落在合法区间里），
        #   承诺值检查也抓不住（d 算错了，承诺值只是如实地记下这个错误）。
        #   所以下面这条提示的措辞值得多花两行 —— 它是学生的最后一根绳子。
        rep.err(f"这些设备的私钥往返加解密失败：{bad_rt}",
                "d 不对。最常见的三个原因，按可能性排序："
                "① φ 用错了 —— 完全平方那台（n = p²）要用 p(p−1)，"
                "不是 (p−1)²。这多半是你在任务一写的 totient 里 "
                "p == q 那一支有问题，回去看它的自检块；"
                "② modinv 的参数顺序反了（modinv(φ, e) 而不是 modinv(e, φ)）；"
                "③ d 是负数 —— modinv 忘了 % m")
    if bad_commit:
        rep.err(f"这些设备的 commitment 字段与内容对不上：{bad_commit}",
                "commitment 必须是 private_key_commitment(n, e, d) 的返回值")
    if n_ok and not (bad_missing or bad_e or bad_range or bad_rt or bad_commit):
        rep.good(f"{n_ok} 把私钥全部通过：d 落在 [0, φ)、承诺值自洽、"
                 f"往返加解密成立")


def check_classification(data: dict, rep: Report) -> None:
    """分类是否自洽 —— 这里能抓住「把 g == n 当成可分解」这个经典错误。

    判定口径**从语料重算**，不接受 JSON 里的自述。
    """
    moduli = load_moduli()
    fac_devs = set(data["factorable_devices"])
    dup = set(data["duplicate_devices"])
    anom_nf = set(data["anomalous_not_factorable"])
    sq = data["perfect_square_device"]

    # 1. 模数重复的设备**不可能**出现在可分解名单里
    overlap = sorted(fac_devs & dup)
    if overlap:
        rep.err(f"设备 {overlap} 的模数是重复的（g == n），你把它算成可分解了",
                "g == n 说明两个模数完全相同。攻击者知道了「重复」，"
                "但拿到的是 n 本身而不是它的因子 —— 这一对**不可分解**。"
                "「异常」不等于「可分解」，这是本实验最核心的一个区分")

    # 2. 列表里不该有重复项，且应升序
    for name in ("factorable_devices", "duplicate_devices",
                 "anomalous_not_factorable"):
        vals = data[name]
        if len(vals) != len(set(vals)):
            rep.err(f"{name} 里有重复的设备号")
        if vals != sorted(vals):
            rep.warn(f"{name} 没有按升序排列（不影响正确性，但建议排一下）")

    # 3. 异常不可分解的必须是重复的那批
    if anom_nf != dup:
        rep.err("anomalous_not_factorable 应当与 duplicate_devices 一致",
                "「异常但拆不开」的只有模数重复那一类。"
                "共享素因子和完全平方**也异常**，但它们**可分解**，"
                "所以属于 factorable_devices")

    # 4. 完全平方：声明的设备是否真的是完全平方
    if sq is not None:
        if not (0 <= sq < len(moduli)):
            rep.err(f"perfect_square_device = {sq} 越界了")
        else:
            r = isqrt(moduli[sq])
            if r * r != moduli[sq]:
                rep.err(f"你把设备 {sq} 标成完全平方，但它的 n 不是完全平方",
                        "检查是不是用了 n ** 0.5 —— float 只有 53 位精度，"
                        "对 1024 位的 n 完全不准。要用 math.isqrt")
            elif sq not in fac_devs:
                rep.err(f"设备 {sq} 是完全平方，但它不在 factorable_devices 里",
                        "完全平方模数 n = p² 是可分解的：p = isqrt(n)，"
                        "φ(n) = p(p−1)")

    # 5. 共享素因子名单里，每台都必须真的和别的设备共享素因子
    for dev in data["shared_factor_devices"]:
        if not (0 <= dev < len(moduli)):
            rep.err(f"shared_factor_devices 里的 {dev} 越界了")
            continue
        n = moduli[dev]
        if not any(j != dev and 1 < gcd(n, moduli[j]) < n
                   for j in range(len(moduli))):
            rep.err(f"设备 {dev} 被列为共享素因子，但它和谁都不共享")

    # 6. 可分解的台数 vs 从语料独立扫出来的
    real_shared = {dev for dev in range(len(moduli))
                   if any(j != dev and 1 < gcd(moduli[dev], moduli[j]) < moduli[dev]
                          for j in range(len(moduli)))}
    real_sq = {dev for dev in range(len(moduli))
               if isqrt(moduli[dev]) ** 2 == moduli[dev]}
    real = real_shared | real_sq
    if fac_devs != real:
        miss, extra = sorted(real - fac_devs), sorted(fac_devs - real)
        if miss:
            # ⚠ 这里**只报台数，不报设备号**。
            #
            # 报了号就等于把答案递过去了：学生交一份空文件，
            # 一条命令就能拿到「哪几台可分解」—— 那正好是本实验最难、
            # 最值钱的那一步（任务二、三的扫描与分类）。
            # 指导书附录 B 承诺的是「可以验证、不可反推」，这里必须守住。
            #
            # 台数**早就公开了**（附录 B.1 明写「真正可分解 6 台」），
            # 所以报台数不泄露任何新信息，却足够让学生知道
            # 「我少了一台」——剩下的「是哪一台」才是要他自己找的。
            rep.err(f"你漏掉了 {len(miss)} 台可分解设备"
                    f"（不告诉你是哪几台 —— 那正是这个实验要你找的东西）",
                    "① 漏掉的那台如果是完全平方，说明你没做 isqrt 那一步 —— "
                    "两两 GCD 对完全平方是**完全沉默**的："
                    "它产生的命中数是 0，一条都没有。"
                    "② 对一下总台数：附录 B.1 给了那个数，看差在哪一类")
        if extra:
            # extra 是学生**自己列进来**的设备号，点名不算泄露
            rep.err(f"这些设备其实不可分解，但你列进来了：{extra}")

    # 7. 共享素因子名单 vs 重算值
    if data["shared_factor_devices"] and \
            set(data["shared_factor_devices"]) != real_shared:
        miss = sorted(real_shared - set(data["shared_factor_devices"]))
        extra = sorted(set(data["shared_factor_devices"]) - real_shared)
        if miss:
            # 同 6：只报台数，不报号（真实共享素因子的那几台是答案）
            rep.err(f"shared_factor_devices 漏了 {len(miss)} 台"
                    f"（同样不点名）")
        if extra:
            rep.err(f"shared_factor_devices 多了：{extra}",
                    "完全平方那台**不是**靠共享素因子分解的 —— "
                    "它是自己开方开出来的，不该出现在这个名单里")

    if not overlap and fac_devs == real:
        rep.good("分类自洽：可分解 / 异常不可分解的划分是正确的")


def check_appendix_b(data: dict, rep: Report) -> None:
    """可选：核对附录 B 的承诺值。会暴露台数，所以默认不开。"""
    print()
    print(DASH)
    print("附录 B 核对（--appendix-b）")
    print(DASH)

    mine = {dev: data["keys"][str(dev)]["commitment"]
            for dev in data["factorable_devices"]
            if str(dev) in data["keys"]}
    want = len(APPENDIX_B_KEY_COMMITMENTS)

    if len(mine) != want:
        rep.err(f"可分解设备台数不对：你报了 {len(mine)} 台，附录 B 是 {want} 台",
                "数不对本身就是线索。少一台的话，想想哪一类设备"
                "是两两 GCD **看不见**的")

    # 逐把核：把你的承诺值排序后，与附录 B 那张**不带设备号**的表比对。
    # 这样既能告诉学生「有一把算错了」，又不会泄露哪一台对哪一台。
    got_sorted = sorted(mine.values())
    if got_sorted == APPENDIX_B_KEY_COMMITMENTS:
        rep.good(f"{len(mine)} 把私钥的承诺值全部与附录 B 对得上")
    elif mine:
        missing = [c for c in APPENDIX_B_KEY_COMMITMENTS if c not in got_sorted]
        extra = [c for c in got_sorted if c not in APPENDIX_B_KEY_COMMITMENTS]
        rep.err(f"有 {len(missing)} 把私钥的承诺值对不上附录 B",
                "附录 B 那张表**不带设备号**，所以没法告诉你具体是哪一台 ——"
                "但你可以自己定位：用 private_key_commitment(n, e, d) "
                "逐台算一遍，看哪几台的承诺值不在附录 B 的表里"
                + (f"。（提示：多出来的那 {len(extra)} 个值就是你自己算的）"
                   if extra else ""))

    # 集合承诺值：确认「一个不多、一个不少」
    #
    # 配方：先把设备号**转成字符串**，按**字典序**排序，用 \n 连接，
    # 再取 UTF-8 字节的 SHA-256。
    # ⚠ 按字典序排的话 "1053" < "17" —— 这和数值序不一样，
    #   是本配方最容易踩的坑。
    def _set_commit(items) -> str:
        return hashlib.sha256(
            "\n".join(sorted(map(str, items))).encode("utf-8")).hexdigest()

    for label, items, want_c in (
        ("可分解设备集合", data["factorable_devices"], APPENDIX_B_FACTORABLE_SET),
        ("模数重复设备集合", data["duplicate_devices"], APPENDIX_B_DUPLICATE_SET),
    ):
        if _set_commit(items) == want_c:
            rep.good(f"{label}与附录 B 一致（一个不多、一个不少）")
        else:
            rep.err(f"{label}的承诺值对不上附录 B",
                    "注意配方是 sorted(map(str, devices)) —— "
                    "先把设备号转成字符串，再按**字典序**排，不是按数值排。"
                    '字典序下 "1053" < "17"，和数值序不一样')

    # 完全平方那一类：只有一台，单独核一次，
    # 让学生知道「漏了 isqrt 那一步」是能被明确指出的
    sq = data["perfect_square_device"]
    sq_list = [] if sq is None else [sq]
    if _set_commit(sq_list) == APPENDIX_B_SQUARE_SET:
        rep.good("完全平方设备与附录 B 一致")
    elif sq is None:
        rep.err("你一个完全平方设备都没报，但附录 B 里有",
                "两两 GCD 对 n = p² 是**完全沉默**的 —— 它不会产生任何命中。"
                "要靠 math.isqrt 单独扫一遍")

    # 总账：把「设备号 ‖ 承诺值」整组拼起来核一次
    ledger = sorted(f"{dev} {c}" for dev, c in mine.items())
    got_ledger = hashlib.sha256("\n".join(ledger).encode("utf-8")).hexdigest()
    if got_ledger == APPENDIX_B_LEDGER_SET:
        rep.good("私钥总账与附录 B 一致（设备号与承诺值的配对全对）")
    elif mine and len(mine) == want:
        rep.err("私钥总账对不上附录 B —— 承诺值本身可能都对，"
                "但对错了设备",
                "这种情况说明你把某两台的 d 串了：p 和 q 取反不影响 d，"
                "但把 A 设备的 d 写到了 B 设备名下就会这样")


def main() -> None:
    ap = argparse.ArgumentParser(description="自查 weak_devices.json")
    ap.add_argument("-i", "--input", type=Path,
                    default=DATA / "weak_devices.json")
    ap.add_argument("--appendix-b", action="store_true",
                    help="额外核对附录 B 的承诺值（会告诉你台数）")
    args = ap.parse_args()

    if not args.input.is_file():
        print(f"找不到 {args.input}")
        print("先跑：python task3_scan.py")
        raise SystemExit(1)

    try:
        data = json.loads(args.input.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"{args.input} 不是合法的 JSON：{exc}")
        raise SystemExit(1) from None

    section(f"自查 {args.input.name}")
    rep = Report()

    # 自查工具**绝不能吐 traceback**。
    # 学生看到 traceback 会以为「程序坏了」，而不是「我的 JSON 有问题」——
    # 而且真正想说的那条提示会被埋在一堆栈帧里。
    # 所以这里兜住一切意外：把话说清楚，再附上异常内容供排查。
    try:
        if check_shape(data, rep):
            check_keys(data, rep)
            check_classification(data, rep)
        if args.appendix_b:
            check_appendix_b(data, rep)
    except Exception as exc:                              # noqa: BLE001
        import traceback
        rep.err(f"检查过程中遇到了意外：{type(exc).__name__}: {exc}",
                "这多半说明 JSON 里有个字段的内容不是这个脚本预期的形状。"
                "把下面的原始信息一并交给老师：")
        print()
        traceback.print_exc()

    print()
    for msg in rep.passes:
        print(f"  ✓ {msg}")
    for msg in rep.warns:
        print(f"  ! {msg}")
    for msg in rep.errors:
        print(f"  ✗ {msg}")

    print()
    print(SEP)
    if rep.ok:
        print("性质检查全部通过。")
        if not args.appendix_b:
            print()
            print("想确认「一个不多、一个不少」，加 --appendix-b 与附录 B 核对。")
            print("（建议先把分析做完 —— 数不对本身是一条线索。）")
    else:
        print(f"有 {len(rep.errors)} 项问题。上面的「→」给了排查方向，")
        print("也可以查《学生上机步骤》的「卡住了怎么办」表。")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
