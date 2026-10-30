"""任务四：防御 —— H(secret || m) 为什么不是 MAC。【4 处填空】

任务二已经演示了：知道 H(secret || m) 和 secret 的长度，就能续写出
H(secret || m || 填充 || 别的)，全程不需要知道 secret。

正确的做法是 HMAC。这一节把两种写法放在一起：

    naive(secret, m) = SHA-256(secret || m)      ← 可被长度扩展
    HMAC(secret, m)  = HMAC-SHA-256(secret, m)   ← 不能


"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fill import Blanks, run          # noqa: E402
import md5_soft                        # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FILL = Blanks()

DATA = Path(__file__).resolve().parent.parent / "data"
OUT = DATA / "defense.json"

DEMO_SECRET = b"demo-key"          # 只用于本节演示
MSG = b"user=alice&command1=ListSquirrels&command2=NoOp"
SUFFIX = b"&command3=UnlockAllSafes"


def naive_mac(secret: bytes, msg: bytes) -> str:
    # TODO(1): 直接把 secret 和 msg 拼起来，算 SHA-256，返回十六进制。
    return hashlib.sha256(secret + msg).hexdigest()


def hmac_mac(secret: bytes, msg: bytes) -> str:
    # TODO(2): 用标准库 hmac，算法用 hashlib.sha256。
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def verify_hmac(secret: bytes, msg: bytes, tag: str) -> bool:
    # TODO(3): 重新算一遍 HMAC，和 tag 做恒定时间比较。
    #          提示：hmac.compare_digest(...)
    return hmac.compare_digest(hmac_mac(secret, msg), tag)


def main() -> None:
    DATA.mkdir(parents=True, exist_ok=True)

    print()
    print("=" * 72)
    print("  任务四：防御 —— H(secret || m) 为什么不是 MAC")
    print("=" * 72)
    print()

    naive = naive_mac(DEMO_SECRET, MSG)
    mac = hmac_mac(DEMO_SECRET, MSG)

    print("  同一条消息，两种写法：")
    print(f"    SHA-256(secret || m) = {naive}")
    print(f"    HMAC-SHA-256         = {mac}")
    print()

    # 对 naive 做一次长度扩展
    pad = md5_soft.padding(len(DEMO_SECRET) + len(MSG))
    # naive 是 SHA-256，不是 MD5。这里只用它演示「构造错了会泄露什么」，
    # 真正的扩展要按 SHA-256 的状态来算；本实验不要求实现 SHA-256。
    # 为了让演示可运行，下面直接用 MD5 的同类构造做一个对照。
    naive_md5 = md5_soft.md5(DEMO_SECRET + MSG).hexdigest()
    ext = md5_soft.md5(
        state=bytes.fromhex(naive_md5),
        count=(len(DEMO_SECRET) + len(MSG) + len(pad)) * 8,
    )
    ext.update(SUFFIX)
    extended = ext.hexdigest()
    direct = md5_soft.md5(DEMO_SECRET + MSG + pad + SUFFIX).hexdigest()

    print("  长度扩展演示（用 MD5 做同构演示）：")
    print(f"    H(secret || m)            = {naive_md5}")
    print(f"    续写后                    = {extended}")
    print(f"    直接哈希整条长消息        = {direct}")
    print(f"    相同：{extended == direct}")
    print()

    # TODO(4): 正确 tag 应当通过，随便改一个 tag 应当不通过。
    ok_good = verify_hmac(DEMO_SECRET, MSG, mac)
    ok_bad = verify_hmac(DEMO_SECRET, MSG, "00" * 32)

    print("  HMAC 校验：")
    print(f"    正确 tag 通过：{ok_good}")
    print(f"    错误 tag 通过：{ok_bad}")
    print()

    ok = (extended == direct) and ok_good and not ok_bad

    if ok:
        print("  ★ 结论：")
        print("    1. H(secret || m) 在知道长度时可以被续写；")
        print("    2. HMAC 不是「把 secret 拼进去再哈希」，它把 secret 处理成")
        print("       两个密钥块，外层再哈希一次，所以不能从 tag 续写；")
        print("    3. 需要 MAC 时，用 hmac 模块，不要自己拼字符串。")
    else:
        print("  ★ 还没成功。检查 fill 1~4 的返回值。")
    print()

    report = {
        "naive_sha256": naive,
        "hmac_sha256": mac,
        "naive_md5": naive_md5,
        "extended": extended,
        "direct": direct,
        "extension_works": extended == direct,
        "hmac_good_ok": ok_good,
        "hmac_bad_ok": ok_bad,
        "ok": ok,
    }
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                   encoding="utf-8")
    print(f"  已写出：{OUT}")
    print()

    if not ok:
        raise SystemExit(1)


if __name__ == "__main__":
    run(main)
