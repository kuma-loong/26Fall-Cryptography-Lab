"""任务一：MD5 的填充与续写。【6 处填空】

任务书
------
MD5 不是一次性把整条消息吞下去的。它每 64 字节压一次，最后不足 64 字节
的部分先补到 64 字节再压。补的规则就是 MD5 填充。

这一节要做两件事：

    1. 自己写出 padding(n)：给 n 字节的消息补出标准填充；
    2. 用 H(m) 当初始状态，算出 H(m || 填充 || suffix)。

第 2 件事就是长度扩展的内核。它不需要知道 m，只需要 len(m) 和 H(m)。


"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fill import Blanks, run          # noqa: E402
import md5_soft                        # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FILL = Blanks()

DATA = Path(__file__).resolve().parent.parent / "data"
OUT = DATA / "task1_padding.json"


def padding(msg_len: int) -> bytes:
    """返回 MD5 对 msg_len 字节消息追加的填充。

    填充后总长度必须是 64 的倍数。结构：

        0x80 | 若干 0x00 | 消息比特数（8 字节，小端序）

    零的个数要让「0x80 + 零 + 8 字节长度」正好凑到 56 mod 64。
    """
    # TODO(1): 先放一个 0x80 字节。
    head = b"\x80"

    # TODO(2): 补零。零的个数 = (56 - (msg_len + 1) % 64) % 64。
    zero_count = (56 - (msg_len + 1) % 64) % 64
    zeros = b"\x00" * zero_count

    # TODO(3): 最后 8 字节是消息长度的比特数，小端序。
    #          提示：struct.pack("<Q", msg_len * 8)
    length = struct.pack("<Q", msg_len * 8)

    return head + zeros + length


def extend_digest(original: bytes, digest_hex: str, suffix: bytes) -> str:
    """已知 H(original) 和 len(original)，求 H(original || 填充 || suffix)。"""
    pad = padding(len(original))

    # TODO(4): 把十六进制摘要还原成 16 字节状态。
    state = bytes.fromhex(digest_hex)

    # TODO(5): 已经处理过的比特数 =（原消息字节数 + 填充字节数）× 8。
    count = (len(original) + len(pad)) * 8

    h = md5_soft.md5(state=state, count=count)
    h.update(suffix)
    return h.hexdigest()


def _show_padding() -> None:
    print("=" * 66)
    print("一、填充长什么样")
    print("=" * 66)
    for n in (0, 3, 55, 56, 64):
        pad = padding(n)
        print(f"  消息 {n:3d} 字节 → 填充 {len(pad):3d} 字节，"
              f"补后 {(n + len(pad)) % 64} mod 64  "
              f"开头 {pad[:8].hex()}")
    print()
    print("  规律：消息长度刚好在 55/56 附近时，填充会多出一整块。")
    print("  这是 MD5 填充最常见的边界错误。")
    print()


def _selftest() -> bool:
    print("=" * 66)
    print("二、用旧摘要续写一段 suffix")
    print("=" * 66)

    original = b"Use HMAC, not hashes"
    suffix = b"Good advice"
    digest = hashlib.md5(original).hexdigest()
    pad = padding(len(original))

    print(f"  original = {original!r}")
    print(f"  H(original) = {digest}")
    print(f"  填充 = {pad.hex()}")
    print()

    extended = extend_digest(original, digest, suffix)
    direct = hashlib.md5(original + pad + suffix).hexdigest()

    # TODO(6): 续写出来的摘要，应当等于直接哈希整条长消息的摘要。
    same = extended == direct

    print(f"  从旧状态续写 suffix：{extended}")
    print(f"  直接哈希整条长消息：{direct}")
    print(f"  两者相同：{same}")
    print()

    if not same:
        print("  ★ 对不上。先检查 padding 的三个部分：0x80、零的个数、")
        print("    末尾 8 字节是不是小端序。再看 count 有没有乘 8。")
        return False

    print("  ★ 没有 original 的明文，也能算出长消息的摘要。")
    print("    这就是长度扩展。任务二会拿它去伪造一条银行请求。")
    print()

    # 边界用例：填充跨块
    print("  再验两个边界：")
    for n in (55, 56):
        m = b"A" * n
        d = hashlib.md5(m).hexdigest()
        ext = extend_digest(m, d, b"!")
        ref = hashlib.md5(m + padding(len(m)) + b"!").hexdigest()
        print(f"    消息 {n:2d} 字节：{'✓' if ext == ref else '✗'}")
        if ext != ref:
            return False
    print()
    return True


def main() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    print()
    print("=" * 66)
    print("  任务一：MD5 的填充与续写")
    print("=" * 66)
    print()

    _show_padding()
    ok = _selftest()

    original = b"Use HMAC, not hashes"
    suffix = b"Good advice"
    digest = hashlib.md5(original).hexdigest()
    pad = padding(len(original))
    extended = extend_digest(original, digest, suffix)
    direct = hashlib.md5(original + pad + suffix).hexdigest()

    OUT.write_text(json.dumps({
        "original_hex": original.hex(),
        "original_len": len(original),
        "digest": digest,
        "padding_hex": pad.hex(),
        "padding_len": len(pad),
        "suffix_hex": suffix.hex(),
        "extended": extended,
        "direct": direct,
        "same": extended == direct,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print("=" * 66)
    print(f"已写出：{OUT}")
    print("报告里要填的数：原消息长度、填充长度、续写摘要、直接摘要、是否相同。")
    print("=" * 66)
    if not ok:
        raise SystemExit(1)


if __name__ == "__main__":
    run(main)
