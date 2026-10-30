"""任务三：MD5 碰撞与两个同哈希的程序。【7 处填空】

任务书
------
data/collision_a.bin 和 data/collision_b.bin 是王小云等人 2004 年
公布的一对 MD5 碰撞块。每个文件 128 字节，只有 6 个比特不同。

你要做三件事：

    1. 验证它们的 MD5 相同、SHA-256 不同；
    2. 把碰撞块放在文件最前面，后面接同一段 Python 程序，
       做成 good 和 evil 两个可执行文件；
    3. 两个文件 MD5 相同，运行结果一个打印 "I mean no harm."，
       另一个打印 "You are doomed!"。


"""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fill import Blanks, run          # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FILL = Blanks()

DATA = Path(__file__).resolve().parent.parent / "data"
A_FILE = DATA / "collision_a.bin"
B_FILE = DATA / "collision_b.bin"
GOOD = DATA / "good"
EVIL = DATA / "evil"
OUT = DATA / "collision_report.json"

# 两个程序共用的代码。它读自己的第一个字节块，按 0x13 的位置决定打印哪句。
# 这段代码对 good 和 evil 完全相同 —— 差别只在文件开头的碰撞块里。
PAYLOAD_CODE = '''\
import sys
from pathlib import Path

raw = Path(sys.argv[0]).read_bytes()
if raw[0x13] == 0x87:
    print("I mean no harm.")
else:
    print("You are doomed!")
'''


def load_pair() -> tuple[bytes, bytes]:
    if not A_FILE.exists() or not B_FILE.exists():
        raise SystemExit(
            f"找不到 {A_FILE.name} 或 {B_FILE.name}。\n"
            "在包根目录运行：python 教师参考/build_dataset.py"
        )
    return A_FILE.read_bytes(), B_FILE.read_bytes()


def find_diffs(a: bytes, b: bytes) -> list[tuple[int, int, int]]:
    """返回 [(偏移, 异或值, 变了几个比特), ...]。"""
    if len(a) != len(b):
        raise ValueError("两个文件长度不同")
    out: list[tuple[int, int, int]] = []
    for i, (x, y) in enumerate(zip(a, b)):
        if x == y:
            continue
        # TODO(1): 记下这一处：位置 i、异或值 x ^ y、异或值里 1 的个数。
        out.append((i, x ^ y, (x ^ y).bit_count()))
    return out


def build_payload() -> bytes:
    """把 PAYLOAD_CODE 打成一个 zipapp 的字节串。"""
    buf = io.BytesIO()
    # 固定时间戳，保证每次构建出来的 zip 字节完全一样。
    info = zipfile.ZipInfo("__main__.py", date_time=(2026, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        # TODO(2): 往 zip 里写一个叫 __main__.py 的文件，内容是 PAYLOAD_CODE。
        z.writestr(info, PAYLOAD_CODE)

    # TODO(3): 返回 zip 的字节内容。
    return buf.getvalue()


def make_programs(a: bytes, b: bytes, payload: bytes) -> tuple[bytes, bytes]:
    """碰撞块在前，zipapp 在后。共同后缀保证碰撞不被破坏。"""
    # TODO(4): good = 碰撞块 A + payload
    good = a + payload
    # TODO(5): evil = 碰撞块 B + payload
    evil = b + payload

    GOOD.write_bytes(good)
    EVIL.write_bytes(evil)
    return good, evil


def run_program(path: Path) -> str:
    # TODO(6): 用当前 Python 解释器运行 path，捕获标准输出。
    #          提示：subprocess.run([sys.executable, str(path)], ...)
    proc = subprocess.run([sys.executable, str(path)], capture_output=True, text=True, timeout=20)
    return proc.stdout.strip()


def main() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    a, b = load_pair()

    print()
    print("=" * 74)
    print("  任务三：MD5 碰撞与两个同哈希的程序")
    print("=" * 74)
    print()
    print(f"  碰撞块 A：{len(a)} 字节")
    print(f"  碰撞块 B：{len(b)} 字节")
    print()

    md5_a = hashlib.md5(a).hexdigest()
    md5_b = hashlib.md5(b).hexdigest()
    sha_a = hashlib.sha256(a).hexdigest()
    sha_b = hashlib.sha256(b).hexdigest()

    print("  两个碰撞块：")
    print(f"    MD5     A = {md5_a}")
    print(f"    MD5     B = {md5_b}   {'相同' if md5_a == md5_b else '不同'}")
    print(f"    SHA-256 A = {sha_a[:32]}…")
    print(f"    SHA-256 B = {sha_b[:32]}…   "
          f"{'相同' if sha_a == sha_b else '不同'}")
    print()

    diffs = find_diffs(a, b)
    print(f"  逐字节比较：{len(diffs)} 个字节不同，"
          f"合计 {sum(n for _, _, n in diffs)} 个比特。")
    print("    偏移    A      B      异或   变了几个比特")
    for i, x, bits in diffs:
        print(f"    {i:4d}   0x{a[i]:02x}  0x{b[i]:02x}   0x{x:02x}      {bits}")
    print()

    # 前缀会破坏碰撞，后缀不会。这是 Merkle–Damgård 的直接结果。
    prefix = b"Serial: 2026-0417; Build: release\n"
    suffix = b"\n-- end of package --\n"
    same_prefix = hashlib.md5(prefix + a).digest() == hashlib.md5(prefix + b).digest()
    same_suffix = hashlib.md5(a + suffix).digest() == hashlib.md5(b + suffix).digest()
    print("  碰撞块换个位置：")
    print(f"    加共同前缀（{len(prefix)} 字节）：MD5 还相同？ {same_prefix}")
    print(f"    加共同后缀（{len(suffix)} 字节）：MD5 还相同？ {same_suffix}")
    print()

    payload = build_payload()
    good, evil = make_programs(a, b, payload)

    # TODO(7): 两个可执行文件的 MD5 必须相同。
    same_md5 = hashlib.md5(good).digest() == hashlib.md5(evil).digest()
    same_sha = hashlib.sha256(good).digest() == hashlib.sha256(evil).digest()

    out_good = run_program(GOOD)
    out_evil = run_program(EVIL)

    print("  两个程序：")
    print(f"    good  {len(good)} 字节  MD5 {hashlib.md5(good).hexdigest()}")
    print(f"    evil  {len(evil)} 字节  MD5 {hashlib.md5(evil).hexdigest()}")
    print(f"    MD5 相同：{same_md5}")
    print(f"    SHA-256 相同：{same_sha}")
    print(f"    good 输出：{out_good}")
    print(f"    evil 输出：{out_evil}")
    print()

    ok = (same_md5 and not same_sha
          and out_good == "I mean no harm."
          and out_evil == "You are doomed!"
          and same_suffix and not same_prefix)

    if ok:
        print("  ★ 成功。两个文件 MD5 一样，SHA-256 不一样，行为也不一样。")
        print("    校验和这一关对它们两个都会放行。")
    else:
        print("  ★ 还没成功。逐项看：")
        print("    - 两个 .bin 是不是 128 字节、MD5 相同？")
        print("    - zipapp 是不是同一份 payload 接在两个碰撞块后面？")
        print("    - data/good、data/evil 运行输出对不对？")
    print()

    report = {
        "md5_a": md5_a,
        "md5_b": md5_b,
        "sha256_a": sha_a,
        "sha256_b": sha_b,
        "diff_bytes": len(diffs),
        "diff_bits": sum(n for _, _, n in diffs),
        "diff_positions": [i for i, _, _ in diffs],
        "same_with_prefix": same_prefix,
        "same_with_suffix": same_suffix,
        "good_md5": hashlib.md5(good).hexdigest(),
        "evil_md5": hashlib.md5(evil).hexdigest(),
        "good_sha256": hashlib.sha256(good).hexdigest(),
        "evil_sha256": hashlib.sha256(evil).hexdigest(),
        "good_output": out_good,
        "evil_output": out_evil,
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
