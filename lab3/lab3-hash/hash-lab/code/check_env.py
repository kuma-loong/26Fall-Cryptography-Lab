"""环境自检 + 填空进度。课前作业，上课前先跑一遍。

检查：
    1. Python 版本
    2. 只依赖标准库
    3. data/ 里的常量文件在不在
    4. 纯 Python MD5 与 hashlib 一致
    5. 填空机制正常（空会报错、赋值会被拒绝）
    6. 每个任务文件还有几个空没填
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fill import Blanks, BlankNotFilled, count_blanks, reference_count  # noqa: E402
import md5_soft                                                          # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(errors="backslashreplace")

CODE = Path(__file__).resolve().parent
DATA = CODE.parent / "data"
TASKS = ("task1_md5.py", "task2_extend.py", "task3_collision.py", "task4_defense.py")

ok = True


def check(label: str, condition: bool, detail: str = "") -> None:
    global ok
    mark = "✓" if condition else "✗"
    print(f"  {mark} {label}" + (f"    {detail}" if detail else ""))
    if not condition:
        ok = False


def main() -> None:
    global ok
    print("=" * 64)
    print("hash-lab1 环境自检（本科 2 学时版）")
    print("=" * 64)
    print()

    print("1. 解释器")
    ver = sys.version_info
    check("Python 版本 >= 3.8", ver >= (3, 8),
          f"当前 {ver.major}.{ver.minor}.{ver.micro}")
    check("不是用 -I 启动的", not sys.flags.isolated,
          "不要加 -I，否则 from fill import ... 会失败")
    print()

    print("2. 标准库")
    for name in ("hashlib", "hmac", "struct", "zipfile", "subprocess", "urllib.parse"):
        try:
            __import__(name)
            check(name, True)
        except Exception as exc:                      # noqa: BLE001
            check(name, False, str(exc))
    print()

    print("3. 数据文件")
    for name, size in (("collision_a.bin", 128), ("collision_b.bin", 128)):
        p = DATA / name
        exists = p.exists()
        check(f"{name} 存在", exists, f"{p}")
        if exists:
            check(f"{name} 是 128 字节", p.stat().st_size == size,
                  f"{p.stat().st_size} 字节")
    sample = DATA / "sample_url.txt"
    check("sample_url.txt 存在", sample.exists(), f"{sample}")
    print()

    print("4. MD5 参照实现")
    for n in (0, 1, 55, 56, 64, 1000):
        msg = b"a" * n
        check(f"长度 {n}", md5_soft.md5(msg).digest() == hashlib.md5(msg).digest())
    print()

    print("5. 填空机制")
    try:
        Blanks()[1]
    except BlankNotFilled:
        check("未填的空会抛出 BlankNotFilled", True)
    except BaseException as exc:                     # noqa: BLE001
        check("未填的空会抛出 BlankNotFilled", False, repr(exc))
    else:
        check("未填的空会抛出 BlankNotFilled", False, "居然没有抛异常")

    try:
        Blanks()[1] = 1                              # type: ignore[index]
    except TypeError:
        check("给 FILL[n] 赋值会被拒绝", True)
    except BaseException as exc:                     # noqa: BLE001
        check("给 FILL[n] 赋值会被拒绝", False, repr(exc))
    else:
        check("给 FILL[n] 赋值会被拒绝", False, "居然赋值成功了")
    print()

    print("=" * 64)
    print("填空进度")
    print("=" * 64)
    expected = {"task1_md5.py": 6, "task2_extend.py": 8,
                "task3_collision.py": 7, "task4_defense.py": 4}
    total = 0
    for name in TASKS:
        path = CODE / name
        n, _ = count_blanks(path)
        total += n
        bar = "░" * n
        print(f"  {name:22s} {bar}  {n} / {expected[name]}")
    print()
    print(f"  合计 {total} / {reference_count()}")
    print()
    if total != reference_count():
        print("  ✗ 填空总数和 fill.py 里的 reference_count() 不一致。")
        ok = False
    print("=" * 64)
    if ok:
        print("全部通过 —— 可以开始实验了。")
    else:
        print("有失败项。先解决带 ✗ 的检查，再开始实验。")


if __name__ == "__main__":
    main()
    raise SystemExit(0 if ok else 1)
