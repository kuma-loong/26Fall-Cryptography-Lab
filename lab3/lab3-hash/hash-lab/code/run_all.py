"""按顺序跑四个任务。

    python run_all.py              # 跑全链
    python run_all.py --progress   # 只看填空进度

退出码：
    0  全部通过
    3  还有空没填（正常状态）
    1  真的报错了
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from fill import count_blanks, reference_count, EXIT_BLANK   # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CODE = Path(__file__).resolve().parent
TASKS = (
    ("task1_md5.py", 6),
    ("task2_extend.py", 8),
    ("task3_collision.py", 7),
    ("task4_defense.py", 4),
)


def progress() -> int:
    print("=" * 56)
    print("填空进度")
    print("=" * 56)
    total = 0
    for name, expected in TASKS:
        n, _ = count_blanks(CODE / name)
        total += n
        print(f"  {name:22s} {'░' * n}  {n} / {expected}")
    print()
    print(f"  合计 {total} / {reference_count()}")
    return total


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--progress", action="store_true")
    args = ap.parse_args()

    if args.progress:
        total = progress()
        raise SystemExit(0 if total == 0 else EXIT_BLANK)

    for name, _ in TASKS:
        print()
        print("#" * 72)
        print(f"# 运行 {name}")
        print("#" * 72)
        proc = subprocess.run([sys.executable, name], cwd=CODE)
        if proc.returncode == EXIT_BLANK:
            print()
            print(f"停在 {name}：还有空没填。")
            print("查进度：python run_all.py --progress")
            raise SystemExit(EXIT_BLANK)
        if proc.returncode != 0:
            print()
            print(f"{name} 退出码 {proc.returncode} —— 这是真的报错了，不是空没填。")
            raise SystemExit(1)

    print()
    print("=" * 56)
    print("四个任务都跑完了。交之前再跑一遍：python verify.py")
    print("=" * 56)


if __name__ == "__main__":
    main()
