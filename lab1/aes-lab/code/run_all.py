"""一键跑通全部任务（便于教师/助教批量检查）。

用法：
    python run_all.py            跑全部
    python run_all.py --keep     保留各任务的完整输出

注意：任务四的**交互模式**不在这里跑（它要等键盘输入）。
本脚本用非交互参数调用它。
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# 让子进程统一用 UTF-8 输出，这样本脚本用 utf-8 解码就是对的。
# 若不设，中文 Windows 上子进程会按 cp936 输出，解码出来是乱码。
CHILD_ENV = {**os.environ, "PYTHONIOENCODING": "utf-8"}


def _no_crash_console() -> None:
    """输出永不因编码问题崩溃（保留本机编码，只把坏字符替换掉）。

    Windows 的 cmd.exe 默认是 cp936，遇到 GBK 里没有的字符（如 U+FFFD、
    生僻汉字）print 会抛 UnicodeEncodeError。这里降级为替换，而不是报错。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass

STEPS: list[tuple[str, list[str]]] = [
    ("环境自检",            ["check_env.py"]),
    ("建立历史密文库",      ["alice_encrypt.py", "--build-history"]),
    ("加密一条新消息",      ["alice_encrypt.py", "-s", "Alice", "-t", "Bob",
                             "-d", "2026-03-15", "-p", "Library"]),
    ("任务一 分组结构",     ["task1_basics.py"]),
    ("任务二 模式泄露",     ["task2_pattern.py"]),
    ("任务三 分组搬运",     ["task3_splice.py"]),
    ("任务四 伪造（改地点）", ["task4_forge.py", "-t", "M1", "-f", "Place", "-s", "M2"]),
    ("任务四 伪造（改发件人）", ["task4_forge.py", "-t", "M1", "-f", "From", "-s", "M4"]),
    ("Bob 解密被伪造的密文", ["bob_decrypt.py", "-i", "../data/forged.ct"]),
    ("任务五 挑战题",       ["task5_challenge.py"]),
    ("任务六 防御对照",     ["task6_defense.py"]),
]


def main() -> None:
    ap = argparse.ArgumentParser(description="一键跑通全部任务")
    ap.add_argument("--keep", action="store_true", help="打印每个任务的完整输出")
    args = ap.parse_args()
    _no_crash_console()

    failed: list[str] = []
    for i, (name, cmd) in enumerate(STEPS, 1):
        print(f"[{i:>2}/{len(STEPS)}] {name} ... ", end="", flush=True)
        p = subprocess.run(
            [sys.executable, *cmd],
            cwd=HERE, capture_output=True, text=True, encoding="utf-8", errors="replace",
            env=CHILD_ENV,
        )
        if p.returncode == 0:
            print("通过")
        else:
            print("失败")
            failed.append(name)
        if args.keep or p.returncode != 0:
            print("-" * 68)
            print(p.stdout)
            if p.stderr:
                print("STDERR:", p.stderr)
            print("-" * 68)

    print()
    print("=" * 68)
    if not failed:
        print(f"全部 {len(STEPS)} 个步骤通过")
        print()
        print("接下来可以手动体验交互式攻击：")
        print("    python task4_forge.py")
        print("    python bob_decrypt.py -i ../data/forged.ct")
    else:
        print(f"{len(failed)} 个步骤失败：{', '.join(failed)}")
        sys.exit(1)
    print("=" * 68)


if __name__ == "__main__":
    main()
