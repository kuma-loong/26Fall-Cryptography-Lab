"""一键跑通全部步骤 + 填空进度表。

【什么时候用它】
· 上课前：老师自己验一遍这个包是不是完好的
· 卡住时：看看是**哪一步**开始不对的 —— 前面的步骤都没问题、
  从某一步起报错，范围立刻缩小了
· 做完后：确认四个任务全部通过，再去写报告
· 课中随时：`python run_all.py --progress`，看还差几处空

它会按顺序跑，**任何一步失败就停下**，并把失败那一步的原样输出留给你。
停下是对的：后面的步骤依赖前面的结果，硬跑下去只会写出一份
半对半错的 JSON，让你更难定位问题。

【「还有空没填」和「代码出错」是两回事 —— 本脚本会分开说】
每个任务脚本在碰到没填的空时会以**退出码 3** 结束（见 fill.py）。
run_all 认这个退出码，并且：

    退出码 3   → 打印填空进度表，说「这是正常状态，继续填」
    其他非零   → 打印「真的出错了」+ 针对性排查提示

没有这个区分，你只会看到「第 3 步失败」，然后分不清是该接着填、
还是该回头改代码 —— 那是两种完全不同的下一步动作。

【它不会替你写代码】
四个任务里该你写的那 29 处空仍然是空的 —— run_all 跑到那里会停下并
告诉你停在哪一处。这正是它该有的行为。

用法：
    python run_all.py                # 全部跑一遍（约 25 秒）
    python run_all.py --progress     # 只看填空进度，什么都不跑
    python run_all.py --only task3   # 只跑到任务三
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

from fill import EXIT_BLANK, reference_count
from rsa_common import DATA, DASH, SEP, pad, section

HERE = Path(__file__).resolve().parent

# (简称, 显示名, 参数, 预计秒数, 是否可跳过)
#
# 最后一列在 rsa-lab4 里全是 False：四个任务都是必做的，没有可跳的。
# 保留这一列是为了结构上与姊妹包的 run_all 对齐（那边有可课后做的选做
# 步骤），也为了日后真要加可选步骤时不用改解包。
STEPS: list[tuple[str, str, list[str], float, bool]] = [
    ("env",    "环境自检",             ["check_env.py"],                    4.0,  False),
    ("task1",  "任务一 数学地基",       ["task1_math.py", "--selftest"],     1.0,  False),
    ("task2",  "任务二 拆一对设备",     ["task2_pair.py"],                   7.0,  False),
    ("task3",  "任务三 全语料扫描",     ["task3_scan.py"],                   2.0,  False),
    ("verify", "自查 weak_devices.json", ["verify.py"],                     15.0,  False),
    ("task4",  "任务四 解开 PDF",       ["task4_decrypt.py"],                2.0,  False),
]

# 与 code/check_env.py 的 EXPECTED_BLANKS 是同一份契约。
# 放在两个文件里是有意的：一边是「环境自检时顺便报」，一边是「单独查」，
# 两处都写死，改一处忘了另一处会立刻在 --progress 上暴露出来。
EXPECTED_BLANKS = {
    "task1_math.py": 10,
    "task2_pair.py": 6,
    "task3_scan.py": 9,
    "task4_decrypt.py": 4,
}


def count_left(path: Path) -> int:
    """数一个文件里还剩几个空。语法错就返回 -1。"""
    import ast
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, OSError):
        return -1
    return sum(
        1 for node in ast.walk(tree)
        if isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Name) and node.value.id == "FILL"
        and not isinstance(node.ctx, ast.Store)
    )


def progress(quiet: bool = False) -> tuple[int, int]:
    """打印填空进度表，返回 (已填, 总数)。"""
    if not quiet:
        section("填空进度")

    # 「29 处空」这个数字同时出现在指导书、上机步骤、PPT 和报告模板里。
    # 把契约核对放在这里，是为了让「改了代码忘了改文档」当场暴露。
    contract = sum(EXPECTED_BLANKS.values())
    if contract != reference_count():
        print(f"  ! 填空总数对不上：本表 {contract} 处，fill.py 里写的是 "
              f"{reference_count()} 处。")
        print("    文档里印的是后者 —— 改完记得回来对齐。")
        print()

    done_all = total_all = 0
    rows: list[str] = []
    for fname, expect in EXPECTED_BLANKS.items():
        path = HERE / fname
        left = count_left(path) if path.is_file() else expect
        total_all += expect
        if left < 0:
            rows.append(f"  ✗ {pad(fname, 18)} 语法错误 —— 先把这一行修好")
            continue
        done = max(0, min(expect - left, expect))
        done_all += done
        bar = "█" * done + "░" * (expect - done)
        rows.append(f"  {pad(fname, 18)} {bar}  {done} / {expect}"
                    + ("  ✓" if done == expect else ""))

    for line in rows:
        print(line)
    print()
    if done_all >= total_all:
        print(f"  合计 {done_all} / {total_all} —— 全部填完，可以跑全流程了。")
    else:
        print(f"  合计 {done_all} / {total_all}")
        print("  没填完不要紧：跑到那一行会告诉你具体是哪个文件的第几行。")
        print("  （就像这样：FILL[2] not filled yet -- task2_pair.py 第 96 行）")
    return done_all, total_all


def run_step(script: str, args: list[str]) -> tuple[int, float, str]:
    """跑一个脚本，返回 (退出码, 用时, 输出)。"""
    cmd = [sys.executable, "-X", "utf8", script, *args]
    t0 = time.perf_counter()
    proc = subprocess.run(
        cmd, cwd=HERE, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )
    dt = time.perf_counter() - t0
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, dt, out.strip()


def main() -> None:
    ap = argparse.ArgumentParser(description="一键跑通 rsa-lab4")
    ap.add_argument("--progress", action="store_true",
                    help="只打印填空进度表，什么都不跑")
    ap.add_argument("--only", default=None,
                    help="只跑到这一步为止（" + " / ".join(s[0] for s in STEPS) + "）")
    ap.add_argument("--verbose", action="store_true", help="打印每一步的完整输出")
    args = ap.parse_args()

    if args.only and args.only not in {s[0] for s in STEPS}:
        raise SystemExit(f"--only 只能是：{', '.join(s[0] for s in STEPS)}")

    if args.progress:
        print(SEP)
        print("rsa-lab4 填空进度")
        print(SEP)
        print()
        progress(quiet=True)
        print()
        print(DASH)
        print("「填完了」的标准：上面每一行都是 █ 且带 ✓。")
        print()
        raise SystemExit(0)

    print(SEP)
    print("rsa-lab4 一键跑通")
    print(SEP)
    print(f"解释器：{sys.executable}")
    print(f"目录　：{HERE}")
    print()

    # 开跑之前先看一眼进度 —— 免得学生跑到第 5 步才发现第 1 步还有空
    done, total = progress(quiet=True)
    if done < total:
        print()
        print("  上面的空还没填完 —— 跑起来会停在第一处没填的地方。")
        print("  想只看进度：python run_all.py --progress")
    print()

    results: list[tuple[str, int, float]] = []
    for key, title, argv, est, skippable in STEPS:
        # 进度提示只在**终端**里用 \r 原地刷新。重定向到文件时
        # （python run_all.py > log.txt）\r 不会覆盖，只会留下一行
        # 半截的「运行中…」，所以那时干脆不打印。
        tty = sys.stdout.isatty()
        if tty:
            print(f"  ▶ {pad(title, 26)} 运行中…", end="\r", flush=True)

        code, dt, out = run_step(argv[0], argv[1:])
        results.append((title, code, dt))
        ok = code == 0
        blank = code == EXIT_BLANK

        place = "  ⏸" if blank else ("  ✓" if ok else "  ✗")
        if blank:
            print(f"{place} {pad(title, 26)} 停住 —— 还有空没填"
                  f"（退出码 {EXIT_BLANK}）")
        elif ok:
            slow = "（比预期慢）" if dt > est * 2.5 else ""
            print(f"{place} {pad(title, 26)} {dt:>6.2f}s  预计 {est:>5.1f}s {slow}")
        else:
            print(f"{place} {pad(title, 26)} {dt:>6.2f}s  退出码 {code}")

        # 「还有空没填」不 dump 原始输出：那一整段就是一句
        # 「FILL[n] not filled yet -- 文件 第几行」，下面还会再讲一遍。
        # 机房里屏幕上每多一行无关的字，学生就多一分看漏关键行。
        if args.verbose or (not ok and not blank):
            print()
            print(DASH[:72])
            for line in out.splitlines():
                print(f"    {line}")
            print(DASH[:72])
            print()

        if not ok:
            print(SEP)
            if blank:
                # —— 这是**正常状态**，不是失败 ——
                print(f"停在「{title}」：这一关还有空没填。")
                print()
                print("这不是程序出错，是你还没写到那儿。上面给出了文件名和行号，")
                print("打开它、把 FILL[n] 换成你的代码，再跑一次 run_all.py 就行。")
                print()
                progress(quiet=True)
            else:
                print(f"✗ 停在「{title}」。这是真的出错了，不是「还没填完」。")
                print()
                _diagnose(key, out)
            print(SEP)
            raise SystemExit(EXIT_BLANK if blank else 1)

        if args.only and key == args.only:
            break

    print()
    print(SEP)
    total_t = sum(dt for _, _, dt in results)
    print(f"全部通过 —— {len(results)} 步，合计 {total_t:.1f} 秒。")
    print(SEP)
    print()
    print("你的交付物：")
    for name in ("weak_devices.json", "homework.pdf"):
        p = DATA / name
        if p.is_file():
            print(f"  ✓ data/{name:<22} {p.stat().st_size:>10,} 字节")
        else:
            print(f"  ✗ data/{name:<22} 还没有（跑上面没做的那一步）")
    print()
    print("接下来：打开《实验报告模板》，把课内记下的数字填进去。")


def _diagnose(key: str, out: str) -> None:
    """按失败的那一步给针对性提示。"""
    tips = {
        "env": [
            "环境自检没过。先把上面标 ✗ 的那几项解决掉 ——",
            "环境问题暴露得越晚，代价越大，所以它排在第一。",
        ],
        "task1": [
            "任务一的自检没过。最常见的两个原因：",
            "  · egcd 里那行赋值写成了两条语句（先赋 a 再算 b），",
            "    顺序反了。要用元组同时赋值：a, b = b, a % b",
            "  · modinv 忘了把结果 % m —— 这时 Bézout 检查和",
            "    a·d≡1 都会通过，只有【三】范围检查能抓住它。",
        ],
        "task2": [
            "任务二没过。按顺序查：",
            "  · 一条命中都没有 —— 扫描的条件是不是写成了 g != 1 之外",
            "    的东西？（命中数应当远多于 5 条，别慌）",
            "  · break_pair 里少了 g == n_a 那一支 —— 重复模数会被当成",
            "    可分解的，算出 p = n、q = 1，然后在 modinv 里炸一个",
            "    指向任务一的错。错误信息在哪，问题不一定在哪。",
            "  · 往返验证失败 —— 上面已经按可能性列了原因，照着查。",
        ],
        "task3": [
            "任务三没过。这是主交付物，也是最长的一步。",
            "检查 classify 里两个分支：g < n 才是可分解，",
            "g == n 是模数重复（异常，但拆不开）。",
        ],
        "verify": [
            "JSON 交出来了，但性质检查发现了问题。",
            "上面每一条 ✗ 后面的「→」都给了排查方向。",
            "最值得先看的一条：你有没有把「模数重复」那两台",
            "当成可分解的？（g == n，异常但拆不开。）",
        ],
        "task4": [
            "解密失败。按顺序查：",
            "  · python verify.py  —— d 真的对吗",
            "  · 反向确认那一行 pow(会话密钥, e, n) == c 加了吗",
            "  · 兜底：python decrypt_hw.py --auto",
        ],
    }
    for line in tips.get(key, []):
        print(f"  {line}")
    if "ModuleNotFoundError" in out:
        print()
        print("  提示：ModuleNotFoundError 多半有两个原因 ——")
        print("        · 命令不在 code/ 目录下跑")
        print("        · 用了 python -I（隔离模式会把脚本目录移出 sys.path）")
        print("        本包不需要 pip install 任何东西。")
    if "SyntaxError" in out:
        print()
        print("  提示：SyntaxError 说明改动把一个语法结构弄坏了。")
        print("        最常发生在填空处 —— 比如把一处空拆成了两条语句，")
        print("        或者删掉了一个括号。对着 TODO 注释再看一眼。")
    print()
    print("  《学生上机步骤》末尾的「卡住了怎么办」表列了更多情况。")


if __name__ == "__main__":
    main()
