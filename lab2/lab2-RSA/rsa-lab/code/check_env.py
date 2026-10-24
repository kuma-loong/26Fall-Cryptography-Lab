"""第 0 步：环境自检。**上课第一件事就跑它。**

【为什么它排在最前面】
环境问题有个残酷的特点：暴露得越晚，代价越大。
如果到第 70 分钟才发现解释器不对，学生已经做完了九成的工作却没有时间修。
所以本实验把环境检查放到**最开始**，而且要求它一次把所有问题都报出来。

【它是怎么检查的】
不是只看「import 成功」—— 那什么都证明不了。这里的每一项都验**性质**：

    · 解释器     打印 sys.executable，确认不是在用 Microsoft Store 的假 python
    · 运行方式   确认没有被 -I / -E 隔离（那会让 from fill import ... 直接失败）
    · 编码       中文与 ² ≈ 这类符号能不能正常输出（Windows 控制台的老问题）
    · 数据文件   data/ 下该有的文件在不在、大小对不对
    · 语料       1000 个模数读得进来，位长是 1023/1024 混排
    · AES        跑 NIST SP 800-38A 官方向量，逐字节比对
    · PBP        跑文件格式解析器的自校验
    · RSA 工具   承诺值可复现、对 d 的每一位敏感
    · 填空机制   填空真的会拦住你，而且 except Exception 吞不掉它

（注意：φ(n) 的两种情形**不在这里**查 —— 它是任务一的内容，
  在 `task1_math.py --selftest` 的【五】里。本自检只覆盖
  「随包给全、与你的填空无关」的那部分。）

用法：
    python check_env.py

输出：
    逐项 ✓/✗；全通过时打印「可以开始实验了」并退出码 0。
    最后附一张**填空进度表** —— 每节课开始和结束时各看一次。
"""

from __future__ import annotations

import platform
import sys
from pathlib import Path

from rsa_common import DATA, DASH, ROOT, SEP, load_moduli, pad, section

MIN_PYTHON = (3, 10)

# 四个任务各自的填空总数。★ 这个表和 code/ 里的 FILL[n] 是一份契约 ★
# tools/check_fills.py 会核对它，所以改了填空数一定要回来改这里。
EXPECTED_BLANKS = {
    "task1_math.py": 10,
    "task2_pair.py": 6,
    "task3_scan.py": 9,
    "task4_decrypt.py": 4,
}


def _line(label: str, ok: bool, detail: str = "") -> bool:
    mark = "✓" if ok else "✗"
    print(f"  {mark} {pad(label, 30)} {detail}")
    return ok


def check_interpreter() -> bool:
    section("1. 解释器")
    v = sys.version_info
    print(f"  {pad('sys.executable', 30)} {sys.executable}")
    print(f"  {pad('Python 版本', 30)} {platform.python_version()}")
    print(f"  {pad('平台', 30)} {platform.system()} {platform.release()}")
    print()

    ok = True
    ok &= _line("Python 版本 >= 3.10",
                v[:2] >= MIN_PYTHON,
                f"当前 {v.major}.{v.minor}"
                + ("" if v[:2] >= MIN_PYTHON
                   else f"，需要 >= {MIN_PYTHON[0]}.{MIN_PYTHON[1]}"))

    # Microsoft Store 的 python.exe 是个转发器，会把 `python` 变成打开应用商店。
    # 它出现时 sys.executable 里通常带 WindowsApps。
    store = "WindowsApps" in sys.executable
    ok &= _line("不是 Microsoft Store 的转发器",
                not store,
                "" if not store else "检测到 WindowsApps —— 请装 python.org 的版本")

    # 路径里有中文或空格，某些老工具会翻车。本实验的脚本都用
    # Path(__file__).resolve() 定位数据，所以能扛住，但还是报一下。
    weird = any(c in str(ROOT) for c in " ")
    print(f"  {pad('实验包根目录', 30)} {ROOT}")
    if weird:
        print(f"  ! {pad('路径含空格', 30)} 本实验的脚本能处理，但命令行里记得加引号")
    return ok


def check_run_mode() -> bool:
    """确认解释器**没有**被 -I / -E 隔离运行。

    【为什么这条检查必须有】
    本包的每个任务都要 `from fill import Blanks` 和 `from rsa_common import ...`
    —— 这两句依赖「脚本所在目录在 sys.path 里」。

    而 `python -I`（隔离模式）做的第一件事就是把脚本目录从 sys.path 里拿掉。
    之后 `import fill` 会报 ModuleNotFoundError: No module named 'fill'，
    而报错信息看起来像是「文件丢了」——学生会去翻目录、重下压缩包，
    排查半天也想不到是命令行多打了一个字母。

    所以这里主动抓它，并把正确的命令直接打出来。
    """
    section("2. 运行方式")
    iso = bool(sys.flags.isolated)
    noenv = bool(getattr(sys.flags, "ignore_environment", False))
    ok = _line("没有用 -I 隔离模式运行", not iso,
               "" if not iso else "检测到 sys.flags.isolated —— 见下面的修复办法")
    ok &= _line("没有用 -E 忽略环境变量", not noenv)

    # 真正的原因：sys.path 里有没有脚本自己所在的目录
    here = str(Path(__file__).resolve().parent)
    in_path = here in [str(Path(p).resolve()) for p in sys.path if p]
    ok &= _line("脚本所在目录在 sys.path 里", in_path,
                "" if in_path else "from fill import ... 会失败")

    if not ok:
        print()
        print("  【修复】去掉命令行里的 -I 和 -E：")
        print("      ✗ python -I check_env.py")
        print("      ✓ python check_env.py")
        print("  本包的脚本不需要任何隔离选项，它不装第三方库、也不读系统环境。")
    return ok


def check_encoding() -> bool:
    section("3. 终端编码")
    try:
        probe = "φ ≈ ² ≥ · ° × −"
        sys.stdout.write(f"  {pad('中文与数学符号', 30)} {probe}\n")
        sys.stdout.flush()
        ok = True
    except UnicodeEncodeError as exc:
        print(f"  ✗ {pad('中文与数学符号', 30)} 输出失败：{exc}")
        print("      → 控制台编码不是 UTF-8。rsa_common 在 import 时已经"
              "尝试切换，")
        print("        如果你看到这一行，说明那一步也失败了。")
        ok = False
    print(f"  {pad('stdout.encoding', 30)} {getattr(sys.stdout, 'encoding', '?')}")
    return ok


def check_data() -> bool:
    section("4. 数据文件")
    ok = True
    expected = {
        "moduli.txt": 200_000,           # 1000 行 × 约 257 字节
        "homework.pdf.enc.asc": 10_000,  # PBP 加密后的通知
    }
    for name, min_size in expected.items():
        p = DATA / name
        if not p.is_file():
            ok &= _line(name, False, "文件不存在")
            continue
        size = p.stat().st_size
        ok &= _line(name, size >= min_size, f"{size:,} 字节")

    # 🔒 学生产物混进 data/ 说明这个包是从跑过的状态打包的
    stray = [f.name for f in DATA.iterdir()
             if f.is_file() and f.name not in expected]
    if stray:
        print(f"  ! {pad('多出来的文件', 30)} {stray}")
        print("      → 上面两个是 data/ 里该有的全部文件。多出来的是跑出来的产物。")
        print("        （如果是 homework.pdf，那是任务四解出来的，说明有人跑过了。）")
    return ok


def check_corpus() -> bool:
    section("5. 语料")
    try:
        moduli = load_moduli()
    except (OSError, ValueError) as exc:
        return _line("读取 moduli.txt", False, str(exc))

    n = len(moduli)
    bits = sorted({m.bit_length() for m in moduli})
    ok = True
    ok &= _line("模数个数", n == 1000, f"{n} 个")
    ok &= _line("位长分布", bits == [1023, 1024],
                f"{bits}（1023/1024 混排是正常的，见指导书附录 B.1）")
    print()
    print("  ⚠ 位长不统一是真实的：生成器没有强制把最高位置 1。")
    print("    如果你为语料写了「每行必须 256 个字符」这类校验，会整体报错。")
    return ok


def check_aes() -> bool:
    section("6. AES（NIST SP 800-38A 官方向量）")
    import aes_soft
    ok = bool(aes_soft._self_test())
    return _line("AES-128/192/256 ECB+CBC", ok,
                 "" if ok else "向量不符 —— 本包可能被改过")


def check_pbp() -> bool:
    section("7. PBP 文件格式")
    import pbp_common
    ok = bool(pbp_common._self_test())
    return ok


def check_rsa_common() -> bool:
    section("8. RSA 公共工具")
    import rsa_common
    ok = bool(rsa_common._self_test())
    return ok


def check_fill_mechanism() -> bool:
    """确认填空机制真的会拦住你 —— 而且拦得住。

    【为什么要验这个】
    「填空没填就报错」是学生唯一的安全网。如果它悄悄失效了（比如被某个
    `except Exception` 吞掉），学生会拿到一个**沉默算错**的结果 ——
    这比直接报错难查一百倍。

    所以这里真的去踩一次：制造一个未填的空，看它抛不抛、抛得对不对，
    再确认它**不会**被 `except Exception` 吞掉。
    """
    section("9. 填空机制")
    from fill import BlankNotFilled, Blanks

    ok = True

    # (a) 取未填的空必须抛 BlankNotFilled
    f = Blanks()
    try:
        _ = f[1]
        ok &= _line("未填的空会抛出专门异常", False, "取 FILL[1] 竟然没有报错")
    except BlankNotFilled as exc:
        # (b) 报错信息里要能看到真实文件与编号 —— 这是「免救火」的关键。
        #     注意 exc.file 必须是**调用方**的文件，不是 fill.py：
        #     指向 fill.py 的报错会把学生引去改那个「不要修改」的文件。
        good = ("FILL[1]" in str(exc) and exc.n == 1
                and exc.file.endswith(".py")
                and not exc.file.endswith("fill.py"))
        ok &= _line("未填的空会抛出专门异常", good,
                    f"n={exc.n} file={Path(exc.file).name} line={exc.line}"
                    + ("" if good else " ← 指向了 fill.py，学生会被带偏"))

    # (c) ★ 关键：except Exception 吞不掉它
    #     这是 BlankNotFilled 故意继承 BaseException 的原因
    caught = "没被吞掉"
    try:
        try:
            _ = Blanks()[1]
        except Exception:                       # noqa: BLE001  故意写宽，测试用
            caught = "被 except Exception 吞掉了"
    except BlankNotFilled:
        caught = "穿过了 except Exception"
    ok &= _line("except Exception 吞不掉它", caught == "穿过了 except Exception",
                caught)

    # (d) 给 FILL[n] 赋值要被明确拒绝（学生会想「我给它赋值不就行了」）
    try:
        Blanks()[1] = 42
        ok &= _line("赋值被拒绝", False, "竟然允许给 FILL[1] 赋值")
    except TypeError as exc:
        ok &= _line("赋值被拒绝", "不要给" in str(exc), str(exc)[:40] + "…")
    return ok


def blank_progress() -> None:
    """打印四个任务的填空进度。

    【为什么要做成表】
    机房场景下最贵的是老师的时间。一眼扫过去就知道谁卡在哪，
    比逐个学生问「你做到哪了」快得多；学生自己也能看到「还差几处」。

    计数用 ast 而不是 grep：提示注释里也会出现 FILL[2] 这几个字
    （「把 FILL[2] 换成你的代码」），grep 会把注释数成代码 ——
    实测一处填空能被数成三处。
    """
    import ast

    section("填空进度")
    code_dir = Path(__file__).resolve().parent
    total_done = total_all = 0
    rows: list[tuple[str, int, int]] = []

    for fname, expect in EXPECTED_BLANKS.items():
        path = code_dir / fname
        if not path.is_file():
            rows.append((fname, 0, expect))
            total_all += expect
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            rows.append((fname, -1, expect))        # -1 表示语法都过不了
            total_all += expect
            continue
        left = sum(
            1 for node in ast.walk(tree)
            if isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name) and node.value.id == "FILL"
            and not isinstance(node.ctx, ast.Store)
        )
        # 表格里的「总数」以契约为准；left 只用来算已填数
        done = max(0, expect - left)
        rows.append((fname, done, expect))
        total_done += done
        total_all += expect

    for fname, done, expect in rows:
        if done < 0:
            print(f"  ✗ {pad(fname, 18)} 语法错误 —— 先修好")
            continue
        bar = "█" * done + "░" * (expect - done)
        mark = "  ✓" if done == expect else ""
        print(f"  {pad(fname, 18)} {bar}  {done} / {expect}{mark}")

    print()
    if total_done == total_all:
        print(f"  合计 {total_done} / {total_all} —— 全部填完，可以跑 run_all.py 了。")
    else:
        print(f"  合计 {total_done} / {total_all}")
        print("  没填完不要紧：跑到那一行会告诉你具体是哪个文件的第几行。")


def main() -> None:
    print(SEP)
    print("rsa-lab4 环境自检（本科 2 学时版）")
    print(SEP)

    results = [
        ("解释器", check_interpreter()),
        ("运行方式", check_run_mode()),
        ("终端编码", check_encoding()),
        ("数据文件", check_data()),
        ("语料", check_corpus()),
        ("AES", check_aes()),
        ("PBP", check_pbp()),
        ("公共工具", check_rsa_common()),
        ("填空机制", check_fill_mechanism()),
    ]

    print()
    blank_progress()

    print()
    print(SEP)
    bad = [name for name, ok in results if not ok]
    if bad:
        print(f"有 {len(bad)} 项没过：{', '.join(bad)}")
        print()
        print("先把这些解决掉再开始做题 —— 环境问题暴露得越晚，代价越大。")
        raise SystemExit(1)

    print("全部通过 —— 可以开始实验了。")
    print(SEP)
    print()
    print("下一步：")
    print("  任务一（课前预习，若还没做）：python task1_math.py --selftest")
    print("  任务二                     ：python task2_pair.py")
    print("  想一眼看全链               ：python run_all.py --progress")
    print(DASH)
    print("本包不需要 pip install 任何东西：AES 是随包附带的纯标准库实现。")


if __name__ == "__main__":
    main()
