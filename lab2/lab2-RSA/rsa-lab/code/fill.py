"""填空机制的实现。★ 本文件不要修改 ★

【它是什么】
本实验的四个任务文件是**骨架**，中间留了 29 处空。每一处空长这样：

        g = FILL[1]

在你把它换成真正的代码之前，程序跑到这一行会停下来，并且告诉你
**是哪个文件、第几行、第几个空**：

        FILL[1] not filled yet -- code/task2_pair.py 第 96 行:
            |     g = FILL[1]
        把 FILL[1] 这几个字删掉，在原位写你的代码。

【怎么填】
把 `FILL[1]` 这**五个字符加方括号**整体删掉，在原位写上你的代码。
不是给它赋值，不是写在它旁边 —— 是**替换**它。

    ✗   FILL[1] = math.gcd(n1, n2)       ← 错：这是在给 FILL[1] 赋值
    ✗   g = FILL[1]  # 答案是 math.gcd   ← 错：注释不算代码
    ✓   g = math.gcd(n1, n2)             ← 对：原来的 FILL[1] 不见了

【为什么要费这个劲，而不是直接写 raise NotImplementedError】
因为那样一次只能报一个错，而且报错位置在**这个文件**里 —— 学生第一反应
是来改 fill.py。本机制做了四件事，都是冲着「机房里没人能逐个救火」去的：

  1. 报错给出**真实文件和行号**，还把那行源码打出来 —— 不用猜
  2. 文件**始终可以 import、可以 --help**，只有跑到那一行才失败
  3. `FILL[3] = ...` 这种写法会被专门拦下并说明怎么改
  4. 空的个数可以用 ast 精确数出来，run_all.py 因此能打印填空进度表

【为什么 BlankNotFilled 继承 BaseException 而不是 Exception】
这是被 rsa-lab2 咬出来的。那个包里用 `raise NotImplementedError` 标记
未完成，而 NotImplementedError 是 Exception 的子类 —— 于是一句
`try: ... except Exception: pass` 就能把它**吞掉**，程序继续往下跑，
带着一个空值，最后在一个毫不相干的地方崩溃。
（rsa-lab2 自己的 task4_decrypt.py 就不得不为此写
`except NotImplementedError: raise` 来把异常重新抛出。）

BaseException 是 KeyboardInterrupt 和 SystemExit 的父类，`except Exception`
抓不到它 —— 所以本包的填空**吞不掉**。这是刻意的。
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

# Windows 控制台默认 GBK。报错信息里有中文，也可能有从源码里带出来的
# ² ≈ 之类符号 —— 那些 GBK 编不了。若不处理，**报错本身**会抛
# UnicodeEncodeError，学生看到的是一段和填空毫无关系的编码异常。
# 只改 errors 不改 encoding：让中文照常正常显示，只把编不了的转义掉。
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(errors="backslashreplace")


class BlankNotFilled(BaseException):
    """某个空还没填。★ 故意继承 BaseException（见模块开头的说明）。"""

    def __init__(self, n: int, frame) -> None:
        # 【frame 是**传进来**的，不是在这里自己数栈帧数出来的】
        #
        # 这里踩过一个坑，值得记下来。最初的写法是在 __init__ 里
        # 调 sys._getframe(1)，想当然地以为「上一层就是学生写
        # FILL[n] 的那一帧」。错了 —— __init__ 的调用者是
        # __getitem__，所以 _getframe(1) 拿到的是 fill.py 自己的帧，
        # _getframe(2) 才是学生的。报错于是变成
        #     「FILL[1] not filled yet -- fill.py 第 91 行」
        # 而 91 行是 `raise BlankNotFilled(n)`。
        #
        # 数栈帧这种方式，只要中间多一层或少一层包装就错，而且错得
        # 很安静（只是指向错误的文件）。改成由 __getitem__ 显式传，
        # 唯一确定，也不用担心以后加包装。
        self.n = n
        self.file = frame.f_code.co_filename
        self.line = frame.f_lineno

        # 顺手把那行源码取出来打给他看。linecache 是标准库，
        # 对磁盘上的文件一定能取到（本包的所有脚本都在磁盘上）。
        try:
            import linecache
            src = linecache.getline(self.file, self.line).rstrip()
        except Exception:                      # noqa: BLE001 —— 取不到就算了
            src = ""

        where = Path(self.file).name
        msg = [f"FILL[{n}] not filled yet -- {where} 第 {self.line} 行:"]
        if src.strip():
            msg.append(f"    | {src.strip()}")
        msg.append(f"把 FILL[{n}] 这几个字删掉，在原位写你的代码。")
        super().__init__("\n".join(msg))


class Blanks:
    """空本身。`FILL[n]` 会落到 __getitem__ 上。"""

    def __getitem__(self, n: int):
        # _getframe(1) 在这里是**对的** —— 本帧是 _getframe(0)，
        # 调用方（学生写下 FILL[n] 的那一行）就是 1。
        raise BlankNotFilled(n, sys._getframe(1))

    def __setitem__(self, n, value):
        # 学生很容易把「填」理解成「赋值」。这个错误必须被专门接住，
        # 否则他看到的是一句没有上下文的 TypeError，然后去改 fill.py。
        raise TypeError(
            f"不要给 FILL[{n}] 赋值 —— 把 FILL[{n}] 这几个字删掉，"
            f"在原位直接写你的代码。\n"
            f"（FILL[{n}] = ... 是「给它赋值」，而你要做的是「替换它」。）"
        )


# ---------------------------------------------------------------------------
# 用 ast 精确数出文件里有多少个空、都在第几行
# ---------------------------------------------------------------------------
#
# 【为什么必须用 ast，不能正则】
# 提示注释里也会出现 FILL[2] 这几个字。实测：一个写着 2 个空的文件，
# 用正则 `FILL\[` 数出来是 **3** 个 —— 多出来的是注释里那句
# 「TODO(2): 原来的 FILL[2] 应该换成一整条语句」。
# 数错不致命，但 run_all.py 的填空进度表会一直显示「填不完」，
# 而学生已经填完了。那种「你的工具在骗你」的体验最伤信任。


def find_blanks(source: str) -> list[tuple[int, int]]:
    """返回 [(行号, 编号), ...]，按行号排序。

    行号是 `FILL[n]` 里那个 n 所在的行的行号。同时把 `FILL[n] = x`
    这种写法也算进来 —— 那是错误写法，但**不能让它藏起来**：
    进度表要看得见它，check_fills.py 要能点名批评它。
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    found: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Subscript):
            continue
        # FILL[...]
        base = node.value
        if not (isinstance(base, ast.Name) and base.id == "FILL"):
            continue
        idx = node.slice
        if isinstance(idx, ast.Constant) and isinstance(idx.value, int):
            found.append((node.lineno, idx.value))
    return sorted(found)


def count_blanks(path: Path | str) -> tuple[int, list[int]]:
    """数一个文件里的空。返回 (个数, 编号列表)。"""
    src = Path(path).read_text(encoding="utf-8", errors="replace")
    blanks = find_blanks(src)
    return len(blanks), [n for _, n in blanks]


def reference_count() -> int:
    """本实验一共留了多少个空。

    写死在这里，是因为它同时出现在指导书、上机步骤、PPT 和报告模板里，
    改一处漏一处会让文档自相矛盾。run_all.py 拿它和实测值对，
    对不上就报出来 —— 文档与代码不一致这件事必须有人管。
    """
    return 29


# ---------------------------------------------------------------------------
# 统一的入口包装
# ---------------------------------------------------------------------------
#
# 【为什么给一个专门的退出码】
# 每个 task*.py 的结尾都是 `run(main)`。跑到空没填时，它打印提示并以
# **退出码 3** 结束。这件事看着小，但它决定了 run_all.py 能不能把
# 「你还有空没填」和「你的代码真的报错了」分开：
#
#     退出码 0   这一关过了
#     退出码 3   还有空没填（正常状态，不是坏事，进度表会显示）
#     其他       真的出错了（语法错、文件找不到、答案算错……）
#
# 没有这个区分，run_all 只会说「第 3 步失败」，而学生分不清是
# 「我还没填完」还是「我填错了」—— 那是两种完全不同的下一步动作。

EXIT_BLANK = 3


def run(main_fn) -> None:
    """跑 main_fn()；遇到没填的空就打印提示并以 EXIT_BLANK 结束。

    每个 task*.py 的结尾都写成：

        if __name__ == "__main__":
            run(main)
    """
    try:
        main_fn()
    except BlankNotFilled as exc:
        # 打到 **stdout** 而不是 stderr。两个理由：
        #   1. 「还有空没填」是**正常状态**，不是程序出错。本实验里
        #      每个学生都会看到它几十次，把它染成红色错误流会让人心慌。
        #   2. stdout 被重定向到文件时是块缓冲的，stderr 不是 ——
        #      打到 stderr 的话，`python x.py > out.txt` 之后提示会
        #      跑到文件外面、顺序也乱。打到 stdout 才能保证
        #      「先看到自检的标题，再看到停在哪一处空」。
        print()
        print("=" * 64)
        print(exc)
        print("=" * 64)
        print(f"（退出码 {EXIT_BLANK}：还有空没填 —— 这不是程序出错。"
              f"查进度：python run_all.py --progress）")
        raise SystemExit(EXIT_BLANK) from None


if __name__ == "__main__":
    import sys as _sys

    _sys.stderr.write(
        "fill.py 是填空机制的实现，不需要单独运行。\n"
        "★ 本文件不要修改 ★ —— 你要填的空都在 task1..task4 里。\n"
        "想知道还有几个空没填：python run_all.py --progress\n"
    )
