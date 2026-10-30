"""交作业之前跑一遍，核对四个任务的产物。

    python verify.py              # 性质检查
    python verify.py --appendix-b # 再和教师参考/answers.json 对一遍

性质检查只看「对不对」，不看「是不是抄的」。真正要证明是你自己做的，
报告里要有自己的输出和解释。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import api_common                       # noqa: E402
import md5_soft                         # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CODE = Path(__file__).resolve().parent
DATA = CODE.parent / "data"
REF = CODE.parent / "教师参考" / "answers.json"

passed = 0
failed = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global passed, failed
    if condition:
        passed += 1
        print(f"  ✓ {label}" + (f"    {detail}" if detail else ""))
    else:
        failed += 1
        print(f"  ✗ {label}" + (f"    {detail}" if detail else ""))


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def check_task1() -> None:
    print("[1] 任务一：填充与续写")
    p = DATA / "task1_padding.json"
    d = load_json(p)
    check("task1_padding.json 存在", bool(d), str(p))
    if not d:
        return
    check("old + padding + suffix 的摘要与直接哈希相同", d.get("same") is True)
    check("填充长度等于 padding() 的结果",
          d.get("padding_len") == len(md5_soft.padding(d.get("original_len", 0))))
    check("续写摘要和直接摘要都是 32 位十六进制",
          len(d.get("extended", "")) == 32 and len(d.get("direct", "")) == 32)
    print()


def check_task2() -> None:
    print("[2] 任务二：长度扩展攻击")
    p = DATA / "forged_url.txt"
    check("forged_url.txt 存在", p.exists(), str(p))
    if not p.exists():
        print()
        return
    url = p.read_text(encoding="utf-8").strip()
    result = api_common.handle(url)
    check("服务端返回 200", result.get("status") == 200,
          f"实际 {result.get('status')}")
    check("执行了 UnlockAllSafes", result.get("unlock") is True)

    try:
        token, _, msg = api_common.split_url(url)
    except ValueError as exc:
        check("URL 可解析", False, str(exc))
        print()
        return
    check("消息里带着 MD5 填充（0x80）", b"\x80" in msg)
    old_token = load_json(DATA / "task2_result.json").get("original_token", "")
    check("新 token 和原始 token 不同", token != old_token, token[:16] + "…")
    check("消息里带着 command3", b"&command3=UnlockAllSafes" in msg)
    print()


def run_program(path: Path) -> str:
    proc = subprocess.run([sys.executable, str(path)],
                          capture_output=True, text=True, timeout=20)
    return proc.stdout.strip()


def check_task3() -> None:
    print("[3] 任务三：碰撞与两个同哈希程序")
    report = load_json(DATA / "collision_report.json")
    check("collision_report.json 存在", bool(report))
    good = DATA / "good"
    evil = DATA / "evil"
    check("data/good 存在", good.exists())
    check("data/evil 存在", evil.exists())
    if not (good.exists() and evil.exists()):
        print()
        return

    gb = good.read_bytes()
    eb = evil.read_bytes()
    check("两个文件 MD5 相同",
          hashlib.md5(gb).digest() == hashlib.md5(eb).digest(),
          hashlib.md5(gb).hexdigest())
    check("两个文件 SHA-256 不同",
          hashlib.sha256(gb).digest() != hashlib.sha256(eb).digest())
    check("good 输出正确", run_program(good) == "I mean no harm.")
    check("evil 输出正确", run_program(evil) == "You are doomed!")
    check("两个文件都以碰撞块开头",
          gb[:128] == (DATA / "collision_a.bin").read_bytes()
          and eb[:128] == (DATA / "collision_b.bin").read_bytes())
    print()


def check_task4() -> None:
    print("[4] 任务四：防御")
    d = load_json(DATA / "defense.json")
    check("defense.json 存在", bool(d))
    if not d:
        print()
        return
    check("长度扩展演示成功", d.get("extension_works") is True)
    check("正确 HMAC 通过", d.get("hmac_good_ok") is True)
    check("错误 HMAC 不通过", d.get("hmac_bad_ok") is False)
    check("总检查通过", d.get("ok") is True)
    print()


def check_appendix_b() -> None:
    print("[B] 与教师参考 answers.json 对照")
    if not REF.exists():
        print("  （教师参考/ 不在，跳过）")
        print()
        return
    ans = json.loads(REF.read_text(encoding="utf-8"))

    forged = DATA / "forged_url.txt"
    if forged.exists():
        check("伪造 token 与参考答案一致",
              api_common.split_url(forged.read_text(encoding="utf-8").strip())[0]
              == ans["forged_token"])

    report = load_json(DATA / "collision_report.json")
    if report:
        check("碰撞块的 MD5 与参考答案一致",
              report.get("md5_a") == ans["collision"]["md5"])
        check("good/evil 的 MD5 与参考答案一致",
              report.get("good_md5") == ans["programs"]["good_md5"]
              and report.get("evil_md5") == ans["programs"]["evil_md5"])
    print()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--appendix-b", action="store_true",
                    help="和教师参考/answers.json 对照")
    args = ap.parse_args()

    print()
    print("=" * 66)
    print("  交付物核对")
    print("=" * 66)
    print()

    check_task1()
    check_task2()
    check_task3()
    check_task4()
    if args.appendix_b:
        check_appendix_b()

    print("=" * 66)
    print(f"通过 {passed} 项，失败 {failed} 项")
    if failed == 0:
        print("全部通过。可以交报告了。")
    else:
        print("有失败项。按上面的 ✗ 逐项检查。")
    print("=" * 66)
    raise SystemExit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
