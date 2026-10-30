"""任务二：长度扩展攻击。【8 处填空】★ 主交付物

场景
----
银行 API 用下面这条规则签名：

    token = MD5(password || user=...&command1=...&command2=...)

密码 8 个字符，攻击者不知道它的值。但签名规则把密码放在了消息**前面**，
这正是长度扩展能打的地方。

你要做的：拿一条合法 URL，不改 token 里的密码，追加

    &command3=UnlockAllSafes

并让服务端返回 200。产物写进 data/forged_url.txt。


"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import quote_from_bytes, unquote_to_bytes, urlsplit

sys.path.insert(0, str(Path(__file__).parent))

from fill import Blanks, run          # noqa: E402
import api_common                      # noqa: E402
import md5_soft                        # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FILL = Blanks()

DATA = Path(__file__).resolve().parent.parent / "data"
SAMPLE = DATA / "sample_url.txt"
OUT = DATA / "forged_url.txt"
SUFFIX = b"&command3=UnlockAllSafes"


def split_url(url: str) -> tuple[str, str, bytes]:
    """拆出 token、原始查询串、解码后的消息字节。"""
    query = urlsplit(url).query
    if not query.startswith("token="):
        raise ValueError("URL 必须以 token= 开头")

    # TODO(1): 在第一个 & 处切开：左边是 token=...，右边是消息。
    token_part, raw_msg = query.split("&", 1)

    # TODO(2): 去掉 token= 前缀，留下 32 个十六进制字符。
    token_hex = token_part[6:]

    # TODO(3): 把百分号编码还原成字节。只解码一次。
    msg = unquote_to_bytes(raw_msg)

    return token_hex, raw_msg, msg


def forge(url: str, secret_len: int = 8, suffix: bytes = SUFFIX) -> str:
    """在不知道密码的情况下，伪造一条带 command3 的 URL。"""
    token_hex, _, msg = split_url(url)

    # TODO(4): 算出 password || msg 的 MD5 填充。
    #          长度是 secret_len + len(msg)。
    pad = md5_soft.padding(secret_len + len(msg))

    # TODO(5): 把填充和 suffix 接在消息后面。
    new_msg = msg + pad + suffix

    # TODO(6): 新消息总共处理过多少比特？
    count = (secret_len + len(msg) + len(pad)) * 8

    # 用旧 token 当初始状态，继续压 suffix。
    h = md5_soft.md5(state=bytes.fromhex(token_hex), count=count)

    # TODO(7): 把 suffix 喂进去。
    h.update(suffix)
    new_token = h.hexdigest()

    # TODO(8): 拼回完整 URL。消息部分要用 quote_from_bytes 编码，
    #          safe 传空字符串，让 & 和 = 也编码。
    new_url = urlsplit(url)._replace(query=f"token={new_token}&{quote_from_bytes(new_msg, safe='')}").geturl()

    return new_url


def _print_result(label: str, url: str) -> dict:
    result = api_common.handle(url)
    print(f"  {label}")
    print(f"    status = {result['status']}")
    if result.get("error"):
        print(f"    error  = {result['error']}")
    if result["status"] == 200:
        print(f"    unlock = {result['unlock']}")
        print(f"    command3 = {result['commands'].get('command3', '（没有）')}")
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description="长度扩展攻击")
    ap.add_argument("--secret-len", type=int, default=8,
                    help="密码长度，默认 8")
    args = ap.parse_args()

    DATA.mkdir(parents=True, exist_ok=True)
    if not SAMPLE.exists():
        print(f"找不到 {SAMPLE}。先运行 python issue_url.py")
        raise SystemExit(1)

    url = SAMPLE.read_text(encoding="utf-8").strip()
    token_hex, raw_msg, msg = split_url(url)

    print()
    print("=" * 70)
    print("  任务二：长度扩展攻击")
    print("=" * 70)
    print()
    print(f"  原始 URL 的消息部分（{len(msg)} 字节）：")
    print(f"    {msg.decode('utf-8', 'replace')}")
    print(f"  token：{token_hex}")
    print(f"  已知密码长度：{args.secret_len}")
    print()

    print("  原始请求：")
    _print_result("bank", url)
    print()

    forged = forge(url, args.secret_len)
    print("  伪造请求：")
    result = _print_result("bank", forged)
    print()

    padding_len = len(md5_soft.padding(args.secret_len + len(msg)))
    print(f"  填充长度：{padding_len} 字节")
    print(f"  新消息长度：{len(msg) + padding_len + len(SUFFIX)} 字节")
    print()

    if result["status"] == 200 and result["unlock"]:
        print("  ★ 成功。服务端认为这条请求是 alice 发的。")
        print("    攻击者不知道密码，只知道 token 和密码长度。")
    else:
        print("  ★ 还没有成功。检查顺序：")
        print("    1. 填充长度用的是 secret_len + len(msg)，不是 len(msg)；")
        print("    2. count 乘了 8；")
        print("    3. suffix 既喂给了 h.update()，也拼进了 new_msg；")
        print("    4. 消息编码用了 quote_from_bytes，safe=''。")

    OUT.write_text(forged + "\n", encoding="utf-8")
    print()
    print(f"  已写出：{OUT}")
    print()

    # 给报告留一份结构化结果
    report = {
        "original_url": url,
        "original_token": token_hex,
        "forged_url": forged,
        "secret_len": args.secret_len,
        "message_len": len(msg),
        "padding_len": padding_len,
        "new_message_len": len(msg) + padding_len + len(SUFFIX),
        "status": result["status"],
        "unlock": result["unlock"],
        "command3": result["commands"].get("command3"),
    }
    (DATA / "task2_result.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")

    if result["status"] != 200 or not result["unlock"]:
        raise SystemExit(1)


if __name__ == "__main__":
    run(main)
