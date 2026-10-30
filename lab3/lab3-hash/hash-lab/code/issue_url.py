"""签发一条合法的银行 API URL，写进 data/sample_url.txt。

学生拿到的输入就是它。密码不在输出里，只在 token 里。
"""

from __future__ import annotations

import argparse
from pathlib import Path

from api_common import issue_url

DATA = Path(__file__).resolve().parent.parent / "data"


def main() -> None:
    ap = argparse.ArgumentParser(description="签发一条银行 API URL")
    ap.add_argument("--user", default="alice")
    ap.add_argument("--command1", default="ListSquirrels")
    ap.add_argument("--command2", default="NoOp")
    ap.add_argument("--out", default=str(DATA / "sample_url.txt"))
    args = ap.parse_args()

    url = issue_url(args.user, args.command1, args.command2)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(url + "\n", encoding="utf-8")
    print(url)
    print(f"已写入 {out}")


if __name__ == "__main__":
    main()
