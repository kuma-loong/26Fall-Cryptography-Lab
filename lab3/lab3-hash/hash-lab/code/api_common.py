"""银行 API 的服务端逻辑。

这个文件同时扮演两个角色：

    签发 URL    issue_url()
    校验 URL    handle()

服务端签名规则（这是不安全的地方）：

    token = MD5(password || 从 user= 开始到最后的原始查询串)

密码固定 8 个字符。学生不需要知道密码，也不需要打开这个文件去找它。
本次实验的攻击只用三样东西：token、消息、密码长度。
"""

from __future__ import annotations

import sys
from urllib.parse import quote_from_bytes, unquote_to_bytes, urlsplit

from md5_soft import md5

# 8 字节的服务端密码。学生做实验时不要读这一行。
SECRET = b"kR7$w2!q"

DEFAULT_USER = "alice"
DEFAULT_COMMAND1 = "ListSquirrels"
DEFAULT_COMMAND2 = "NoOp"


def build_message(user: str, command1: str, command2: str) -> bytes:
    return f"user={user}&command1={command1}&command2={command2}".encode("utf-8")


def issue_url(user: str = DEFAULT_USER,
              command1: str = DEFAULT_COMMAND1,
              command2: str = DEFAULT_COMMAND2) -> str:
    """签发一个合法 URL。token 覆盖的是 user=... 这一段。"""
    msg = build_message(user, command1, command2)
    token = md5(SECRET + msg).hexdigest()
    return (
        "http://bank.cse127.local/api?"
        f"token={token}&{quote_from_bytes(msg, safe='=&')}"
    )


def split_url(url: str) -> tuple[str, str, bytes]:
    """把 URL 拆成 (token, 原始查询串, 解码后的消息字节)。

    只解码一次。这一点很重要：padding 里的 %00、%80 不能被解码两次。
    """
    query = urlsplit(url).query
    if not query.startswith("token="):
        raise ValueError("URL 必须以 token= 开头")
    token_part, sep, raw_msg = query.partition("&")
    if not sep:
        raise ValueError("URL 里没有消息部分")
    token = token_part[len("token="):]
    return token, raw_msg, unquote_to_bytes(raw_msg)


def handle(url: str) -> dict:
    """服务端处理一个请求，返回判定结果。

    返回字段：
        status   200 或 403
        unlock   True 表示执行了 command3=UnlockAllSafes
        commands 解码后解析出的命令
    """
    try:
        token, _, msg = split_url(url)
    except ValueError as exc:
        return {"status": 400, "unlock": False, "error": str(exc), "commands": {}}

    expected = md5(SECRET + msg).hexdigest()
    if token.lower() != expected:
        return {"status": 403, "unlock": False,
                "error": "token 不匹配", "commands": {}}

    text = msg.decode("utf-8", "replace")
    commands: dict[str, str] = {}
    for part in text.split("&"):
        key, _, value = part.partition("=")
        if key:
            commands[key] = value

    return {
        "status": 200,
        "unlock": commands.get("command3") == "UnlockAllSafes",
        "commands": commands,
        "msg_len": len(msg),
    }


def main() -> None:
    if len(sys.argv) != 2:
        print("用法：python api_common.py \"<URL>\"")
        print("不传 URL 时打印一个合法样例：")
        print(issue_url())
        return
    result = handle(sys.argv[1])
    print(f"status = {result['status']}")
    if result.get("error"):
        print(f"error  = {result['error']}")
    if result["status"] == 200:
        print(f"unlock = {result['unlock']}")
        print(f"命令   = {result['commands']}")


if __name__ == "__main__":
    main()
