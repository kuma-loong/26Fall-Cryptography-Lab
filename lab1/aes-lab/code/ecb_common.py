"""公共模块：消息格式定义 + AES-ECB / CBC / GCM 封装 + 历史密文库。

⚠️ 这个文件里有 KEY。凡是**扮演攻击者**的程序都不应该 import 它。
   攻击者只允许用 block_utils.py。

依赖：cryptography
    pip install cryptography
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from block_utils import to_blocks  # noqa: F401  （供外部 from ecb_common import 使用）

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
HISTORY_FILE = DATA_DIR / "history.json"

# ---------------------------------------------------------------------------
# 密钥
# ---------------------------------------------------------------------------
# 真实系统里密钥来自密钥管理系统。这里为了全班结果一致，用一个固定的派生值。
# 注意：**这个密钥只出现在本文件和 alice/bob 两个程序里**，攻击者程序看不到它。

DEMO_KEY = hashlib.sha256(b"cryptography-course/ecb-demo/v1").digest()[:16]

# ---------------------------------------------------------------------------
# 消息格式
# ---------------------------------------------------------------------------


def format_naive(sender: str, to: str, date: str, place: str) -> str:
    """格式 A：自然写法。字段长度不定，不保证与 16 字节分组边界对齐。"""
    return f"From: {sender}\nTo: {to}\nDate: {date}\nPlace: {place}"


# 格式 B：每个字段恰好占一个分组
W_SENDER, W_TO, W_DATE, W_PLACE = 10, 12, 10, 8


def format_aligned(sender: str, to: str, date: str, place: str) -> str:
    """格式 B：定长对齐写法。

        "From: " (6) + sender(10)   = 16   <- 分组 0
        "To: "   (4) + to(12)       = 16   <- 分组 1
        "Date: " (6) + date(10)     = 16   <- 分组 2
        "Place: "(7) + place(8)     = 15   <- 分组 3 的前 15 字节
                                     ----
                                      63   PKCS#7 再补 1 字节 -> 64 字节

    一个字段正好一个分组，这是本实验的攻击能干净成立的前提。
    """
    if len(sender) > W_SENDER:
        raise ValueError(f"发件人过长：{sender!r}（最多 {W_SENDER} 字符）")
    if len(to) > W_TO:
        raise ValueError(f"收件人过长：{to!r}（最多 {W_TO} 字符）")
    if len(date) != W_DATE:
        raise ValueError(f"日期必须恰好 {W_DATE} 位：{date!r}")
    if len(place) > W_PLACE:
        raise ValueError(f"地点过长：{place!r}（最多 {W_PLACE} 字符）")
    return (
        "From: " + sender.ljust(W_SENDER)
        + "To: " + to.ljust(W_TO)
        + "Date: " + date.ljust(W_DATE)
        + "Place: " + place.ljust(W_PLACE)
    )


def pretty_aligned(plaintext: bytes) -> str:
    """把格式 B 的明文字节还原成人类可读的多行形式。

    Mallory 做的是纯字节搬运；这个函数只是让人看得懂结果。
    """
    t = plaintext.decode("latin-1")
    parts, i = [], 0
    for w in (16, 16, 16, 15):
        parts.append(t[i : i + w].rstrip())
        i += w
    return "\n".join(parts)


def parse_aligned(plaintext: bytes) -> dict[str, str]:
    """把格式 B 的明文拆成四个字段。

    布局（共 63 字节）：
        0..5    "From: "      6..15   sender(10)
        16..19  "To: "        20..31  to(12)
        32..37  "Date: "      38..47  date(10)
        48..54  "Place: "     55..62  place(8)
    """
    t = plaintext.decode("latin-1")
    return {
        "sender": t[6:16].strip(),
        "to": t[20:32].strip(),
        "date": t[38:48].strip(),
        "place": t[55:63].strip(),
    }


# ---------------------------------------------------------------------------
# 三种模式
# ---------------------------------------------------------------------------


def ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(padded) + enc.finalize()


def ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(padded) + enc.finalize()


def cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """返回 密文 || 16 字节认证标签。"""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return AESGCM(key).encrypt(nonce, plaintext, None)


def gcm_decrypt(key: bytes, nonce: bytes, blob: bytes) -> bytes:
    """认证失败会抛 InvalidTag —— 这正是 AEAD 的价值。"""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return AESGCM(key).decrypt(nonce, blob, None)


# ---------------------------------------------------------------------------
# 历史密文库
# ---------------------------------------------------------------------------

# Mallory 在网络上抓到的 6 条密文。他用自己对这些消息内容的了解（或猜测）
# 给它们做了标注 —— 这就是已知明文假设。
HISTORY_MESSAGES = [
    ("M1", "Alice", "Bob", "2026-03-15", "Library"),
    ("M2", "Alice", "Bob", "2026-03-15", "Gym"),
    ("M3", "Alice", "Bob", "2026-03-22", "Library"),
    ("M4", "Carol", "Dave", "2026-03-15", "Office"),
    ("M5", "Bob", "Alice", "2026-04-01", "Cafe"),
    ("M6", "Alice", "Carol", "2026-03-15", "Library"),
]


def build_history(fmt: str = "aligned", include_plaintext: bool = False) -> list[dict]:
    """用密钥把历史消息加密一遍，得到历史密文库。

    include_plaintext=False（默认）是**发给学生的那一份** ——
    里面只有密文和公开的字段标注，没有任何明文。
    这是实验的前提：Mallory 手上只有密文。

    include_plaintext=True 供教师核对答案用（见 教师参考/gen_teacher_history.py），
    **那一份不能发给学生**。
    """
    maker = format_aligned if fmt == "aligned" else format_naive
    out = []
    for mid, s, t, d, p in HISTORY_MESSAGES:
        plain = maker(s, t, d, p).encode("latin-1")
        entry = {
            "id": mid,
            "sender": s, "to": t, "date": d, "place": p,
            "format": fmt,
            "ciphertext_hex": ecb_encrypt(DEMO_KEY, plain).hex(),
        }
        if include_plaintext:
            entry["plaintext_hex"] = plain.hex()
        out.append(entry)
    return out


def save_history(fmt: str = "aligned") -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "note": "这里是密文，没有密钥。攻击者程序只能读到这些。",
        "key_length": 16,
        "messages": build_history(fmt),
    }
    HISTORY_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return HISTORY_FILE


def load_history() -> list[dict]:
    if not HISTORY_FILE.exists():
        raise FileNotFoundError(
            f"找不到 {HISTORY_FILE}\n请先运行：python alice_encrypt.py --build-history"
        )
    return json.loads(HISTORY_FILE.read_text(encoding="utf-8"))["messages"]


def by_id(messages: list[dict], mid: str) -> dict:
    for m in messages:
        if m["id"] == mid:
            return m
    raise KeyError(f"历史库里没有 {mid}")
