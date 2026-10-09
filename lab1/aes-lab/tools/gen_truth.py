"""生成《实验指导书》附录 B 的真值数据。

只用标准库（依赖同目录的 aes_ref.py），不需要安装任何第三方包。
输出为 Markdown，直接写进 tools/_truth_output.md。

用法：
    python gen_truth.py
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from aes_ref import (
    _expand_key,
    cbc_decrypt,
    cbc_encrypt,
    decrypt_block,
    ecb_decrypt,
    ecb_encrypt,
    to_blocks,
)

OUT = Path(__file__).with_name("_truth_output.md")

# ---------------------------------------------------------------------------
# 场景设定
# ---------------------------------------------------------------------------

KEY = hashlib.sha256(b"cryptography-course/ecb-demo/v1").digest()[:16]

# 历史密文库：Mallory 在网络上抓到的 6 条密文（他知道这些消息的大致内容）
HISTORY = [
    ("M1", "Alice", "Bob", "2026-03-15", "Library"),
    ("M2", "Alice", "Bob", "2026-03-15", "Gym"),
    ("M3", "Alice", "Bob", "2026-03-22", "Library"),
    ("M4", "Carol", "Dave", "2026-03-15", "Office"),
    ("M5", "Bob", "Alice", "2026-04-01", "Cafe"),
    ("M6", "Alice", "Carol", "2026-03-15", "Library"),
]


def fmt_naive(sender, to, date, place):
    """格式 A：自然写法，字段长度不定。"""
    return f"From: {sender}\nTo: {to}\nDate: {date}\nPlace: {place}"


# 格式 B：定长对齐，每个字段恰好占一个 16 字节分组
W_SENDER, W_TO, W_DATE, W_PLACE = 10, 12, 10, 8


def fmt_aligned(sender, to, date, place):
    """格式 B：四个定长字段依次拼接，前三个 16 字节，最后一个 15 字节。

    "From: "(6) + sender(10)          = 16
    "To: "  (4) + to(12)              = 16
    "Date: "(6) + date(10)            = 16
    "Place: "(7) + place(8)           = 15
                                    总计 63 字节
    PKCS#7 补 1 字节 0x01 -> 64 字节 = 4 个分组
    """
    if len(sender) > W_SENDER:
        raise ValueError(f"发件人过长：{sender!r}（最多 {W_SENDER} 字符）")
    if len(to) > W_TO:
        raise ValueError(f"收件人过长：{to!r}（最多 {W_TO} 字符）")
    if len(date) != W_DATE:
        raise ValueError(f"日期必须是 {W_DATE} 位：{date!r}")
    if len(place) > W_PLACE:
        raise ValueError(f"地点过长：{place!r}（最多 {W_PLACE} 字符）")
    return ("From: " + sender.ljust(W_SENDER)
            + "To: " + to.ljust(W_TO)
            + "Date: " + date.ljust(W_DATE)
            + "Place: " + place.ljust(W_PLACE))


def show(s: str) -> str:
    """把控制字符显示成可见形式。"""
    return s.replace("\n", "\\n").replace("\x01", "\\x01").replace("\x0d", "\\x0d")


def b2s(b: bytes) -> str:
    """把分组的 16 字节显示成可读 ASCII（不可打印字符用 · 代替）。"""
    return "".join(chr(x) if 32 <= x < 127 else "·" for x in b)


def pretty_aligned(plain: bytes) -> str:
    """把格式 B 的明文字节还原成人类可读的多行形式。"""
    t = plain.decode("latin-1")
    parts, i = [], 0
    for w in (16, 16, 16, 15):
        parts.append(t[i:i + w].rstrip())
        i += w
    return "\n".join(parts)


L: list[str] = []
def w(line: str = "") -> None:
    L.append(line)


# ---------------------------------------------------------------------------
w("# 附录 B 真值数据（由 tools/gen_truth.py 自动生成）")
w()
w(f"演示密钥 = SHA-256(`cryptography-course/ecb-demo/v1`)[:16] = `{KEY.hex()}`")
w()
w("> 生成方式：纯标准库 AES-128 参考实现（tools/aes_ref.py），"
  "已通过 FIPS-197 附录 C.1 已知答案测试。")
w("> AES-ECB 是确定性算法，学生用 `cryptography` 库跑出的密文与此**逐字节相同**。")
w()

# ---------- 一、格式 A：字段与分组不对齐 ----------
w("## B.1 格式 A（自然写法）的分组布局")
w()
w("```python")
w('f"From: {sender}\\nTo: {to}\\nDate: {date}\\nPlace: {place}"')
w("```")
w()

naive_ct = {}
for mid, s, t, d, p in HISTORY:
    pt = fmt_naive(s, t, d, p).encode()
    ct = ecb_encrypt(KEY, pt)
    naive_ct[mid] = (pt, ct)

w("| 消息 | 明文长度 | 填充后 | 分组数 |")
w("|------|---------|-------|-------|")
for mid, s, t, d, p in HISTORY:
    pt, ct = naive_ct[mid]
    pad = 16 - (len(pt) % 16) if len(pt) % 16 else 16
    w(f"| {mid} | {len(pt)} | {len(pt) + pad} | {len(ct) // 16} |")
w()

w("### M1 与 M3 的分组对照（二者只差日期）")
w()
w("```")
pt1, ct1 = naive_ct["M1"]
pt3, ct3 = naive_ct["M3"]
for i in range(4):
    w(f"分组 {i}   M1 明文: {b2s(pt1[i*16:(i+1)*16])!r}")
    w(f"          M3 明文: {b2s(pt3[i*16:(i+1)*16])!r}")
    w(f"          M1 密文: {ct1[i*16:(i+1)*16].hex()}")
    w(f"          M3 密文: {ct3[i*16:(i+1)*16].hex()}")
    w(f"          密文相同: {'是' if ct1[i*16:(i+1)*16] == ct3[i*16:(i+1)*16] else '否'}")
    w()
w("```")
w()

# 格式A下的朴素调换：把 M3 的第 2 分组替换进 M1
w("### 格式 A 下的分组调换实验")
w()
w("把 M3 的第 2 分组挪进 M1 的位置 2：")
w()
for label, src, idx in [("用 M3 的分组 2", "M3", 2), ("用 M3 的分组 3", "M3", 3)]:
    src_ct = naive_ct[src][1]
    forged_ct = ct1[:idx * 16] + src_ct[idx * 16:(idx + 1) * 16] + ct1[(idx + 1) * 16:]
    dec = ecb_decrypt(KEY, forged_ct)
    w(f"- **{label}** 替换 M1 的第 {idx} 分组 -> 解密结果：")
    w()
    w("  ```")
    for ln in dec.decode("latin-1").split("\n"):
        w(f"  {show(ln)}")
    w("  ```")
    w()
w("结论：分组 3 两边都是 `y` + 13 字节填充，换了等于没换；"
  "分组 2 里夹着日期的尾巴和地点的开头，换了会连带改动两个字段。")
w()

# M1 vs M2 的错位调换
w("### 错位示例：M1 与 M2（长度不同）")
w()
pt2, ct2 = naive_ct["M2"]
w(f"- M1 明文 {len(pt1)} 字节 -> {len(ct1)//16} 个分组")
w(f"- M2 明文 {len(pt2)} 字节 -> {len(ct2)//16} 个分组")
w()
forged = ct1[:48] + ct2[32:48]
dec = ecb_decrypt(KEY, forged)
w("把 M2 的最后一个分组接到 M1 的第 3 分组之后，解密得到：")
w()
w("```")
for ln in dec.decode("latin-1").split("\n"):
    w(show(ln))
w("```")
w()
w("地点字段被从中间切断，拼出了 `Libr3-15` 这种不伦不类的东西，"
  "后面还多出一行 `Place: Gym` —— 这就是「换块之后读起来不对劲」的真实样子。"
  "根因是两个字段的分组边界**没有对齐**，切下去必然伤到别的字段。")
w()

# ---------- 二、格式 B ----------
w("## B.2 格式 B（定长对齐）的明文分组")
w()
w("| 字段 | 前缀 | 内容宽度 | 该行总长 |")
w("|------|------|---------|---------|")
w("| From | `From: ` (6) | 10 | 16 |")
w("| To | `To: ` (4) | 12 | 16 |")
w("| Date | `Date: ` (6) | 10 | 16 |")
w("| Place | `Place: ` (7) | 8 | 15 |")
w()
w("明文总长 63 字节，PKCS#7 补 1 字节 `0x01` 凑满 64 字节 = **4 个分组**，"
  "一个字段正好一个分组。")
w()

w("### 历史密文库：明文分组")
w()
w("| 消息 | 发件人 | 收件人 | 日期 | 地点 | 分组0 明文 | 分组1 明文 | 分组2 明文 | 分组3 明文 |")
w("|------|-------|-------|------|------|-----------|-----------|-----------|-----------|")
aligned = {}
for mid, s, t, d, p in HISTORY:
    pt = fmt_aligned(s, t, d, p).encode()
    ct = ecb_encrypt(KEY, pt)
    aligned[mid] = (pt, ct)
    ptd = pt + bytes([1])  # 补上填充字节后正好 64 字节
    bl = to_blocks(ptd)
    cells = " | ".join(f"`{b2s(b)}`" for b in bl)
    w(f"| {mid} | {s} | {t} | {d} | {p} | {cells} |")
w()

w("### 历史密文库：密文分组（十六进制）")
w()
w("| 消息 | 分组0 | 分组1 | 分组2 | 分组3 |")
w("|------|-------|-------|-------|-------|")
for mid, s, t, d, p in HISTORY:
    pt, ct = aligned[mid]
    bl = to_blocks(ct)
    w(f"| {mid} | `{bl[0].hex()}` | `{bl[1].hex()}` | `{bl[2].hex()}` | `{bl[3].hex()}` |")
w()

# ---------- 三、模式泄露 ----------
w("## B.3 ECB 的模式泄露（不解密就能看出来的信息）")
w()
w("相同明文分组 -> 相同密文分组。逐组比对 6 条密文：")
w()
groups = {"分组0 (From)": 0, "分组1 (To)": 1, "分组2 (Date)": 2, "分组3 (Place)": 3}
for label, idx in groups.items():
    buckets: dict[bytes, list[str]] = {}
    for mid, s, t, d, p in HISTORY:
        blk = to_blocks(aligned[mid][1])[idx]
        buckets.setdefault(blk, []).append(mid)
    dupes = {k: v for k, v in buckets.items() if len(v) > 1}
    w(f"**{label}** — 不同的密文分组共 {len(buckets)} 种")
    w()
    if dupes:
        w("| 密文分组 | 出现在 | 说明 |")
        w("|---------|-------|------|")
        for k, v in sorted(dupes.items(), key=lambda kv: -len(kv[1])):
            meta = {"0": "同一发件人", "1": "同一收件人", "2": "同一天", "3": "同一地点"}[str(idx)]
            w(f"| `{k.hex()}` | {', '.join(v)} | {meta} |")
    else:
        w("（本组无重复）")
    w()

# ---------- 四、攻击 ----------
w("## B.4 攻击演示")
w()

def attack(name, recipe, note):
    """recipe: list of (msg_id, block_index)"""
    ct = b"".join(to_blocks(aligned[m][1])[i] for m, i in recipe)
    dec = ecb_decrypt(KEY, ct)
    w(f"### {name}")
    w()
    w("取块配方：" + " + ".join(f"{m}.分组{i}" for m, i in recipe))
    w()
    w("伪造密文：")
    w()
    w("```")
    for i, b in enumerate(to_blocks(ct)):
        w(f"分组{i}: {b.hex()}   <- {recipe[i][0]}.分组{recipe[i][1]}")
    w("```")
    w()
    w("Bob 用密钥解密后看到：")
    w()
    w("```")
    w(pretty_aligned(dec))
    w("```")
    w()
    w(note)
    w()
    return ct, dec


attack("攻击 1：改地点（换 1 个分组，消息依然通顺）",
       [("M1", 0), ("M1", 1), ("M1", 2), ("M2", 3)],
       "Mallory 不知道密钥，却把 `Place: Library` 改成了 `Place: Gym`，"
       "而且解密结果是一条完全正常的消息。")

attack("攻击 2：改发件人",
       [("M4", 0), ("M1", 1), ("M1", 2), ("M1", 3)],
       "把 Carol 那条消息的发件人分组搬过来，消息变成 Carol 发给 Bob。")

attack("攻击 3：改日期",
       [("M1", 0), ("M1", 1), ("M3", 2), ("M1", 3)],
       "换日期分组，约定时间被推到一周后。")

attack("挑战题示例：四个分组来自三条不同消息，拼出一条从未存在过的消息",
       [("M4", 0), ("M1", 1), ("M3", 2), ("M2", 3)],
       "发件人来自 M4、收件人来自 M1、日期来自 M3、地点来自 M2 —— "
       "这条消息**从来没有任何人发送过**，但它能通过解密、格式完整、语义自洽。")

# ---------- 五、防御对照 ----------
w("## B.5 防御对照：同样的分组搬运，在 CBC 下会怎样")
w()
w("ECB 与 CBC 的唯一区别是**链接**：")
w()
w("```")
w("ECB:  ct[i] = E(pt[i])                 分组之间互不相干")
w("CBC:  ct[i] = E(pt[i] XOR ct[i-1])     分组与前一个密文分组绑定")
w("```")
w()
w("下面用真实运行结果对照。两条消息用**同一个固定 IV**（真实代码见 "
  "`code/task6_defense.py`）。")
w()

IV = bytes(16)  # 全零 IV，只为演示
ct1_cbc = cbc_encrypt(KEY, IV, aligned["M1"][0])
ct2_cbc = cbc_encrypt(KEY, IV, aligned["M2"][0])
b1_cbc, b2_cbc = to_blocks(ct1_cbc), to_blocks(ct2_cbc)

ct4_cbc = cbc_encrypt(KEY, IV, aligned["M4"][0])
b4_cbc = to_blocks(ct4_cbc)


def cbc_blocks(ct: bytes) -> list[bytes]:
    return to_blocks(ct)


def raw_blocks(forged: bytes, iv: bytes) -> list[bytes]:
    """解密但**不做填充校验**，用于观察乱码长什么样。"""
    w_ = _expand_key(KEY)
    out, prev = [], iv
    for i in range(0, len(forged), 16):
        c = forged[i : i + 16]
        out.append(bytes(a ^ b for a, b in zip(decrypt_block(c, w_), prev)))
        prev = c
    return out


def show_forged(title: str, forged: bytes, recipe: str) -> None:
    w(f"### {title}")
    w()
    w(f"取块配方：{recipe}")
    w()
    w("```")
    rb = raw_blocks(forged, IV)
    for i, b in enumerate(to_blocks(forged)):
        w(f"分组{i} 密文: {b.hex()}")
        w(f"       明文: {b2s(rb[i])!r}")
    w("```")
    w()
    try:
        dec = cbc_decrypt(KEY, IV, forged)
        w("填充校验**通过**，Bob 看到：")
        w()
        w("```")
        w(pretty_aligned(dec))
        w("```")
    except Exception as e:
        w(f"填充校验**失败** -> `pkcs7_unpad` 抛 `ValueError: {e}`，消息被拒收。")
    w()


show_forged(
    "对照 1：M1 与 M4（从第一个分组起就不同）",
    b1_cbc[0] + b1_cbc[1] + b1_cbc[2] + b4_cbc[3],
    "M1.分组0 + M1.分组1 + M1.分组2 + **M4.分组3**",
)
w("M1 与 M4 从发件人起就完全不同，CBC 的链接值一路岔开，"
  "所以搬过来的分组对不上前驱，解出乱码，填充校验失败。")
w()

show_forged(
    "对照 2：搬动中间分组，看错误向后扩散",
    b1_cbc[0] + b4_cbc[1] + b1_cbc[2] + b1_cbc[3],
    "M1.分组0 + **M4.分组1** + M1.分组2 + M1.分组3",
)
w("**错误扩散**是 CBC 的核心防护：搬动一个密文分组，它自己解出乱码，"
  "**它后面所有分组跟着一起烂掉**。攻击者越往前面动，破坏面越大。")
w()

show_forged(
    "对照 3（关键）：M1 与 M2 前缀相同 —— CBC 挡不住",
    b1_cbc[0] + b1_cbc[1] + b1_cbc[2] + b2_cbc[3],
    "M1.分组0 + M1.分组1 + M1.分组2 + **M2.分组3**",
)
w("两条消息前三个分组一模一样，于是它们的密文前三个分组也**一模一样** "
  "（`ct1[2] == ct2[2]`）。搬过来的分组正好对得上前驱，解密完全成功，"
  "`Place: Library` 被改成了 `Place: Gym`。")
w()
w("**这个结果很重要**：CBC 并不阻止分组搬运。它只是让「前驱对不上」的情况")
w("失败，而前缀相同的两条消息，前驱天然对得上。只要攻击者能找到两条前缀")
w("相同的消息，同样的攻击在 CBC 下照样成立。")
w()
w("所以正确的结论不是「用 CBC 就安全了」，而是：")
w()
w("1. IV 必须每次随机且不可预测（本演示用了固定全零 IV，本身就是缺陷）；")
w("2. 加密**必须**配合完整性保护。要么 Encrypt-then-MAC（加密后对密文做 HMAC），")
w("   要么直接用 AES-GCM / ChaCha20-Poly1305 这类 AEAD 模式 —— 它们在密文之外")
w("   附带认证标签，解密前先验标签，任何一个比特被改动都会当场被拒，")
w("   攻击者连「拼一条试试看」的机会都没有。")
w()

OUT.write_text("\n".join(L), encoding="utf-8")
print(f"已写出 {OUT}")
print(f"共 {len(L)} 行")
