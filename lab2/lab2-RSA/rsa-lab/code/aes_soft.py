"""纯标准库 AES-128/192/256-CBC 实现（零第三方依赖）。

【这是一个黑盒，任务四不需要读懂它】
AES 不是本实验的攻击对象 —— 攻击对象是**模数是怎么生成的**。
解密那一层（AES、填充、文件容器）全部给现成的，你只需要调用它。

所以你**不需要**看这个文件。它放在这里有两个理由：
  1. `decrypt_hw.py` 要用它；
  2. 本实验包因此**不需要 pip install 任何东西** —— 包括 cryptography。

【为什么不用 cryptography 库】
不是因为它不好，而是因为「上课第 70 分钟才发现 pip 装不上」是本实验
最没必要、也最容易避免的一种失败。附带一份纯标准库实现，这个失败模式
就整个消失了。

【正确性怎么保证】
AES 是确定性算法，同一密钥同一明文必然得到同一密文 —— 所以「自己实现」
不等于「结果可能不一样」。本文件末尾有 NIST SP 800-38A 附录 F 的
**官方向量自校验**，覆盖 AES-128/192/256 的 ECB 与 CBC。
`python check_env.py` 会在开课时替你跑一遍。

用法：
    python aes_soft.py

输出：
    全部向量通过时打印「全部通过」并以退出码 0 结束；
    有任何一项不符则打印差异并以退出码 1 结束。
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# GF(2^8) 运算。AES 把每个字节看作 GF(2^8) 上的元素，
# 模多项式为 m(x) = x^8 + x^4 + x^3 + x + 1，即 0x11B。
# ---------------------------------------------------------------------------


def xtime(a: int) -> int:
    """GF(2^8) 上乘以 x（即乘以 2）。溢出时对 0x11B 取模。"""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def gf_mul(a: int, b: int) -> int:
    """GF(2^8) 上的乘法（俄罗斯农民乘法）。

    本实验用到的系数只有 2、3、9、11、13、14，但写成通用版本更不容易出错。
    """
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result & 0xFF


def _rotl8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _build_sbox() -> list[int]:
    """按 FIPS-197 5.1.1 的构造法生成 S 盒，避免手抄 256 个字节出错。

    S 盒 = 先求 GF(2^8) 上的乘法逆元，再做仿射变换。
    这里用 p/q 同步游走的经典写法：p 每次乘 3，q 每次除以 3，二者始终互逆。
    """
    sbox = [0] * 256
    p = q = 1
    while True:
        # p <- p * 3
        p ^= xtime(p)
        # q <- q / 3   （除以 3 等价于乘以 3 的逆元 0xF6，用移位展开）
        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        if q & 0x80:
            q ^= 0x09
        q &= 0xFF
        # 仿射变换：b ^ rotl(b,1) ^ rotl(b,2) ^ rotl(b,3) ^ rotl(b,4) ^ 0x63
        x = q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4)
        sbox[p] = x ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


SBOX = _build_sbox()
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i


# ---------------------------------------------------------------------------
# 密钥扩展（FIPS-197 5.2）
# ---------------------------------------------------------------------------

# 轮常量 Rcon[i] = x^(i-1)，i 从 1 开始。这里存前 15 个，够 AES-256 用。
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]


def _key_words(key: bytes) -> list[int]:
    """把密钥字节串切成 4 字节的字（大端）。Nk = len(key) / 4。"""
    return [int.from_bytes(key[i : i + 4], "big") for i in range(0, len(key), 4)]


def expand_key(key: bytes) -> list[int]:
    """密钥扩展，返回 4*(Nr+1) 个 32-bit 轮密钥字。"""
    nk = len(key) // 4
    if len(key) not in (16, 24, 32):
        raise ValueError(f"密钥长度必须是 16 / 24 / 32 字节，收到 {len(key)}")
    nr = {4: 10, 6: 12, 8: 14}[nk]
    w = _key_words(key)
    for i in range(nk, 4 * (nr + 1)):
        temp = w[i - 1]
        if i % nk == 0:
            # RotWord：循环左移一个字节
            temp = ((temp << 8) | (temp >> 24)) & 0xFFFFFFFF
            # SubWord：逐字节过 S 盒
            temp = (
                (SBOX[(temp >> 24) & 0xFF] << 24)
                | (SBOX[(temp >> 16) & 0xFF] << 16)
                | (SBOX[(temp >> 8) & 0xFF] << 8)
                | SBOX[temp & 0xFF]
            )
            temp ^= RCON[i // nk - 1] << 24
        elif nk > 6 and i % nk == 4:
            # AES-256 独有的一步：额外的 SubWord
            temp = (
                (SBOX[(temp >> 24) & 0xFF] << 24)
                | (SBOX[(temp >> 16) & 0xFF] << 16)
                | (SBOX[(temp >> 8) & 0xFF] << 8)
                | SBOX[temp & 0xFF]
            )
        w.append(w[i - nk] ^ temp)
    return w


def _rounds_for(key: bytes) -> int:
    return {16: 10, 24: 12, 32: 14}[len(key)]


# ---------------------------------------------------------------------------
# 轮函数。状态按 FIPS-197 的列主序排成一个 16 字节的扁平列表：
# s[r + 4c] 是第 r 行第 c 列。这恰好就是输入字节的天然顺序。
# ---------------------------------------------------------------------------


def _add_round_key(s: list[int], w: list[int], rnd: int) -> list[int]:
    out = s[:]
    for c in range(4):
        word = w[4 * rnd + c]
        out[4 * c + 0] ^= (word >> 24) & 0xFF
        out[4 * c + 1] ^= (word >> 16) & 0xFF
        out[4 * c + 2] ^= (word >> 8) & 0xFF
        out[4 * c + 3] ^= word & 0xFF
    return out


def _sub_bytes(s: list[int], box: list[int]) -> list[int]:
    return [box[b] for b in s]


def _shift_rows(s: list[int]) -> list[int]:
    """第 r 行循环左移 r 个字节。"""
    return [s[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4)]


def _inv_shift_rows(s: list[int]) -> list[int]:
    """第 r 行循环右移 r 个字节。"""
    return [s[r + 4 * ((c - r) % 4)] for c in range(4) for r in range(4)]


def _mix_columns(s: list[int]) -> list[int]:
    out = []
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c : 4 * c + 4]
        out += [
            xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3,
            a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3,
            a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3),
            (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3),
        ]
    return out


def _inv_mix_columns(s: list[int]) -> list[int]:
    out = []
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c : 4 * c + 4]
        out += [
            gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9),
            gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13),
            gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11),
            gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14),
        ]
    return out


def encrypt_block(block: bytes, w: list[int], nr: int) -> bytes:
    """加密单个 16 字节分组。"""
    s = _add_round_key(list(block), w, 0)
    for rnd in range(1, nr):
        s = _mix_columns(_shift_rows(_sub_bytes(s, SBOX)))
        s = _add_round_key(s, w, rnd)
    s = _shift_rows(_sub_bytes(s, SBOX))
    s = _add_round_key(s, w, nr)
    return bytes(s)


def decrypt_block(block: bytes, w: list[int], nr: int) -> bytes:
    """解密单个 16 字节分组。"""
    s = _add_round_key(list(block), w, nr)
    for rnd in range(nr - 1, 0, -1):
        s = _inv_shift_rows(_sub_bytes(s, INV_SBOX))
        s = _add_round_key(s, w, rnd)
        s = _inv_mix_columns(s)
    s = _inv_shift_rows(_sub_bytes(s, INV_SBOX))
    s = _add_round_key(s, w, 0)
    return bytes(s)


# ---------------------------------------------------------------------------
# 高层接口：ECB / CBC
# ---------------------------------------------------------------------------


def ecb_encrypt(key: bytes, data: bytes) -> bytes:
    """ECB 加密。data 长度必须是 16 的整数倍（本函数不做填充）。"""
    if len(data) % 16:
        raise ValueError("ECB 要求数据长度是 16 的整数倍")
    w, nr = expand_key(key), _rounds_for(key)
    return b"".join(encrypt_block(data[i : i + 16], w, nr) for i in range(0, len(data), 16))


def ecb_decrypt(key: bytes, data: bytes) -> bytes:
    if len(data) % 16:
        raise ValueError("ECB 要求数据长度是 16 的整数倍")
    w, nr = expand_key(key), _rounds_for(key)
    return b"".join(decrypt_block(data[i : i + 16], w, nr) for i in range(0, len(data), 16))


def cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """CBC 加密。data 长度必须是 16 的整数倍（本函数不做填充）。"""
    if len(iv) != 16:
        raise ValueError(f"IV 必须是 16 字节，收到 {len(iv)}")
    if len(data) % 16:
        raise ValueError("CBC 要求数据长度是 16 的整数倍")
    w, nr = expand_key(key), _rounds_for(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i : i + 16], prev))
        prev = encrypt_block(blk, w, nr)
        out += prev
    return bytes(out)


def cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(iv) != 16:
        raise ValueError(f"IV 必须是 16 字节，收到 {len(iv)}")
    if len(data) % 16:
        raise ValueError("CBC 要求数据长度是 16 的整数倍")
    w, nr = expand_key(key), _rounds_for(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = data[i : i + 16]
        out += bytes(a ^ b for a, b in zip(decrypt_block(blk, w, nr), prev))
        prev = blk
    return bytes(out)


# ---------------------------------------------------------------------------
# 自校验：NIST SP 800-38A 附录 F 官方向量
# ---------------------------------------------------------------------------

# 四个明文分组，F.1/F.2 全部子节共用。
_PT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

VECTORS: list[tuple[str, str, bytes, bytes, bytes]] = [
    # (来源, 密钥, 期望密文)  模式由来源决定
    (
        "F.1.1 ECB-AES128",
        "2b7e151628aed2a6abf7158809cf4f3c",
        _IV,
        _PT,
        bytes.fromhex(
            "3ad77bb40d7a3660a89ecaf32466ef97"
            "f5d3d58503b9699de785895a96fdbaaf"
            "43b1cd7f598ece23881b00e3ed030688"
            "7b0c785e27e8ad3f8223207104725dd4"
        ),
    ),
    (
        "F.1.3 ECB-AES192",
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        _IV,
        _PT,
        bytes.fromhex(
            "bd334f1d6e45f25ff712a214571fa5cc"
            "974104846d0ad3ad7734ecb3ecee4eef"
            "ef7afd2270e2e60adce0ba2face6444e"
            "9a4b41ba738d6c72fb16691603c18e0e"
        ),
    ),
    (
        "F.1.5 ECB-AES256",
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        _IV,
        _PT,
        bytes.fromhex(
            "f3eed1bdb5d2a03c064b5a7e3db181f8"
            "591ccb10d410ed26dc5ba74a31362870"
            "b6ed21b99ca6f4f9f153e7b1beafed1d"
            "23304b7a39f9f3ff067d8d8f9e24ecc7"
        ),
    ),
    (
        "F.2.1 CBC-AES128",
        "2b7e151628aed2a6abf7158809cf4f3c",
        _IV,
        _PT,
        bytes.fromhex(
            "7649abac8119b246cee98e9b12e9197d"
            "5086cb9b507219ee95db113a917678b2"
            "73bed6b8e3c1743b7116e69e22229516"
            "3ff1caa1681fac09120eca307586e1a7"
        ),
    ),
    (
        "F.2.3 CBC-AES192",
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        _IV,
        _PT,
        bytes.fromhex(
            "4f021db243bc633d7178183a9fa071e8"
            "b4d9ada9ad7dedf4e5e738763f69145a"
            "571b242012fb7ae07fa9baac3df102e0"
            "08b0e27988598881d920a9e64f5615cd"
        ),
    ),
    (
        "F.2.5 CBC-AES256",
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        _IV,
        _PT,
        bytes.fromhex(
            "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
            "9cfc4e967edb808d679f777bc6702c7d"
            "39f23369a9d9bacfa530e26304231461"
            "b2eb05e2c39be9fcda6c19078c6a9d1b"
        ),
    ),
]


def _self_test() -> bool:
    print("NIST SP 800-38A 附录 F 已知答案测试")
    print("-" * 62)
    ok = True
    for name, key_hex, iv, pt, want in VECTORS:
        key = bytes.fromhex(key_hex)
        if name.startswith("F.1"):
            got = ecb_encrypt(key, pt)
            back = ecb_decrypt(key, got)
        else:
            got = cbc_encrypt(key, iv, pt)
            back = cbc_decrypt(key, iv, got)
        enc_ok = got == want
        dec_ok = back == pt
        mark = "通过" if (enc_ok and dec_ok) else "失败"
        print(f"  {name:<18} 加密 {mark}   解密 {'通过' if dec_ok else '失败'}")
        if not enc_ok:
            print(f"      期望 {want.hex()}")
            print(f"      实际 {got.hex()}")
        ok &= enc_ok and dec_ok
    return ok


if __name__ == "__main__":
    passed = _self_test()
    print("-" * 62)
    if passed:
        print("全部通过：本机 AES 实现与 NIST 官方向量逐字节一致。")
    else:
        print("存在失败项，实现有误。")
        raise SystemExit(1)
