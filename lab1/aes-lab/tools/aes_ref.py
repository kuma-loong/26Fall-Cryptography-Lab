"""纯标准库 AES-128-ECB 参考实现（零第三方依赖）。

【这个文件是干什么的】
本实验的学生端代码用 `cryptography` 库。但《实验指导书》里需要写进**真实的**
十六进制密文和伪造结果 —— 这些数字编不得。为了在**不安装任何第三方包**的机器上
也能生成并复核这些真值，这里用纯标准库实现了一份 AES-128。

【它不是给学生用的】
学生做实验**不需要**这个文件。它只服务于两件事：
  1. 生成《实验指导书》附录 B 的真值数据（tools/gen_truth.py 调用它）；
  2. 在没装 cryptography 的机器上复核附录 B 的数据有没有算错。

【正确性保证】
AES-128 是确定性算法，同一密钥同一明文必然得到同一密文。因此本文件生成的密文，
与学生用 `cryptography` 跑出来的**逐字节相同**。
本实现由 FIPS-197 附录 C.1 的官方已知答案测试（Known Answer Test）自校验，
见文件末尾的 __main__。
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
    """GF(2^8) 上的乘法（俄罗斯农民乘法）。"""
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
# 密钥扩展（AES-128：4 个字 -> 44 个字，共 11 组轮密钥）
# ---------------------------------------------------------------------------


def _expand_key(key: bytes) -> list[list[int]]:
    if len(key) != 16:
        raise ValueError("AES-128 的密钥必须是 16 字节")
    w = [list(key[4 * i : 4 * i + 4]) for i in range(4)]
    rcon = 1
    for i in range(4, 44):
        temp = list(w[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]          # RotWord
            temp = [SBOX[b] for b in temp]      # SubWord
            temp[0] ^= rcon                     # 异或轮常数
            rcon = xtime(rcon)
        w.append([w[i - 4][j] ^ temp[j] for j in range(4)])
    return w


# ---------------------------------------------------------------------------
# 轮变换。state 是 16 字节的平铺列表，按列主序：
#   state[r + 4c] = 输入的第 r + 4c 个字节（r = 行，c = 列）
# ---------------------------------------------------------------------------


def _add_round_key(state: list[int], w: list[list[int]], rnd: int) -> list[int]:
    rk = [w[4 * rnd + c][r] for c in range(4) for r in range(4)]
    return [state[i] ^ rk[i] for i in range(16)]


def _sub_bytes(state: list[int]) -> list[int]:
    return [SBOX[b] for b in state]


def _inv_sub_bytes(state: list[int]) -> list[int]:
    return [INV_SBOX[b] for b in state]


def _shift_rows(state: list[int]) -> list[int]:
    """第 r 行循环左移 r 个字节。"""
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = state[r + 4 * ((c + r) % 4)]
    return out


def _inv_shift_rows(state: list[int]) -> list[int]:
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = state[r + 4 * ((c - r) % 4)]
    return out


def _mix_columns(state: list[int]) -> list[int]:
    out = [0] * 16
    for c in range(4):
        a = state[4 * c : 4 * c + 4]
        out[4 * c + 0] = gf_mul(a[0], 2) ^ gf_mul(a[1], 3) ^ a[2] ^ a[3]
        out[4 * c + 1] = a[0] ^ gf_mul(a[1], 2) ^ gf_mul(a[2], 3) ^ a[3]
        out[4 * c + 2] = a[0] ^ a[1] ^ gf_mul(a[2], 2) ^ gf_mul(a[3], 3)
        out[4 * c + 3] = gf_mul(a[0], 3) ^ a[1] ^ a[2] ^ gf_mul(a[3], 2)
    return out


def _inv_mix_columns(state: list[int]) -> list[int]:
    out = [0] * 16
    for c in range(4):
        a = state[4 * c : 4 * c + 4]
        out[4 * c + 0] = gf_mul(a[0], 14) ^ gf_mul(a[1], 11) ^ gf_mul(a[2], 13) ^ gf_mul(a[3], 9)
        out[4 * c + 1] = gf_mul(a[0], 9) ^ gf_mul(a[1], 14) ^ gf_mul(a[2], 11) ^ gf_mul(a[3], 13)
        out[4 * c + 2] = gf_mul(a[0], 13) ^ gf_mul(a[1], 9) ^ gf_mul(a[2], 14) ^ gf_mul(a[3], 11)
        out[4 * c + 3] = gf_mul(a[0], 11) ^ gf_mul(a[1], 13) ^ gf_mul(a[2], 9) ^ gf_mul(a[3], 14)
    return out


# ---------------------------------------------------------------------------
# 单块加解密
# ---------------------------------------------------------------------------


def encrypt_block(block: bytes, w: list[list[int]]) -> bytes:
    state = list(block)
    state = _add_round_key(state, w, 0)
    for rnd in range(1, 10):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, w, rnd)
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, w, 10)
    return bytes(state)


def decrypt_block(block: bytes, w: list[list[int]]) -> bytes:
    state = list(block)
    state = _add_round_key(state, w, 10)
    for rnd in range(9, 0, -1):
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, w, rnd)
        state = _inv_mix_columns(state)
    state = _inv_shift_rows(state)
    state = _inv_sub_bytes(state)
    state = _add_round_key(state, w, 0)
    return bytes(state)


# ---------------------------------------------------------------------------
# PKCS#7 填充与 ECB 模式
# ---------------------------------------------------------------------------


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    n = block_size - (len(data) % block_size)
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size:
        raise ValueError("密文长度不是分组长度的整数倍，或被截断了")
    n = data[-1]
    if not 1 <= n <= block_size:
        raise ValueError(f"填充字节非法：0x{n:02x}")
    if data[-n:] != bytes([n]) * n:
        raise ValueError("填充内容不一致，密文可能已被篡改")
    return data[:-n]


def ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    w = _expand_key(key)
    padded = pkcs7_pad(plaintext)
    return b"".join(encrypt_block(padded[i : i + 16], w) for i in range(0, len(padded), 16))


def ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    w = _expand_key(key)
    if len(ciphertext) % 16:
        raise ValueError("密文长度必须是 16 的整数倍")
    padded = b"".join(decrypt_block(ciphertext[i : i + 16], w) for i in range(0, len(ciphertext), 16))
    return pkcs7_unpad(padded)


# ---------------------------------------------------------------------------
# CBC 模式：只用来做「防御对照」，说明链式结构为什么能挡住分组搬运
#   加密: ct[i] = E(pt[i] XOR ct[i-1]),   ct[-1] = IV
#   解密: pt[i] = D(ct[i]) XOR ct[i-1]
# ---------------------------------------------------------------------------


def cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    if len(iv) != 16:
        raise ValueError("IV 必须是 16 字节")
    w = _expand_key(key)
    padded = pkcs7_pad(plaintext)
    out, prev = [], iv
    for i in range(0, len(padded), 16):
        xored = bytes(a ^ b for a, b in zip(padded[i : i + 16], prev))
        prev = encrypt_block(xored, w)
        out.append(prev)
    return b"".join(out)


def cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if len(iv) != 16:
        raise ValueError("IV 必须是 16 字节")
    if len(ciphertext) % 16:
        raise ValueError("密文长度必须是 16 的整数倍")
    w = _expand_key(key)
    out, prev = [], iv
    for i in range(0, len(ciphertext), 16):
        c = ciphertext[i : i + 16]
        out.append(bytes(a ^ b for a, b in zip(decrypt_block(c, w), prev)))
        prev = c
    return pkcs7_unpad(b"".join(out))


def to_blocks(data: bytes, block_size: int = 16) -> list[bytes]:
    return [data[i : i + block_size] for i in range(0, len(data), block_size)]


def hexs(data: bytes) -> str:
    return data.hex()


def hex_pretty(data: bytes) -> str:
    return " ".join(data[i : i + 2].hex() for i in range(0, len(data), 2))


# ---------------------------------------------------------------------------
# 自校验：FIPS-197 附录 C.1 官方测试向量
# ---------------------------------------------------------------------------

FIPS197_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
FIPS197_PT = bytes.fromhex("00112233445566778899aabbccddeeff")
FIPS197_CT = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

# NIST SP 800-38A F.2.1 / F.2.2，CBC-AES128
NIST_CBC_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
NIST_CBC_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
NIST_CBC_PT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
NIST_CBC_CT = bytes.fromhex(
    "7649abac8119b246cee98e9b12e9197d"
    "5086cb9b507219ee95db113a917678b2"
    "73bed6b8e3c1743b7116e69e22229516"
    "3ff1caa1681fac09120eca307586e1a7"
)


def selftest() -> bool:
    ok = True

    w = _expand_key(FIPS197_KEY)
    got = encrypt_block(FIPS197_PT, w)
    back = decrypt_block(got, w)
    ok &= got == FIPS197_CT and back == FIPS197_PT
    print("FIPS-197 附录 C.1 已知答案测试（单块 AES-128）")
    print(f"  密钥      : {FIPS197_KEY.hex()}")
    print(f"  明文      : {FIPS197_PT.hex()}")
    print(f"  期望密文  : {FIPS197_CT.hex()}")
    print(f"  实际密文  : {got.hex()}   {'通过' if got == FIPS197_CT else '失败'}")
    print(f"  解密回明文: {back.hex()}   {'通过' if back == FIPS197_PT else '失败'}")
    print()

    # 注意：NIST 的向量恰好是整分组，PKCS#7 会再补一整块，
    # 所以这里比对前 64 字节。
    ct = cbc_encrypt(NIST_CBC_KEY, NIST_CBC_IV, NIST_CBC_PT)
    pt = cbc_decrypt(NIST_CBC_KEY, NIST_CBC_IV, ct)
    ok_cbc = ct[:64] == NIST_CBC_CT and pt == NIST_CBC_PT
    ok &= ok_cbc
    print("NIST SP 800-38A F.2.1/F.2.2 已知答案测试（CBC-AES128）")
    print(f"  期望密文  : {NIST_CBC_CT.hex()}")
    print(f"  实际密文  : {ct[:64].hex()}   {'通过' if ct[:64] == NIST_CBC_CT else '失败'}")
    print(f"  解密回明文: {'通过' if pt == NIST_CBC_PT else '失败'}")
    print()

    print("总体：" + ("全部通过" if ok else "存在失败项"))
    return ok


if __name__ == "__main__":
    raise SystemExit(0 if selftest() else 1)
