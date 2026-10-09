"""环境自检：确认 cryptography 装好了，而且算得对。

用法：
    python check_env.py

它会用 FIPS-197 附录 C.1 的官方测试向量跑一遍 AES-128。
只要输出「全部通过」，后面所有任务的结果就都可信。
"""

from __future__ import annotations

import sys

FIPS197_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
FIPS197_PT = bytes.fromhex("00112233445566778899aabbccddeeff")
FIPS197_CT = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

ok = True

# ---- Python 版本 ----------------------------------------------------------
print(f"Python 版本 : {sys.version.split()[0]}")

# ---- 依赖 -----------------------------------------------------------------
try:
    import cryptography

    print(f"cryptography: {cryptography.__version__}")
except ImportError:
    print("cryptography: 未安装")
    print()
    print("请先安装：pip install cryptography")
    raise SystemExit(1)

# ---- 用官方测试向量验证 AES 本身算得对 ------------------------------------
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402

enc = Cipher(algorithms.AES(FIPS197_KEY), modes.ECB()).encryptor()
got = enc.update(FIPS197_PT) + enc.finalize()

print()
print("FIPS-197 附录 C.1 已知答案测试")
print(f"  密钥      : {FIPS197_KEY.hex()}")
print(f"  明文      : {FIPS197_PT.hex()}")
print(f"  期望密文  : {FIPS197_CT.hex()}")
enc_ok = got == FIPS197_CT
print(f"  实际密文  : {got.hex()}   {'通过' if enc_ok else '失败'}")
ok &= enc_ok

dec = Cipher(algorithms.AES(FIPS197_KEY), modes.ECB()).decryptor()
back = dec.update(got) + dec.finalize()
dec_ok = back == FIPS197_PT
print(f"  解密回明文: {back.hex()}   {'通过' if dec_ok else '失败'}")
ok &= dec_ok

# ---- PKCS#7 填充 ----------------------------------------------------------
from cryptography.hazmat.primitives import padding  # noqa: E402

for n in (0, 1, 15, 16, 17, 50):
    data = bytes(range(n))
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    restored = unpadder.update(padded) + unpadder.finalize()
    if restored != data or len(padded) % 16:
        print(f"  PKCS#7 在 {n} 字节时出错")
        ok = False

print()
print("PKCS#7 填充 ：通过" if ok else "PKCS#7 填充 ：失败")

# ---- 结论 ----------------------------------------------------------------
print()
if ok:
    print("=" * 56)
    print("环境自检全部通过，可以开始实验。")
    print("下一步：python alice_encrypt.py --build-history")
    print("=" * 56)
else:
    print("环境自检存在失败项，请检查 cryptography 的安装。")
    raise SystemExit(1)
