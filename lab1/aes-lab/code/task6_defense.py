"""任务六：为什么换成 CBC / GCM 就防住了。

同一个「搬分组」动作，在三种模式下各跑一遍，看结果差在哪。

本关会撞见两个**反直觉的事实**：
  · CBC 挡不住前缀相同的两条消息；
  · GCM 在分组层面**同样挡不住** —— 它的密文分组也是可以搬的，
    真正拦住攻击的是最后那个认证标签。
所以「用了 AEAD 就安全」的重点在**认证**，不在分组怎么排。

用法：
    python task6_defense.py
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from block_utils import from_blocks, to_blocks
from ecb_common import (
    DEMO_KEY,
    cbc_decrypt,
    cbc_encrypt,
    ecb_decrypt,
    ecb_encrypt,
    format_aligned,
    gcm_decrypt,
    gcm_encrypt,
    pretty_aligned,
)

SEP = "=" * 68
GCM_TAG = 16


def section(title: str) -> None:
    print()
    print(SEP)
    print(title)
    print(SEP)


def aes_block_decrypt(block: bytes) -> bytes:
    """只做 AES 的单块解密（不带任何模式），用来观察 CBC 的原始字节。"""
    dec = Cipher(algorithms.AES(DEMO_KEY), modes.ECB()).decryptor()
    return dec.update(block) + dec.finalize()


def printable(b: bytes) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "·" for c in b)


def try_decrypt(fn, label: str) -> None:
    try:
        plain = fn()
        print(f"  {label}：解密成功")
        print("  " + "-" * 56)
        print("  " + pretty_aligned(plain).replace("\n", "\n  "))
        print("  " + "-" * 56)
    except Exception as e:
        print(f"  {label}：被拒绝 -> {type(e).__name__}: {e}")


def main() -> None:
    m1 = format_aligned("Alice", "Bob", "2026-03-15", "Library").encode("latin-1")
    m2 = format_aligned("Alice", "Bob", "2026-03-15", "Gym").encode("latin-1")     # 前缀同 m1
    m4 = format_aligned("Carol", "Dave", "2026-03-15", "Office").encode("latin-1")  # 前缀就不同

    # =======================================================================
    section("准备：三种模式各加密几条消息")
    # =======================================================================
    iv = bytes(16)          # 只为演示用固定全零 —— 这本身就是缺陷
    nonce1, nonce2 = bytes(12), bytes(12)

    ecb = {"m1": ecb_encrypt(DEMO_KEY, m1), "m2": ecb_encrypt(DEMO_KEY, m2), "m4": ecb_encrypt(DEMO_KEY, m4)}
    cbc = {"m1": cbc_encrypt(DEMO_KEY, iv, m1), "m2": cbc_encrypt(DEMO_KEY, iv, m2), "m4": cbc_encrypt(DEMO_KEY, iv, m4)}
    gcm = {"m1": gcm_encrypt(DEMO_KEY, nonce1, m1), "m2": gcm_encrypt(DEMO_KEY, nonce2, m2)}

    print("明文 63 字节。三种模式的密文长度：")
    print(f"  ECB : {len(ecb['m1']):>3} 字节   4 个分组（有填充，明文被凑到 64）")
    print(f"  CBC : {len(cbc['m1']):>3} 字节   4 个分组（同样有填充）")
    print(f"  GCM : {len(gcm['m1']):>3} 字节   63 字节密文 + {GCM_TAG} 字节认证标签，**不填充**")
    print()
    print("GCM 是流式模式，密文和明文一样长 —— 这一点等下很关键。")

    # =======================================================================
    section("对照 1：ECB —— 把 M2 的分组 3 搬进 M1")
    # =======================================================================
    a, b = to_blocks(ecb["m1"]), to_blocks(ecb["m2"])
    forged_ecb = from_blocks(a[:3] + [b[3]])
    print(f"  伪造密文：{forged_ecb.hex()}")
    print()
    try_decrypt(lambda: ecb_decrypt(DEMO_KEY, forged_ecb), "ECB")
    print()
    print(">>> 改成功了。ECB 内部**没有任何机制**能发现这件事。")

    # =======================================================================
    section("对照 2：CBC —— 同样搬分组，但两条消息前缀不同（M1 vs M4）")
    # =======================================================================
    a, b = to_blocks(cbc["m1"]), to_blocks(cbc["m4"])
    forged_cbc1 = from_blocks(a[:3] + [b[3]])
    print(f"  伪造密文：{forged_cbc1.hex()}")
    print()
    print("  逐分组解密（跳过填充校验，直接看 CBC 的中间结果）：")
    for i in range(4):
        blk = forged_cbc1[i * 16 : (i + 1) * 16]
        prev = iv if i == 0 else forged_cbc1[(i - 1) * 16 : i * 16]
        plain_blk = bytes(x ^ y for x, y in zip(aes_block_decrypt(blk), prev))
        tag = "正常" if i < 3 else "乱码（前一个密文分组对不上）"
        print(f"    分组{i}: |{printable(plain_blk)}|  <- {tag}")
    print()
    try_decrypt(lambda: cbc_decrypt(DEMO_KEY, iv, forged_cbc1), "CBC")
    print()
    print(">>> CBC 的 ct[i] = E(pt[i] XOR ct[i-1]) 让每个分组都绑定前驱。")
    print(">>> 搬来的分组对不上前驱，解出乱码，填充校验把它拦下。")
    print(">>> 但请注意：拦下它的只是**填充校验**，不是为完整性设计的机制。")

    # =======================================================================
    section("对照 3：CBC —— 但 M1 和 M2 前缀相同，挡不住")
    # =======================================================================
    a, b = to_blocks(cbc["m1"]), to_blocks(cbc["m2"])
    forged_cbc2 = from_blocks(a[:3] + [b[3]])
    print(f"  伪造密文：{forged_cbc2.hex()}")
    print()
    print("  M1 与 M2 前三个分组相同 -> 密文前三个分组也相同：")
    print(f"    ct1[2] = {a[2].hex()}")
    print(f"    ct2[2] = {b[2].hex()}")
    print(f"    相等：{a[2] == b[2]}")
    print()
    try_decrypt(lambda: cbc_decrypt(DEMO_KEY, iv, forged_cbc2), "CBC")
    print()
    print(">>> 搬过来的分组正好对得上前驱，解密完全成功，Library 变成了 Gym。")
    print(">>> CBC **并不阻止**分组搬运，它只让「前驱对不上」的情况失败。")

    # =======================================================================
    section("对照 4：GCM —— 分组照样能搬，但标签会当场揭穿")
    # =======================================================================
    ct1, tag1 = gcm["m1"][:-GCM_TAG], gcm["m1"][-GCM_TAG:]
    ct2 = gcm["m2"][:-GCM_TAG]

    print("先看 GCM 的结构：")
    print(f"  密文部分 {len(ct1)} 字节（= 明文长度，无填充）")
    print(f"  认证标签 {GCM_TAG} 字节：{tag1.hex()}")
    print()
    print("GCM 的密文部分就是流密码：ct[i] = pt[i] XOR ks[i]。")
    print("**每个字节都只和自己位置上的密钥流有关** —— 所以照样可以搬。")
    print()

    forged_ct = ct1[:48] + ct2[48:63]        # 把最后 15 字节（Place 字段）换掉
    forged_gcm = forged_ct + tag1            # 标签原封不动地留着

    # 已知明文假设：Mallory 猜得到 m2 的内容，于是能求出密钥流
    ks = bytes(x ^ y for x, y in zip(ct2, m2))
    moved = bytes(x ^ y for x, y in zip(forged_ct, ks))
    print("  Mallory 拿搬完的密文，配上他推算出的密钥流：")
    print(f"    分组3 明文 = |{printable(moved[48:63])}|   <- 分组层面**搬成功了**")
    print()
    print(f"  伪造密文（{len(forged_gcm)} 字节，末尾 16 字节还是 M1 的原标签）：")
    print(f"    {forged_gcm.hex()}")
    print()
    try_decrypt(lambda: gcm_decrypt(DEMO_KEY, nonce1, forged_gcm), "GCM")
    print()
    print(">>> 看清楚：GCM 在**分组层面同样挡不住**搬运。")
    print(">>> 拦住攻击的是最后那 16 字节标签 —— 它覆盖了整条密文，")
    print(">>> 任何一比特被改动，标签就对不上，解密直接抛 InvalidTag。")
    print(">>> 攻击者连「拼一条试试看」的机会都没有。")

    # =======================================================================
    section("结论")
    # =======================================================================
    print("1. ECB 的问题不是 AES 弱，而是**分组彼此独立、且没有完整性保护**。")
    print()
    print("2. CBC 加的是「链接」，不是「完整性」。它能让多数搬运失败，")
    print("   但前缀相同的消息照样被改；而且兜底的填充校验并不可靠 ——")
    print("   随机字节有约 1/256 的概率蒙混过关，它从来就不是完整性校验。")
    print()
    print("3. 真正的修法是**认证加密**：")
    print("     · AES-GCM / ChaCha20-Poly1305（AEAD，首选）")
    print("     · 或 Encrypt-then-MAC：先加密，再对密文算 HMAC，解密前先验 MAC")
    print("   要点是：**解密之前**先把完整性验过。先解密再看内容，已经晚了。")
    print()
    print("4. 另外两件事同样重要：")
    print("     · IV / nonce 必须每次随机且不重复（本演示用固定值，是反面教材）")
    print("     · 不要用 ECB，任何场景都不要 —— 它连「看起来安全」都做不到")
    print()
    print(SEP)


if __name__ == "__main__":
    main()
