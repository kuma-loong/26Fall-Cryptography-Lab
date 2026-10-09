"""cryptography 的**验证用垫片**（纯标准库实现）。

【这不是给学生用的】
学生请安装真的 cryptography：pip install cryptography

这个垫片只服务于一个目的：让本实验包的作者（和助教）在**没有安装
cryptography 的机器上**，也能把 code/ 下所有脚本端到端跑一遍，确认
逻辑、分块配方、输出格式都对。它实现了真实 cryptography 的一个极小
子集：

    cryptography.hazmat.primitives.ciphers         Cipher / algorithms.AES / modes.ECB / modes.CBC
    cryptography.hazmat.primitives.ciphers.aead    AESGCM（完整实现，含 GHASH）
    cryptography.hazmat.primitives.padding         PKCS7
    cryptography.exceptions                        InvalidTag

底层 AES 由 tools/aes_ref.py 提供（已通过 FIPS-197 与 NIST SP 800-38A 向量）。
GCM 由 NIST SP 800-38D 实现，并已用附录 B 的测试向量校验。

用法：
    PYTHONPATH=tools/_devshim python code/task1_basics.py
"""

__version__ = "0.0.0-devshim"
