"""cryptography.exceptions 的最小子集。"""


class InvalidTag(Exception):
    """AEAD 认证标签校验失败。真实 cryptography 里也是这个名字。"""


class InvalidSignature(Exception):
    pass
