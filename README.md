# Cryptography Labs

哈尔滨工业大学（深圳）2026 年秋季《密码学基础》课程实验，围绕对称加密、公钥密码与密钥安全开展实践。

## 实验内容

| 实验 | 内容 |
| --- | --- |
| [实验一：AES 的 ECB 模式安全性分析](lab1/) | 观察模式泄露，通过密文分组拼接伪造消息，并比较 CBC、GCM 的防御效果；支持多字段拼接与自动搜索。 |
| [实验二：RSA 共享素因子攻击](lab2/lab2-RSA/) | 实现扩展欧几里得算法与模逆，扫描共享素因子、重复模数和完全平方模数，恢复私钥并解密文件。 |
| [实验三：哈希长度扩展与碰撞攻击](lab3/lab3-hash/) | 实现 MD5 填充与摘要续写，伪造银行 API 请求，构造同 MD5、不同行为的程序，并验证 HMAC 防御。 |

## 运行

使用 Python 3.10 或更新版本。实验一依赖 `cryptography`，实验二、三仅使用标准库。以下命令均从仓库根目录运行。

实验一：

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install cryptography==50.0.2
python lab1/aes-lab/code/run_all.py
```

实验二：

```sh
python3 lab2/lab2-RSA/rsa-lab/code/run_all.py
python3 lab2/lab2-RSA/rsa-lab/code/verify.py --appendix-b
```

实验三：

```sh
python3 lab3/lab3-hash/hash-lab/code/issue_url.py
python3 lab3/lab3-hash/hash-lab/code/run_all.py
python3 lab3/lab3-hash/hash-lab/code/verify.py
```
