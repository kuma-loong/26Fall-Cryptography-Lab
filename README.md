# Cryptography Labs

哈尔滨工业大学（深圳）2026 年秋季《密码学基础》课程实验。

每个实验使用独立子目录，由根目录的同一个 Git 仓库管理。

| 目录 | 实验 | 状态 |
| --- | --- | --- |
| [lab1/](lab1/) | AES 的 ECB 模式安全性分析：模式泄露、密文分组拼接与 CBC / GCM 防御对照 | 已实现多字段拼接、自动搜索并验证 |

## 实验一目录

```text
lab1/
├── 密码学基础-1-AES 的 ECB 模式安全性分析.pdf
├── 密码学基础实验一报告（模板）.doc
└── aes-lab/
    ├── 0-实验指导.pdf
    ├── 1-实验原理.pdf
    ├── 2-实验步骤.pdf
    ├── code/     # 课程提供的实验脚本
    ├── data/     # 课程初始示例消息、历史密文与伪造密文
    └── tools/    # 课程包附带的参考实现及验证工具
```

实验一从本地收到的课程包导入；初始内容见提交 `578ae92`。后续在任务一增加整分组填充实测，在任务四增加多字段拼接和自动搜索，并加入独立回归检查。

## 运行实验一

使用 Python 3.8 或更新版本，安装正式的 `cryptography` 库：

```sh
uv venv .venv
uv pip install --python .venv/bin/python cryptography==50.0.2
source .venv/bin/activate
cd lab1/aes-lab/code
python check_env.py
python run_all.py
```

`run_all.py` 会依次运行课程包提供的 11 个步骤，不包含任务四的交互模式。需要交互体验时运行 `python task4_forge.py`。

在 `code/` 中可运行扩展功能和回归检查：

```sh
# 一次修改三个字段，分组来自 M4、M1、M3、M2。
python task4_forge.py -t M1 --replace From=M4 --replace Date=M3 --replace Place=M2
python bob_decrypt.py -i ../data/forged.ct

# 根据历史库的已知明文标注，搜索出来自四条不同消息的取块配方。
python task4_forge.py -t M1 --want From=Bob --want To=Carol --want Date=2026-03-22 --want Place=Gym
python bob_decrypt.py -i ../data/forged.ct
python -m unittest -v test_lab1.py
```

自动搜索以历史库中存在对应字段为前提，只使用已知的同位置密文块。攻击工具只导入标准库和 `block_utils`，解密检查在 Bob 或测试代码中执行。

`test_lab1.py` 检查全部 1296 种字段来源组合、单字段兼容、自动搜索和导入隔离。任务六原演示使用固定 CBC IV、重复 GCM nonce，属于故意设置的反例；同前缀 CBC 密文块相同的观察依赖相同 IV，不能推广到独立随机 IV。

`tools/_devshim/` 是课程包自带的验证垫片，日常实验使用正式安装的 `cryptography`。`tools/gen_truth.py` 生成的 `_truth_output.md` 属于本地产物，不纳入版本控制。

`data/` 中的四个文件作为课程初始示例纳入 Git；运行脚本会改写其中部分文件，提交时应检查这些差异。

## 公开内容范围

参考 [操作系统实验仓库](https://github.com/kuma-loong/26Fall-OS-Lab) 使用白名单管理公开内容，只追踪实验源码、必要示例数据和经过检查的课程材料。

个人填写的实验报告、个人笔记、截图、运行输出、虚拟环境、凭据和系统临时文件留在本地，默认忽略。原始空白报告模板通过精确路径纳入 Git；填写时请另存为其他文件名（例如 `实验一报告.docx`），避免将个人信息写入已追踪的模板。课程 PDF 仅对上面列出的四个原始文件开放；新文档、新实验目录与新数据文件需检查后再调整 `.gitignore`，不要通过 `git add -f` 加入个人材料。

提交前使用 `git status` 和 `git diff --cached` 检查内容。忽略规则不会识别已允许文件内部的个人信息。
