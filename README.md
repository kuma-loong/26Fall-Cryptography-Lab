# Cryptography Labs

哈尔滨工业大学（深圳）2026 年秋季《密码学基础》课程实验。

每个实验使用独立子目录，由根目录的同一个 Git 仓库管理。

| 目录 | 实验 | 状态 |
| --- | --- | --- |
| [lab1/](lab1/) | AES 的 ECB 模式安全性分析：模式泄露、密文分组拼接与 CBC / GCM 防御对照 | 课程初始内容 |

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

实验一从本地收到的课程包导入，保留源码和示例数据原样；初始提交不表示已完成个人实验。

## 运行实验一

使用 Python 3.8 或更新版本，安装正式的 `cryptography` 库：

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install cryptography
cd lab1/aes-lab/code
python check_env.py
python run_all.py
```

`run_all.py` 会依次运行课程包提供的 11 个步骤，不包含任务四的交互模式。需要交互体验时运行 `python task4_forge.py`。

`tools/_devshim/` 是课程包自带的验证垫片，日常实验使用正式安装的 `cryptography`。`tools/gen_truth.py` 生成的 `_truth_output.md` 属于本地产物，不纳入版本控制。

`data/` 中的四个文件作为课程初始示例纳入 Git；运行脚本会改写其中部分文件，提交时应检查这些差异。

## 公开内容范围

参考 [操作系统实验仓库](https://github.com/kuma-loong/26Fall-OS-Lab) 使用白名单管理公开内容，只追踪实验源码、必要示例数据和经过检查的课程材料。

个人填写的实验报告、个人笔记、截图、运行输出、虚拟环境、凭据和系统临时文件留在本地，默认忽略。原始空白报告模板通过精确路径纳入 Git；填写时请另存为其他文件名（例如 `实验一报告.docx`），避免将个人信息写入已追踪的模板。课程 PDF 仅对上面列出的四个原始文件开放；新文档、新实验目录与新数据文件需检查后再调整 `.gitignore`，不要通过 `git add -f` 加入个人材料。

提交前使用 `git status` 和 `git diff --cached` 检查内容。忽略规则不会识别已允许文件内部的个人信息。
