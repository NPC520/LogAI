\# LogAI - 流量日志智能分析平台



🛡️ 基于大模型的网络流量威胁分析桌面应用，支持多模型接入、对话式分析、攻击链还原与高危自动爆红。



!\[Python](https://img.shields.io/badge/Python-3.8+-blue)

!\[PySide6](https://img.shields.io/badge/GUI-PySide6-green)

!\[License](https://img.shields.io/badge/License-MIT-yellow)



\---



\## ✨ 亮点特性



\- 🧠 \*\*多模型统一接入\*\*：支持 OpenAI、DeepSeek、Ollama(本地)、Groq 等 31+ 供应商，热切换无需重启。

\- 🔍 \*\*智能威胁检测\*\*：规则+熵+大模型三级漏斗，精准识别 SQLi/XSS/RCE/LFI/SSRF 等 7 类攻击。

\- 💬 \*\*对话式日志分析\*\*：输入中文问题（如“列出所有SQL注入”），AI 自动生成分析代码并返回结果。

\- 📊 \*\*攻击链还原\*\*：自动将离散日志拼成攻击步骤，标注 MITRE ATT\&CK 技术 ID（时间轴可视化）。

\- 🎨 \*\*高危爆红\*\*：分析结果表格中高风险自动红色高亮，支持右键标记误报。

\- 🔌 \*\*插件化扩展\*\*：支持自定义日志解析器与报告导出器，方便集成各类日志格式。



\---



\## 📸 界面预览



!\[主界面](screenshots/main.png)



\---



\## 🚀 快速开始



\### 环境要求



\- Windows 10/11

\- Python 3.8 及以上

\- （可选）Npcap（用于 pcap 文件解析）



\### 安装依赖



```bash

git clone https://github.com/NPC520/LogAI.git

cd LogAI

python -m venv venv

.\\venv\\Scripts\\activate

pip install -r requirements.txt

配置模型

启动后点击 设置 → 模型供应商配置



选择提供商（如 Ollama），填写 API Key 和 Base URL



点击 测试连接 确认可用



在主窗口右侧下拉框选择当前使用的模型



开始分析

点击 导入日志文件（支持 .pcap、.csv、.txt）



点击 开始分析，进度条显示处理进度



结果在表格中以红色高亮显示高危威胁



在下方聊天框输入问题，与日志数据对话



LogAI/

├── main.py                # 入口

├── ui/                    # 界面模块

│   ├── main\_window.py

│   ├── settings\_dialog.py

│   └── ...

├── core/                  # 核心逻辑

│   ├── llm\_adapter.py     # 多模型统一适配器

│   ├── log\_loader.py      # 日志解析器

│   ├── filter\_funnel.py   # 规则+熵筛选器

│   ├── attack\_story.py    # 攻击链拼图

│   └── feedback\_learner.py # 误报学习

├── configs/               # 配置文件

│   ├── providers.json     # 模型供应商列表

│   └── rules.regex        # 硬规则正则

├── plugins/               # 插件目录

│   ├── parsers/

│   └── exporters/

└── requirements.txt

🛠 技术栈

GUI: PySide6

数据: Pandas, Scapy

AI 接口: OpenAI, Groq, Ollama (httpx)

可视化: PySide6 QTableView, 内嵌 HTML/JS (时间轴、地图)

打包: PyInstaller + Inno Setup

🤝 贡献

欢迎提交 Issue 或 Pull Request，一起让日志分析更智能！

📄 开源协议

本项目采用 MIT License。

⭐ 如果觉得本项目对你有帮助，请给一个 Star！



