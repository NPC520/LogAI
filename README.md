<p align="center">
  <img src="icon.ico" alt="LogAI Logo" width="120" height="120">
</p>

<h1 align="center">LogAI - 流量日志智能威胁分析平台</h1>

<p align="center">
  🛡️ 基于大模型的多层网络流量威胁研判系统 | Windows 桌面应用
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue?logo=python" alt="Python">
  <img src="https://img.shields.io/badge/GUI-PySide6-green?logo=qt" alt="PySide6">
  <img src="https://img.shields.io/badge/Platform-Windows_10/11-blue?logo=windows" alt="Windows">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License">
  <img src="https://img.shields.io/badge/Release-v2.0.0-red" alt="Release">
</p>

---

## 📖 项目简介

**LogAI** 是一款面向网络安全分析师的 Windows 桌面应用。它能够导入网络流量日志（PCAP / CSV / TXT），通过**硬规则 + 信息熵 + 大模型**三级漏斗式分析管线，自动识别 SQL 注入、XSS、命令注入、LFI、SSRF 等 7 类攻击行为，并将结果以红色高亮形式展现在表格中。

与传统的规则匹配工具不同，LogAI 实现了：
- **攻击链自动还原**：将离散日志按源 IP 和时间窗口聚合，调用大模型还原攻击步骤并标注 MITRE ATT&CK 技术 ID
- **对话式日志分析**：分析师可用中文自然语言提问，AI 自动生成数据分析代码并返回结果
- **误报反馈闭环**：基于 Jaccard 相似度的终身学习机制，越用越准

---

## ✨ 核心功能

| 模块 | 功能 | 说明 |
|------|------|------|
| 🧠 **多模型接入** | 31+ LLM 供应商 | OpenAI、DeepSeek、Ollama、Groq、SiliconFlow、Zhipu 等，支持热切换与高级配置（代理、自定义请求头） |
| 📂 **日志导入** | PCAP / CSV / TXT | 基于 Scapy + Pandas 解析，自动识别格式，统一转为结构化数据 |
| 🔍 **威胁检测** | 规则 + 熵 + LLM 三级漏斗 | 硬规则正则匹配 → 香农熵异常检测 → 大模型深度研判，高效节省 Token |
| 🔴 **结果爆红** | 表格红色高亮 | 高危威胁整行红色标注，中危黄色，一目了然 |
| 🕐 **攻击链还原** | MITRE ATT&CK 时间轴 | 离散日志自动拼接为攻击步骤，vis.js 可视化展示完整攻击故事 |
| 🗺️ **攻击地图** | 离线瓦片 + GeoIP | 高德瓦片源离线地图（2-4 级可切换），红点标记攻击来源，支持层级选择 |
| 💬 **对话式查询** | 自然语言交互 | 输入"列出所有 SQL 注入"，AI 自动生成 Pandas 代码并在沙箱安全执行 |
| 🔄 **误报学习** | 反馈闭环 | 右键标记误报 → SQLite 存储 → Jaccard 相似度匹配 → 下次自动过滤 |
| ⚙️ **供应商管理** | 双面板配置 | 增删改查 LLM 供应商，支持 API Key / Base URL / 代理 / 自定义请求头 |

---

## 📸 界面预览

| 分析结果 | 攻击链时间轴 | 攻击地图 |
|:---:|:---:|:---:|
| *(截图待补充)* | *(截图待补充)* | *(截图待补充)* |

> 运行程序后按 `Win+Shift+S` 截图，保存到 `screenshots/` 文件夹，命名为 `main.png`、`timeline.png`、`map.png`，然后替换上面的占位文字为 `![截图](screenshots/main.png)` 即可。

---

## 🚀 快速开始

### 环境要求

- Windows 10 / 11 64 位
- Python 3.8 或更高版本
- （可选）Npcap —— 用于 PCAP 文件解析，[下载地址](https://npcap.com/)
- （可选）GeoLite2-City.mmdb —— 用于攻击地图 GeoIP 查询，[MaxMind 免费下载](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)

### 从源码运行

```bash
# 1. 克隆仓库
git clone https://github.com/NPC520/LogAI.git
cd LogAI

# 2. 创建虚拟环境
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3. 安装依赖
pip install -r requirements.txt

# 4. 启动程序
python main.py
下载安装包（无需 Python 环境）
前往 Releases 页面 下载 LogAI_Setup_2.0.0.exe，双击安装即可。

📁 项目结构
text
LogAI/
├── main.py                 # 程序入口
├── requirements.txt        # Python 依赖
├── LogAI.spec              # PyInstaller 打包配置
├── installer.iss           # Inno Setup 安装包脚本
├── icon.ico                # 程序图标
├── download_tiles.py       # 离线地图瓦片下载工具
│
├── configs/                # 配置文件
│   ├── providers.json      # LLM 供应商配置（31+）
│   └── rules.regex         # 硬规则正则表达式
│
├── core/                   # 核心业务逻辑
│   ├── log_loader.py       # 日志加载器（PCAP/CSV/TXT）
│   ├── filter_funnel.py    # 筛选漏斗（规则+熵值）
│   ├── llm_adapter.py      # 大模型统一适配器
│   ├── attack_story.py     # 攻击链生成器
│   ├── feedback_learner.py # 误报反馈学习
│   └── geo_service.py      # GeoIP 地理查询
│
├── ui/                     # 界面组件
│   ├── main_window.py      # 主窗口（分析流程 + 表格 + 聊天）
│   ├── settings_dialog.py  # 供应商配置对话框
│   ├── feedback_manager.py # 误报管理对话框
│   ├── timeline_view.py    # 攻击链时间轴（vis.js）
│   └── map_view.py         # 攻击地图（Leaflet + 离线瓦片）
│
├── tests/                  # 单元测试（34 个，全部通过）
├── tiles/                  # 离线地图瓦片（2-4 级）
└── plugins/                # 插件目录（解析器/导出器扩展）
🛠 技术栈
层级	技术
GUI 框架	PySide6（Qt for Python）
数据处理	Pandas、Scapy、NumPy
AI 接口	OpenAI SDK、Httpx、Ollama API
可视化	QWebEngineView、Leaflet.js、vis.js
数据库	SQLite（误报学习）
GeoIP	MaxMind GeoLite2
打包	PyInstaller + Inno Setup
测试	Pytest（34 个测试用例）
版本管理	Git + GitHub
📦 打包与安装
打包为 EXE
powershell
pyinstaller LogAI.spec
# 输出：dist/LogAI.exe（约 300MB，含所有依赖）
制作安装程序
安装 Inno Setup 7

打开 installer.iss，点击 Build → Compile

安装包生成在 Output/LogAI_Setup_2.0.0.exe

🔧 开发指南
添加新的 LLM 供应商
打开 configs/providers.json

在数组中添加新条目：

json
{
  "name": "提供商名称",
  "api_base": "API 地址",
  "api_key": "",
  "default_model": "模型名称",
  "proxy": "",
  "headers": {},
  "options": {"thinking_mode": true}
}
如果该供应商兼容 OpenAI API 格式，无需修改代码即可使用。否则在 core/llm_adapter.py 中新增子类。

添加新的日志解析器
在 plugins/parsers/ 下创建新的 .py 文件

实现 parse(file_path) -> pd.DataFrame 方法

程序启动时自动加载

✅ 运行测试
bash
pytest tests/ -v
# 34 passed in 4.55s
🤝 贡献
欢迎提交 Issue 或 Pull Request！

Fork 本仓库

新建特性分支：git checkout -b feature/xxx

提交更改：git commit -m "feat: xxx"

推送到分支：git push origin feature/xxx

创建 Pull Request

📄 开源协议
本项目采用 MIT License 开源。

⭐ Star History
如果觉得本项目对你有帮助，请给一个 Star ⭐

https://api.star-history.com/svg?repos=NPC520/LogAI&type=Date