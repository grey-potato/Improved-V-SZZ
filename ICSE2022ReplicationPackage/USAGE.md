# LLM-Enhanced V-SZZ 运行指南

## 📖 简介

LLM-Enhanced V-SZZ 是一个使用大语言模型增强的漏洞引入提交（Vulnerability Introducing Commit, VIC）追踪工具。它结合了传统的 AST/srcml 代码分析工具和 LLM 的语义理解能力，提供更准确的追踪结果。

### 核心特性

- 🔍 **混合分析模式**: AST/srcml 工具 + LLM 协同分析
- 🧠 **双 LLM 架构**: 大模型追踪 + 小模型验证
- 🔄 **反馈循环**: 验证失败自动重试
- 💾 **智能缓存**: 减少重复 API 调用
- 📊 **置信度评估**: 工具结果可信度标注

---

## 🛠️ 环境要求

### Python 依赖

```bash
pip install openai gitpython
```

### 外部工具（可选，用于混合模式）

| 工具 | 用途 | 安装 |
|------|------|------|
| **Java + ASTMapEval.jar** | Java 代码 AST 分析 | 需要 JDK 8+ |
| **srcml** | C/C++/C#/Java 代码分析 | `choco install srcml` (Windows) |

---

## ⚙️ 配置

### API 配置

本工具默认使用 **云雾 API**（`https://yunwu.ai/v1`）。

#### 方式 1: 环境变量（推荐）

```powershell
# PowerShell
$env:OPENAI_API_KEY = "你的API密钥"

# 或使用其他 API 服务
$env:OPENAI_BASE_URL = "https://api.openai.com/v1"
```

```bash
# Linux/macOS
export OPENAI_API_KEY="你的API密钥"
export OPENAI_BASE_URL="https://yunwu.ai/v1"
```

#### 方式 2: 命令行参数

```bash
python run_llm_vszz.py /path/to/repo commit_hash --api-key sk-xxx
```

### 模型配置

| 参数 | 默认值 | 用途 |
|------|--------|------|
| `--large-model` | `gpt-5.1-codex` | 大模型，用于追踪决策 |
| `--small-model` | `gpt-5-mini` | 小模型，用于结果验证 |

---

## 🚀 运行模式

### 模式 1: 混合模式（推荐）

结合 AST/srcml 工具和 LLM 进行分析。**工具提供辅助信息，LLM 做最终决策。**

```bash
python run_llm_vszz.py <仓库路径> <修复提交哈希>
```

**示例：**

```bash
python run_llm_vszz.py C:\repos\activemq a1b2c3d4e5f6
```

**工作流程：**

```
┌─────────────────────────────────────────────────────────────────┐
│                        混合模式工作流                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────┐    ┌──────────────────────────────────────────┐  │
│  │ Java 文件 │───▶│ AST 工具 (ASTMapEval.jar) + srcml       │  │
│  └──────────┘    │ ↓                                        │  │
│                  │ 工具结果 (带置信度)                       │  │
│  ┌──────────┐    │ ↓                                        │  │
│  │ C/C++ 文件│───▶│ srcml 分析                              │  │
│  └──────────┘    │ ↓                                        │  │
│                  │ 工具结果 (带置信度)                       │  │
│  ┌──────────┐    └──────────────────────────────────────────┘  │
│  │ 其他文件  │──┐                                              │
│  └──────────┘  │                                              │
│                ▼                                              │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │           大 LLM (gpt-5.1-codex)                         │  │
│  │  • 接收工具结果（仅供参考，可能有误差）                    │  │
│  │  • 独立分析代码语义                                       │  │
│  │  • 做出追踪决策                                           │  │
│  └──────────────────────────────────────────────────────────┘  │
│                ↓                                              │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │           小 LLM (gpt-5-mini) 验证                        │  │
│  │  • 验证追踪链的合理性                                     │  │
│  │  • 如验证失败，反馈给大 LLM 重新分析                       │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 模式 2: 纯 LLM 模式

仅使用 LLM 进行分析，不依赖任何外部工具。适用于工具不支持的语言（如 Python、Go、Rust）。

```bash
python run_llm_vszz.py <仓库路径> <修复提交哈希> --pure-llm
```

**示例：**

```bash
python run_llm_vszz.py C:\repos\my-project abc123 --pure-llm
```

**工作流程：**

```
┌─────────────────────────────────────────────────────────────────┐
│                        纯 LLM 模式                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  修复提交 diff ──▶ 大 LLM 分析 ──▶ 追踪决策 ──▶ 小 LLM 验证    │
│                         ↑                           │          │
│                         └─────── 反馈循环 ──────────┘          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📋 命令行参数

```
python run_llm_vszz.py [选项] <仓库路径> <修复提交>
```

### 必需参数

| 参数 | 说明 |
|------|------|
| `仓库路径` | Git 仓库的本地路径 |
| `修复提交` | 漏洞修复提交的哈希值（完整或前缀） |

### 可选参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--api-key` | API 密钥 | 环境变量 `OPENAI_API_KEY` |
| `--base-url` | API 基础 URL | `https://yunwu.ai/v1` |
| `--large-model` | 大模型名称 | `gpt-5.1-codex` |
| `--small-model` | 小模型名称 | `gpt-5-mini` |
| `--pure-llm` | 使用纯 LLM 模式 | 否（使用混合模式） |
| `--ast-path` | AST 工具路径 | 自动检测 |
| `--no-cache` | 禁用 LLM 缓存 | 否（启用缓存） |
| `--max-depth` | 最大追踪深度 | 30 |
| `--max-iterations` | 最大重试次数 | 3 |
| `-o, --output` | 输出 JSON 文件路径 | 无 |

---

## 📝 使用示例

### 基础使用

```bash
# 分析单个修复提交
python run_llm_vszz.py C:\repos\activemq a1b2c3d4

# 输出结果到文件
python run_llm_vszz.py C:\repos\activemq a1b2c3d4 -o results.json
```

### 自定义模型

```bash
# 使用更强的模型
python run_llm_vszz.py C:\repos\myproject abc123 \
    --large-model gpt-5.2 \
    --small-model gpt-4.1-mini
```

### 调试模式

```bash
# 禁用缓存（每次都重新调用 LLM）
python run_llm_vszz.py C:\repos\myproject abc123 --no-cache
```

### 使用其他 API 服务

```bash
# 使用 OpenAI 官方 API
python run_llm_vszz.py C:\repos\myproject abc123 \
    --base-url https://api.openai.com/v1 \
    --api-key sk-xxx
```

---

## 📊 输出格式

### 控制台输出

```
======================================================================
🔍 LLM-Enhanced V-SZZ 分析
======================================================================
仓库: C:\repos\activemq
修复提交: a1b2c3d4e5f6
大模型: gpt-5.1-codex
小模型: gpt-5-mini
分析模式: 混合模式 (AST/srcml + LLM)

📂 获取受影响的文件...
   找到 2 个受影响文件
   - src/main/java/Vulnerable.java: 5 行

🚀 开始追踪...

======================================================================
📊 分析结果
======================================================================

结果 1:
  修复提交: a1b2c3d4e5f6
  BIC提交: x7y8z9w0a1b2
  验证状态: ✅ 通过
  迭代次数: 1
  追踪链长度: 3
  追踪链:
    1. ➡️ def456ab [MODIFIED] 重构了输入验证逻辑...
    2. ➡️ ghi789cd [MODIFIED] 添加了新的处理方法...
    3. 🎯 x7y8z9w0 [INTRODUCED] 初始实现，缺少输入验证...
```

### JSON 输出格式

```json
[
  {
    "fix_commit": "a1b2c3d4e5f6...",
    "bic_commit": "x7y8z9w0a1b2...",
    "verified": true,
    "iterations": 1,
    "tracking_chain": [
      {
        "commit_hash": "def456ab...",
        "commit_date": "2024-01-15",
        "commit_message": "重构了输入验证逻辑",
        "file_path": "src/main/java/Vulnerable.java",
        "line_num": 42,
        "change_type": "MODIFIED",
        "reasoning": "该提交修改了验证逻辑但保留了漏洞",
        "confidence": 0.85
      },
      {
        "commit_hash": "x7y8z9w0...",
        "commit_date": "2023-06-20",
        "commit_message": "初始实现",
        "file_path": "src/main/java/Vulnerable.java",
        "line_num": 35,
        "change_type": "INTRODUCED",
        "reasoning": "首次引入了缺少输入验证的代码",
        "confidence": 0.92
      }
    ]
  }
]
```

---

## ⚠️ 注意事项

### 工具结果的可信度

混合模式下，AST/srcml 工具的分析结果**仅供参考**：

- 工具可能产生误报或漏报
- LLM 会独立分析代码，不盲目信任工具结果
- 低置信度结果会在提示词中标注警告

### API 成本

| 操作 | 预估 Token 消耗 |
|------|----------------|
| 单次追踪决策 | 2,000 - 5,000 |
| 单次验证 | 1,000 - 2,000 |
| 完整分析（含重试） | 10,000 - 50,000 |

建议使用缓存（默认启用）来减少重复调用。

### 支持的语言

| 语言 | 混合模式 | 纯 LLM 模式 |
|------|---------|-------------|
| Java | ✅ AST + srcml | ✅ |
| C/C++ | ✅ srcml | ✅ |
| C# | ✅ srcml | ✅ |
| Python | ❌ | ✅ |
| Go | ❌ | ✅ |
| Rust | ❌ | ✅ |
| JavaScript | ❌ | ✅ |

---

## 🔧 故障排除

### 常见问题

**1. API 密钥错误**

```
❌ 未配置API密钥
```

解决：设置环境变量 `OPENAI_API_KEY` 或使用 `--api-key` 参数。

**2. 仓库不存在**

```
❌ 仓库路径不存在
```

解决：确认路径正确，且包含 `.git` 目录。

**3. AST 工具不可用**

```
⚠️ AST工具不可用，使用纯LLM分析
```

解决：安装 JDK 并确保 `ASTMapEval_jar` 目录存在，或使用 `--pure-llm` 模式。

**4. srcml 不可用**

```
⚠️ srcml工具不可用
```

解决：安装 srcml 并确保在 PATH 中，或使用 `--pure-llm` 模式。

---

## 📚 相关资源

- [原始 V-SZZ 论文](https://doi.org/10.1109/ICSE43902.2021.00048)
- [OpenAI API 文档](https://platform.openai.com/docs)
- [云雾 API](https://yunwu.ai)
- [srcml 官网](https://www.srcml.org)

---

## 📄 License

MIT License
