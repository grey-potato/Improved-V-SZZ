# LLM-Enhanced V-SZZ 混合架构

## 概述

LLM-Enhanced V-SZZ 采用混合架构，结合传统代码分析工具（AST/srcml）和大语言模型（LLM），实现高效、准确的漏洞引入提交（BIC）追踪。

## 架构图

```
                    ┌─────────────────────────────────────┐
                    │         Fix Commit (漏洞修复提交)     │
                    └─────────────────┬───────────────────┘
                                      │
                                      ▼
                    ┌─────────────────────────────────────┐
                    │     获取受影响文件和行 (Git Diff)      │
                    └─────────────────┬───────────────────┘
                                      │
                                      ▼
                    ┌─────────────────────────────────────┐
                    │         Git Blame (获取历史)          │
                    └─────────────────┬───────────────────┘
                                      │
                    ┌─────────────────┴───────────────────┐
                    │                                     │
                    ▼                                     ▼
        ┌───────────────────┐               ┌───────────────────┐
        │    Java 文件?      │               │    C/C++ 文件?     │
        └─────────┬─────────┘               └─────────┬─────────┘
                  │                                   │
        ┌─────────┴─────────┐               ┌─────────┴─────────┐
        │    AST 工具分析    │               │   srcml 工具分析   │
        │  (ASTMapEval.jar) │               │   (srcml CLI)     │
        └─────────┬─────────┘               └─────────┬─────────┘
                  │                                   │
                  └───────────────┬───────────────────┘
                                  │
                                  ▼
                  ┌─────────────────────────────────────┐
                  │          大LLM 验证/增强              │
                  │   (验证工具结果 + 语义理解)           │
                  │   GPT-4 / Claude / 其他             │
                  └─────────────────┬───────────────────┘
                                    │
                          ┌─────────┴─────────┐
                          │                   │
                          ▼                   ▼
              ┌─────────────────┐   ┌─────────────────┐
              │   INTRODUCED    │   │    MODIFIED     │
              │   (找到BIC)      │   │  (继续追踪)      │
              └────────┬────────┘   └────────┬────────┘
                       │                     │
                       │                     └──────► 返回 Git Blame
                       │
                       ▼
              ┌─────────────────────────────────────┐
              │           小LLM 验证                  │
              │    (验证BIC是否正确)                  │
              │    GPT-3.5 / 小型模型                │
              └─────────────────┬───────────────────┘
                                │
                      ┌─────────┴─────────┐
                      │                   │
                      ▼                   ▼
              ┌─────────────┐     ┌─────────────┐
              │   ACCEPT    │     │   REJECT    │
              │  (接受结果)  │     │ (重新追踪)   │
              └──────┬──────┘     └──────┬──────┘
                     │                   │
                     │                   └──────► 带反馈重新追踪
                     │
                     ▼
              ┌─────────────────────────────────────┐
              │            输出 BIC 结果             │
              └─────────────────────────────────────┘
```

## 组件说明

### 1. 代码分析工具 (`code_analyzer.py`)

封装了两种代码分析工具：

#### ASTAnalyzer (Java)
- 使用 `ASTMapEval.jar` 进行 AST 级别的代码变更分析
- 支持精确的语句级别映射
- 可以识别 Insert/Delete/Update/Move 等变更类型

#### SrcMLAnalyzer (C/C++)
- 使用 `srcml` CLI 工具将代码转换为 XML
- 基于行内容匹配进行变更分析
- 支持 C/C++ 文件（.c, .h, .cpp, .hpp, .cc, .cxx）

### 2. LLM 客户端 (`llm_client.py`)

- 支持 OpenAI API 和兼容服务
- 内置响应缓存（SHA256 哈希）
- 统计 API 调用次数和缓存命中率

### 3. 核心追踪逻辑 (`llm_vszz.py`)

#### 混合分析流程：
1. **工具先行**：对于支持的语言，先用 AST/srcml 工具分析
2. **LLM 增强**：把工具结果传给大 LLM 进行验证和语义分析
3. **验证循环**：用小 LLM 验证最终结果，失败则重新追踪

#### 特殊处理：
- **智能截断**：对大型 diff 进行智能截断，保留关键上下文
- **NEED_MORE_INFO**：LLM 可以请求更多上下文（最多3级）
- **反馈循环**：验证失败时，反馈信息会传给下一轮追踪

## 使用方法

### 基本用法（混合模式）

```bash
# 默认使用混合模式（AST/srcml + LLM）
python run_llm_vszz.py /path/to/repo abc123def456
```

### 纯 LLM 模式

```bash
# 不使用 AST/srcml，完全依赖 LLM
python run_llm_vszz.py /path/to/repo abc123 --pure-llm
```

### 自定义模型

```bash
# 使用 GPT-4-turbo 和 GPT-3.5-turbo
python run_llm_vszz.py /path/to/repo abc123 \
    --large-model gpt-4-turbo \
    --small-model gpt-3.5-turbo
```

### 保存结果

```bash
python run_llm_vszz.py /path/to/repo abc123 -o results.json
```

## 混合模式的优势

1. **成本优化**：工具分析结果可以减少 LLM 需要推理的内容，降低 token 消耗
2. **准确性提升**：工具提供精确的语法分析，LLM 提供语义理解，互相补充
3. **鲁棒性**：当工具失败时，可以回退到纯 LLM 模式
4. **可追溯性**：保留工具分析结果，便于调试和审计

## 配置要求

### 环境变量

```bash
export OPENAI_API_KEY=sk-xxx
export OPENAI_BASE_URL=https://api.openai.com/v1  # 可选，用于兼容服务
```

### 工具依赖

- **Java**: 需要 JRE/JDK（AST 分析）
- **srcml**: 需要安装 srcml CLI（https://www.srcml.org/）

## 文件结构

```
ICSE2022ReplicationPackage/
├── llm_vszz.py          # 核心追踪逻辑
├── llm_client.py        # LLM 客户端封装
├── code_analyzer.py     # 代码分析工具封装
├── run_llm_vszz.py      # CLI 入口
├── ASTMapEval_jar/      # AST 工具目录
│   └── ASTMapEval.jar
└── .llm_cache/          # LLM 响应缓存（自动创建）
```

## 输出格式

```json
{
    "fix_commit": "abc123...",
    "bic_commit": "def456...",
    "verified": true,
    "iterations": 1,
    "tracking_chain": [
        {
            "commit_hash": "...",
            "commit_date": "...",
            "commit_message": "...",
            "file_path": "...",
            "line_num": 42,
            "change_type": "MODIFIED",
            "reasoning": "...",
            "confidence": 0.95
        },
        {
            "change_type": "INTRODUCED",
            "..."
        }
    ]
}
```
