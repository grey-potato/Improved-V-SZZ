# 集成V-SZZ使用说明（LLM验证版）

## 🎯 系统特点

**LLM精确验证 + V-SZZ分析 = 高准确度漏洞溯源**

系统使用GPT-4验证BFC，确保分析质量：
1. 快速扫描仓库提交（规则筛选候选）
2. **LLM深度验证**每个候选是否真的是安全修复
3. 对验证通过的BFC运行V-SZZ分析
4. 输出漏洞引入提交(BIC)及详细信息

---

## ⚙️ 前置要求

### **必需：OpenAI API Key**

系统使用GPT-4模型验证BFC，需要OpenAI API访问权限。

**获取API Key：**
1. 访问 https://platform.openai.com/api-keys
2. 注册/登录账号
3. 创建新的API密钥
4. 复制密钥（格式：`sk-proj-...`）

**配置方法：**

**方法1：环境变量（推荐）**
```powershell
# PowerShell
$env:OPENAI_API_KEY="sk-your-actual-key-here"

# 验证
echo $env:OPENAI_API_KEY
```

**方法2：命令行参数**
```bash
python integrated_vszz.py repo_path --openai-key sk-your-key
```

**成本估算：**
- GPT-4 验证：约 $0.02-0.05 per BFC
- 分析10个BFC：约 $0.20-0.50
- 分析50个BFC：约 $1-2.5

---

## 🚀 快速开始

### 最简单的方式

```bash
cd ICSE2022ReplicationPackage

# 1. 设置API Key（只需一次）
$env:OPENAI_API_KEY="sk-xxx"

# 2. 运行快速分析
python quick_analyze.py <仓库路径>
```

**示例：**
```bash
# 分析activemq（使用环境变量中的API Key）
python quick_analyze.py ..\repos\activemq

# 或直接指定API Key
python quick_analyze.py ..\repos\activemq sk-your-key

# 自定义参数
python quick_analyze.py ..\repos\activemq sk-xxx 500 10
```

---

## 📖 六种使用模式

### 1️⃣ 完整分析（默认）

**扫描 → LLM验证 → V-SZZ分析**

```bash
python integrated_vszz.py <仓库路径> --openai-key sk-xxx
```

输出：BFC列表 + 每个BFC的BIC

---

### 2️⃣ 扫描模式

**只扫描候选，不验证不分析（不需要API Key）**

```bash
python integrated_vszz.py <仓库路径> --scan-only
```

生成：`integrated_results/项目名_candidates_时间戳.json`

**用途：**
- 先快速看看有哪些可能的BFC
- 节省API成本，后续按需分析
- 团队讨论选择哪些候选

---

### 3️⃣ 指定Commit

**直接分析已知的commit**

```bash
# 单个
python integrated_vszz.py repo --commit abc123def --openai-key sk-xxx

# 多个
python integrated_vszz.py repo --commit abc123,def456,ghi789 --openai-key sk-xxx
```

**适用场景：**
- 已知某个commit是BFC（如从CVE数据库查到）
- 快速验证特定commit
- 复现研究结果

---

### 4️⃣ CVE搜索

**自动查找CVE相关commits并分析**

```bash
python integrated_vszz.py repo --cve CVE-2023-1234 --openai-key sk-xxx
```

**工作流程：**
1. 扫描commit message包含该CVE的提交
2. LLM验证是否真的是该CVE的修复
3. 对验证通过的运行V-SZZ

---

### 5️⃣ 文件加载

**从扫描结果中选择特定BFC分析**

```bash
# 第一步：扫描（不需要API Key）
python integrated_vszz.py repo --scan-only

# 第二步：查看候选，选择要分析的
cat integrated_results/*_candidates_*.json

# 第三步：分析选定的BFC
python integrated_vszz.py repo --analyze-from candidates.json --ids 1,3,5 --openai-key sk-xxx
```

**优点：**
- 避免重复扫描
- 精确控制成本
- 可以分批分析

---

### 6️⃣ 交互模式

**交互式选择要分析的BFC**

```bash
python integrated_vszz.py repo --interactive --openai-key sk-xxx
```

**交互流程：**
```
找到 15 个候选:
[1] abc123 (分数:30) - Fix CVE-2023-1234
[2] def456 (分数:25) - Fix XSS vulnerability
...

请选择: 1,3,5
或输入范围: 1-5
或输入 'all'
> 1,3

✓ 选择了 2 个BFC
开始LLM验证...
```

---

## 📊 输出结果

### 控制台输出示例

```
================================================================================
🚀 集成V-SZZ分析: activemq
================================================================================

【阶段1】扫描候选BFC (扫描最近500个提交)...
  扫描进度: 100/500
  扫描进度: 200/500
  ...
✓ 找到 15 个候选

🔝 Top 10 BFC候选:

1. a1b2c3d4 (分数: 35)
   2023-05-10T14:30:00 | John Doe
   Fix CVE-2023-1234: SQL injection vulnerability in authentication...
   原因: 高优先级:cve; 高优先级:vulnerability; 中优先级:injection; 修复类
   核心文件: 3

...

【阶段1.5】LLM验证BFC (处理前10个候选)...
  验证 1/10: a1b2c3d4
    ✓ 通过 (置信度: 0.95, 类型: SQL Injection)
  验证 2/10: e5f6g7h8
    ✗ 未通过 (置信度: 0.45)
  ...
✓ LLM验证通过 5 个BFC

【阶段2】V-SZZ分析 (处理5个BFC)...

分析 1/5: a1b2c3d4
  消息: Fix CVE-2023-1234: SQL injection...
  → 获取受影响文件...
  → 受影响文件: 2
  → 查找BIC...
  ✓ 找到 3 个BIC候选
      1. f9g0h1i2
      2. j3k4l5m6
      3. n7o8p9q0

...

【阶段3】生成报告...
💾 候选BFC: integrated_results/activemq_candidates_20260112_143022.json
💾 验证结果: integrated_results/activemq_20260112_143022.json
💾 报告: integrated_results/activemq_20260112_143022_report.txt

================================================================================
✅ 分析完成
================================================================================
📊 统计:
  - 扫描提交: 500
  - 初步候选: 15
  - LLM验证通过: 5
  - 成功分析: 5
  - 总BIC: 12

💾 结果已保存: integrated_results/activemq_20260112_143022.json
```

### JSON结构

```json
{
  "repository": {
    "name": "activemq",
    "path": "/path/to/repo"
  },
  "analysis_info": {
    "timestamp": "20260112_143022",
    "bfc_count": 5,
    "successful_analysis": 5,
    "total_bics": 12
  },
  "bfcs": [
    {
      "commit_hash": "a1b2c3d4...",
      "short_hash": "a1b2c3d4",
      "date": "2023-05-10T14:30:00",
      "author": "John Doe",
      "message": "Fix CVE-2023-1234: SQL injection...",
      "cve_id": "CVE-2023-1234",
      "vulnerability_type": "SQL Injection",
      "llm_verified": true,
      "confidence": 0.95,
      "cwe_id": "CWE-89",
      "severity": "High",
      "vulnerability_description": "SQL injection in authentication module",
      "core_files": ["src/auth/login.java", "src/db/query.java"],
      "bic_count": 3
    }
  ],
  "bic_mapping": {
    "a1b2c3d4...": ["f9g0h1i2...", "j3k4l5m6...", "n7o8p9q0..."]
  }
}
```

---

## 💡 使用建议

### 首次使用
```bash
# 1. 小规模测试
python integrated_vszz.py repo --max-commits 100 --max-bfcs 3 --openai-key sk-xxx

# 2. 检查结果是否合理

# 3. 扩大规模
python integrated_vszz.py repo --max-commits 500 --max-bfcs 10 --openai-key sk-xxx
```

### 节省成本
```bash
# 1. 先免费扫描
python integrated_vszz.py repo --scan-only --max-commits 1000

# 2. 查看候选，选择高分的
cat candidates.json

# 3. 只验证高分候选
python integrated_vszz.py repo --analyze-from candidates.json --ids 1,2,3 --openai-key sk-xxx
```

### 研究特定漏洞
```bash
# 直接搜索CVE
python integrated_vszz.py repo --cve CVE-2023-1234 --openai-key sk-xxx
```

### 批量分析
```bash
# 分批处理，避免一次性成本过高
python integrated_vszz.py repo --scan-only
python integrated_vszz.py repo --analyze-from candidates.json --ids 1-10 --openai-key sk-xxx
python integrated_vszz.py repo --analyze-from candidates.json --ids 11-20 --openai-key sk-xxx
```

---

## ⚙️ 参数说明

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `repo_path` | 位置参数 | - | Git仓库路径 |
| `--openai-key` | 字符串 | 环境变量 | OpenAI API Key |
| `--max-commits` | 整数 | 500 | 最多扫描提交数 |
| `--max-bfcs` | 整数 | 10 | 最多LLM验证数 |
| `--min-score` | 整数 | 10 | 候选最低分数 |
| `--scan-only` | 标志 | False | 只扫描不验证 |
| `--commit` | 字符串 | - | 指定commit |
| `--cve` | 字符串 | - | 指定CVE |
| `--analyze-from` | 文件 | - | 从文件加载 |
| `--ids` | 字符串 | - | 选择的ID |
| `--interactive` | 标志 | False | 交互模式 |

---

## ❓ 常见问题

**Q: 必须使用LLM吗？**
是的。本系统设计为使用LLM确保高准确度。如果只想扫描候选，使用`--scan-only`。

**Q: API Key如何收费？**
按token计费。验证一个BFC约$0.02-0.05，取决于commit大小和diff长度。

**Q: 扫描很慢怎么办？**
减少`--max-commits`或`--max-bfcs`参数。

**Q: LLM验证失败怎么办？**
检查网络连接和API Key是否正确。可以先用`--scan-only`保存候选，稍后重试。

**Q: 如何提高准确度？**
降低`--min-score`发现更多候选，让LLM验证更多可能性。

**Q: 候选太少怎么办？**
- 降低`--min-score`（如改为5）
- 增加`--max-commits`扫描范围
- 检查仓库是否有安全相关commit

---

## 📞 技术支持

### 配置问题
```bash
# 测试API Key
python -c "from openai import OpenAI; print(OpenAI().models.list())"

# 检查环境变量
echo $env:OPENAI_API_KEY
```

### 调试模式
```python
# 单独测试BFC识别
from integrated_vszz import IntegratedVSZZ
analyzer = IntegratedVSZZ('repo_path')
candidates = analyzer._identify_bfcs(100, 10)
print(f"找到 {len(candidates)} 个候选")
```

---

## 🎓 示例工作流

### 完整研究流程

```bash
# 1. 探索阶段：扫描候选（免费）
python integrated_vszz.py ../repos/activemq --scan-only --max-commits 1000

# 2. 筛选阶段：查看候选，记录感兴趣的ID
cat integrated_results/*_candidates_*.json | grep -A 5 "CVE"

# 3. 验证阶段：LLM验证高分候选
python integrated_vszz.py ../repos/activemq --analyze-from candidates.json --ids 1,2,3,5,8 --openai-key sk-xxx

# 4. 深入分析：对特定CVE进行详细分析
python integrated_vszz.py ../repos/activemq --cve CVE-2023-1234 --openai-key sk-xxx

# 5. 结果整理：查看报告
cat integrated_results/*_report.txt
```
