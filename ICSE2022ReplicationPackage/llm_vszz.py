#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
LLM 增强版 V-SZZ 实现

核心设计原则：
- LLM 永远是最终决策者，工具只是提供辅助信息
- Java 代码：AST + srcml 综合分析 → 结果给 LLM
- 非 Java 代码：srcml 分析 → 结果给 LLM
- 所有代码都必须经过 LLM 分析
"""

import os
import sys
import json
import re
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime

from git import Repo

# 添加pyszz路径
sys.path.append(os.path.join(os.path.dirname(__file__), 
                             'icse2021-szz-replication-package/tools/pyszz/'))

from szz.core.abstract_szz import AbstractSZZ, ImpactedFile
from llm_client import CachedLLMClient, create_llm_client
from code_analyzer import CodeAnalyzerFactory, ToolAnalysisResult, CombinedToolResult


# ============================================================================
# Prompt 模板
# ============================================================================

TRACKING_SYSTEM_PROMPT = """你是一个专业的代码安全分析专家，专门追踪漏洞代码的引入历史。

你的任务是分析 Git blame 返回的提交，判断该提交对漏洞代码做了什么操作：
1. INTRODUCED - 这个提交首次引入了漏洞代码（这就是我们要找的BIC）
2. MODIFIED - 漏洞代码在此之前就存在，这个提交只是修改/移动/重命名了代码
3. UNRELATED - 这行代码的改动与漏洞无关（如纯注释、格式化）
4. NEED_MORE_INFO - 提供的代码信息不足以做出判断，需要更多上下文

关键判断原则：
- 如果漏洞的核心逻辑（如SQL字符串拼接、缺少权限检查等）是在这个提交中首次出现的，则是 INTRODUCED
- 如果漏洞逻辑之前就存在，这个提交只是移动代码位置、重命名变量、重构等，则是 MODIFIED
- 如果改动只是空白、注释、与漏洞无关的代码，则是 UNRELATED
- 如果diff被截断且缺失了关键信息，无法判断，则返回 NEED_MORE_INFO

请仔细分析代码变化，给出准确的JSON响应。"""


# 用于混合分析的 Prompt（当有工具分析结果时使用）
HYBRID_TRACKING_SYSTEM_PROMPT = """你是一个专业的代码安全分析专家，专门追踪漏洞代码的引入历史。

## 你的角色
我们使用了代码分析工具（AST 和/或 srcml）对代码变更进行了初步分析。
**重要：工具结果仅供参考，可能存在误差，你必须独立分析代码并做出判断。**

## 变更类型判断
1. INTRODUCED - 这个提交首次引入了漏洞代码（这就是我们要找的BIC）
2. MODIFIED - 漏洞代码在此之前就存在，这个提交只是修改/移动/重命名了代码
3. UNRELATED - 这行代码的改动与漏洞无关（如纯注释、格式化）
4. NEED_MORE_INFO - 信息不足以做出判断

## 关于工具结果（重要警告）
- **AST 工具**：对 Java 较准确，但在代码重构时可能出错
- **srcml 工具**：当前实现基于简单文本匹配，**准确率有限，仅供参考**
- **置信度 < 0.5 的结果应当忽略或高度怀疑**
- 工具可能给出错误的行号映射，**请务必通过阅读 diff 自行验证**
- 如果工具说是 "Insert" 但 diff 显示代码是从其他地方移动来的，工具就是错的
- 如果工具给的原始行号在 diff 中看起来不合理，请忽略工具结果

## 你的判断原则
1. **首先阅读 diff，理解代码变化的实际含义**
2. 然后参考工具结果（如果置信度足够高）
3. 如果工具结果与你的理解冲突，**以你的判断为准**
4. 最终决策必须基于代码语义，而不是盲目相信工具

请仔细分析 diff，给出准确的JSON响应。"""


HYBRID_TRACKING_USER_PROMPT_TEMPLATE = """## 漏洞修复信息

**修复提交**: {fix_commit_hash}
**修复消息**: {fix_commit_message}
**漏洞类型**: {vulnerability_type}

**修复的代码变化**:
```diff
{fix_diff}
```

## 当前追踪点

**文件**: {current_file}
**行号**: {current_line}
**漏洞代码**:
```
{vulnerable_code}
```

## Blame 结果（需要分析的提交）

**提交哈希**: {blame_commit_hash}
**提交日期**: {blame_commit_date}  
**提交消息**: {blame_commit_message}
**作者**: {blame_author}

## 工具分析结果

{tool_analysis_summary}

## 该提交对此文件的改动
```diff
{blame_diff}
```

## 请分析

1. 工具的分析结果是否可信？
2. 结合漏洞语义，这个提交实际做了什么？
3. 如果是 MODIFIED，漏洞代码在这个提交之前位于哪一行？

请返回JSON格式：
```json
{{
    "tool_assessment": {{
        "trust_tool": true或false,
        "tool_issues": "如果不信任工具，说明原因"
    }},
    "change_type": "INTRODUCED 或 MODIFIED 或 UNRELATED 或 NEED_MORE_INFO",
    "reasoning": "你的分析推理过程",
    "continue_tracking": {{
        "should_continue": true或false,
        "target_line": 行号或null（优先使用工具给出的source_line，如果工具可信的话）,
        "target_file": "文件路径或null",
        "confidence": 0.0到1.0
    }},
    "need_more_info": {{
        "reason": "如果是NEED_MORE_INFO，说明需要什么信息",
        "suggested_context": "建议获取的额外上下文类型：full_diff / surrounding_code / file_history"
    }}
}}
```"""


TRACKING_USER_PROMPT_TEMPLATE = """## 漏洞修复信息

**修复提交**: {fix_commit_hash}
**修复消息**: {fix_commit_message}
**漏洞类型**: {vulnerability_type}

**修复的代码变化**:
```diff
{fix_diff}
```

## 当前追踪点

**文件**: {current_file}
**行号**: {current_line}
**漏洞代码**:
```
{vulnerable_code}
```

## Blame 结果（需要分析的提交）

**提交哈希**: {blame_commit_hash}
**提交日期**: {blame_commit_date}  
**提交消息**: {blame_commit_message}
**作者**: {blame_author}

**该提交对此文件的改动**:
```diff
{blame_diff}
```

## 请分析

1. 这个提交对漏洞代码做了什么？
2. 如果是 MODIFIED，漏洞代码在这个提交之前位于哪一行？

请返回JSON格式：
```json
{{
    "change_type": "INTRODUCED 或 MODIFIED 或 UNRELATED 或 NEED_MORE_INFO",
    "reasoning": "你的分析推理过程",
    "continue_tracking": {{
        "should_continue": true或false,
        "target_line": 行号或null,
        "target_file": "文件路径或null",
        "confidence": 0.0到1.0
    }},
    "need_more_info": {{
        "reason": "如果是NEED_MORE_INFO，说明需要什么信息",
        "suggested_context": "建议获取的额外上下文类型：full_diff / surrounding_code / file_history"
    }}
}}
```"""


VERIFICATION_SYSTEM_PROMPT = """你是一个代码安全审计专家，负责验证漏洞引入提交（BIC）的识别结果是否正确。

验证标准：
1. BIC 提交必须是首次引入漏洞代码/逻辑的提交
2. 如果漏洞逻辑在 BIC 之前就存在，则识别错误
3. 检查追踪链是否合理，有没有遗漏的步骤

请仔细验证，给出你的判断。"""


VERIFICATION_USER_PROMPT_TEMPLATE = """## 漏洞修复信息

**修复提交**: {fix_commit_hash}
**修复消息**: {fix_commit_message}
**漏洞类型**: {vulnerability_type}

**修复的代码变化**:
```diff
{fix_diff}
```

## 识别出的漏洞引入提交 (BIC)

**BIC哈希**: {bic_commit_hash}
**BIC日期**: {bic_commit_date}
**BIC消息**: {bic_commit_message}
**BIC作者**: {bic_author}

**BIC引入的代码**:
```diff
{bic_diff}
```

## 追踪链

从修复提交到BIC的完整追踪过程：
{tracking_chain_str}

## 请验证

1. 这个 BIC 是否真的是首次引入漏洞的提交？
2. 追踪链是否合理？有没有可能漏掉了真正的引入点？

请返回JSON格式：
```json
{{
    "verdict": "ACCEPT 或 REJECT",
    "confidence": 0.0到1.0,
    "reasoning": "验证的推理过程",
    "rejection_reason": "如果REJECT，说明原因",
    "suggestion": "如果REJECT，给出建议（如应该继续追踪到哪里）"
}}
```"""


# ============================================================================
# 数据结构
# ============================================================================

@dataclass
class TrackingStep:
    """追踪链中的一步"""
    commit_hash: str
    commit_date: str
    commit_message: str
    author: str
    file_path: str
    line_num: int
    code_snippet: str
    change_type: str  # INTRODUCED / MODIFIED / UNRELATED
    reasoning: str
    confidence: float


@dataclass 
class TrackingResult:
    """追踪结果"""
    fix_commit: str
    bic_commit: str
    tracking_chain: List[TrackingStep]
    verified: bool
    verification_result: Optional[Dict]
    iterations: int


# ============================================================================
# LLM 增强版 V-SZZ
# ============================================================================

class LLMEnhancedVSZZ(AbstractSZZ):
    """
    LLM 增强版 V-SZZ（混合架构）
    
    混合分析策略：
    1. 对Java文件：先用AST工具分析，然后把结果给大LLM验证/增强
    2. 对C/C++文件：先用srcml工具分析，然后把结果给大LLM验证/增强
    3. 其他语言：直接使用大LLM分析
    4. 最终：用小LLM验证追踪结果
    
    这种混合架构的优势：
    - 工具分析快速、准确（对于支持的语言）
    - LLM提供语义理解，弥补工具的不足
    - 节省API调用成本（工具结果可以减少LLM的推理工作）
    """
    
    def __init__(self, 
                 repo_full_name: str,
                 repo_url: str = None,
                 repos_dir: str = None,
                 large_llm: CachedLLMClient = None,
                 small_llm: CachedLLMClient = None,
                 max_tracking_depth: int = 30,
                 max_iterations: int = 3,
                 ast_map_path: str = None,
                 use_hybrid: bool = True):
        """
        初始化
        
        Args:
            repo_full_name: 仓库名称
            repo_url: 仓库URL
            repos_dir: 仓库目录
            large_llm: 大LLM客户端（用于追踪决策）
            small_llm: 小LLM客户端（用于验证）
            max_tracking_depth: 最大追踪深度
            max_iterations: 验证失败后最大重试次数
            ast_map_path: AST工具路径（ASTMapEval.jar所在目录）
            use_hybrid: 是否使用混合分析（True=工具+LLM，False=纯LLM）
        """
        super().__init__(repo_full_name, repo_url, repos_dir, use_temp_dir=False)
        
        self.large_llm = large_llm
        self.small_llm = small_llm
        self.max_tracking_depth = max_tracking_depth
        self.max_iterations = max_iterations
        self.use_hybrid = use_hybrid
        
        # 初始化代码分析器工厂
        if use_hybrid:
            # 如果未指定ast_map_path，尝试使用默认路径
            if ast_map_path is None:
                ast_map_path = os.path.join(os.path.dirname(__file__), 'ASTMapEval_jar')
            
            # 获取仓库实际路径
            if repos_dir:
                repo_path = os.path.join(repos_dir, repo_full_name)
            else:
                repo_path = None
            
            self.code_analyzer = CodeAnalyzerFactory(
                repo_path=repo_path,
                repo_name=repo_full_name,
                ast_map_path=ast_map_path
            )
            
            # 打印工具状态
            status = self.code_analyzer.get_status()
            print(f"\n🔧 代码分析工具状态:")
            print(f"   AST (Java): {'✅ 可用' if status['ast']['available'] else '❌ 不可用'}")
            print(f"   srcml (C/C++): {'✅ 可用' if status['srcml']['available'] else '❌ 不可用'}")
        else:
            self.code_analyzer = None
            print(f"\n🤖 使用纯LLM模式")
        
        # 漏洞信息缓存（在分析过程中填充）
        self._fix_commit_info = None
        self._vulnerability_type = None
    
    def find_bic(self, fix_commit_hash: str, 
                 impacted_files: List['ImpactedFile'],
                 **kwargs) -> List[TrackingResult]:
        """
        查找漏洞引入提交
        
        Args:
            fix_commit_hash: 修复提交哈希
            impacted_files: 受影响的文件列表
            
        Returns:
            追踪结果列表
        """
        # 获取修复提交信息
        self._fix_commit_info = self._get_commit_info(fix_commit_hash)
        self._vulnerability_type = self._infer_vulnerability_type(
            self._fix_commit_info['message']
        )
        
        results = []
        
        for imp_file in impacted_files:
            print(f"\n📁 追踪文件: {imp_file.file_path}")
            
            for line_num in imp_file.modified_lines:
                print(f"  📍 追踪第 {line_num} 行...")
                
                result = self._track_line_with_feedback(
                    fix_commit_hash=fix_commit_hash,
                    file_path=imp_file.file_path,
                    line_num=line_num
                )
                
                if result:
                    results.append(result)
        
        return results
    
    def _track_line_with_feedback(self, fix_commit_hash: str,
                                   file_path: str, 
                                   line_num: int) -> Optional[TrackingResult]:
        """
        带反馈循环的行追踪
        
        Args:
            fix_commit_hash: 修复提交
            file_path: 文件路径
            line_num: 行号
            
        Returns:
            追踪结果
        """
        feedback = None
        
        for iteration in range(self.max_iterations):
            print(f"    🔄 迭代 {iteration + 1}/{self.max_iterations}")
            
            # 阶段1: 大LLM辅助追踪
            tracking_chain = self._track_line(
                fix_commit_hash=fix_commit_hash,
                file_path=file_path,
                line_num=line_num,
                feedback=feedback
            )
            
            if not tracking_chain:
                print(f"    ❌ 追踪失败")
                return None
            
            # 找到BIC（追踪链最后一个INTRODUCED类型的步骤）
            bic_step = None
            for step in reversed(tracking_chain):
                if step.change_type == "INTRODUCED":
                    bic_step = step
                    break
            
            if not bic_step:
                print(f"    ⚠️ 未找到引入点")
                return None
            
            print(f"    🎯 候选BIC: {bic_step.commit_hash[:8]}")
            
            # 阶段2: 小LLM验证
            if self.small_llm:
                verification = self._verify_bic(
                    fix_commit_hash=fix_commit_hash,
                    bic_step=bic_step,
                    tracking_chain=tracking_chain
                )
                
                if verification['verdict'] == 'ACCEPT':
                    print(f"    ✅ 验证通过 (置信度: {verification['confidence']:.2f})")
                    return TrackingResult(
                        fix_commit=fix_commit_hash,
                        bic_commit=bic_step.commit_hash,
                        tracking_chain=tracking_chain,
                        verified=True,
                        verification_result=verification,
                        iterations=iteration + 1
                    )
                else:
                    print(f"    ❌ 验证拒绝: {verification.get('rejection_reason', 'Unknown')}")
                    # 记录反馈，供下次迭代使用
                    feedback = {
                        'rejected_bic': bic_step.commit_hash,
                        'reason': verification.get('rejection_reason'),
                        'suggestion': verification.get('suggestion')
                    }
            else:
                # 没有小LLM，直接返回结果
                return TrackingResult(
                    fix_commit=fix_commit_hash,
                    bic_commit=bic_step.commit_hash,
                    tracking_chain=tracking_chain,
                    verified=False,
                    verification_result=None,
                    iterations=iteration + 1
                )
        
        # 达到最大迭代次数，返回最后的结果
        print(f"    ⚠️ 达到最大迭代次数")
        return TrackingResult(
            fix_commit=fix_commit_hash,
            bic_commit=bic_step.commit_hash if bic_step else None,
            tracking_chain=tracking_chain,
            verified=False,
            verification_result=None,
            iterations=self.max_iterations
        )
    
    def _track_line(self, fix_commit_hash: str, file_path: str, 
                    line_num: int, feedback: Dict = None) -> List[TrackingStep]:
        """
        追踪单行代码的引入历史
        
        Args:
            fix_commit_hash: 修复提交
            file_path: 文件路径
            line_num: 行号
            feedback: 上一次迭代的反馈
            
        Returns:
            追踪链
        """
        tracking_chain = []
        current_file = file_path
        current_line = line_num
        current_commit = fix_commit_hash
        
        # 需要跳过的提交（来自反馈）
        skip_commits = set()
        if feedback and feedback.get('rejected_bic'):
            skip_commits.add(feedback['rejected_bic'])
        
        for depth in range(self.max_tracking_depth):
            # Step 1: Git blame 获取上一个修改这行的提交
            try:
                blame_data = self._blame(
                    rev=f'{current_commit}^',
                    file_path=current_file,
                    modified_lines=[current_line],
                    ignore_revs_file_path=None,
                    ignore_whitespaces=False,
                    skip_comments=False
                )
                blame_entry = list(blame_data)[0]
            except Exception as e:
                print(f"      Blame失败: {e}")
                break
            
            blame_commit = blame_entry.commit.hexsha
            
            # 检查是否需要跳过
            if blame_commit in skip_commits:
                print(f"      跳过被拒绝的提交: {blame_commit[:8]}")
                current_commit = blame_commit
                continue
            
            # Step 2: 大LLM 分析这个提交
            analysis = self._analyze_commit_with_llm(
                blame_entry=blame_entry,
                current_file=current_file,
                current_line=current_line,
                feedback=feedback
            )
            
            # 记录追踪步骤
            step = TrackingStep(
                commit_hash=blame_commit,
                commit_date=str(blame_entry.commit.committed_datetime),
                commit_message=blame_entry.commit.message.strip()[:200],
                author=blame_entry.commit.author.name,
                file_path=current_file,
                line_num=current_line,
                code_snippet=blame_entry.line_str[:200] if blame_entry.line_str else "",
                change_type=analysis['change_type'],
                reasoning=analysis['reasoning'],
                confidence=analysis['continue_tracking']['confidence']
            )
            tracking_chain.append(step)
            
            print(f"      [{depth+1}] {blame_commit[:8]} - {analysis['change_type']}")
            
            # Step 3: 根据分析结果决定是否继续
            if analysis['change_type'] == 'INTRODUCED':
                # 找到引入点，停止
                break
            elif analysis['change_type'] == 'MODIFIED':
                # 继续追踪
                if analysis['continue_tracking']['should_continue']:
                    current_commit = blame_commit
                    current_line = analysis['continue_tracking']['target_line'] or current_line
                    current_file = analysis['continue_tracking']['target_file'] or current_file
                else:
                    break
            elif analysis['change_type'] == 'UNRELATED':
                # 跳过无关提交，继续blame
                current_commit = blame_commit
        
        return tracking_chain
    
    def _analyze_commit_with_llm(self, blame_entry, current_file: str,
                                  current_line: int, 
                                  feedback: Dict = None,
                                  context_level: int = 1) -> Dict:
        """
        分析blame返回的提交
        
        核心原则：LLM 永远是最终决策者，工具只是提供辅助信息
        
        流程：
        1. 调用代码分析工具（Java: AST+srcml，非Java: srcml）
        2. 把所有工具结果传给大LLM
        3. LLM 综合分析后做出最终判断
        
        Args:
            blame_entry: blame结果条目
            current_file: 当前文件路径
            current_line: 当前行号
            feedback: 反馈信息
            context_level: 上下文级别 (1=基础, 2=扩展, 3=完整)
            
        Returns:
            分析结果
        """
        blame_commit = blame_entry.commit
        
        # 获取工具分析结果（CombinedToolResult）
        combined_result = None
        if self.use_hybrid and self.code_analyzer:
            combined_result = self.code_analyzer.analyze(
                commit_hash=blame_commit.hexsha,
                file_path=current_file,
                line_num=current_line,
                repo=self.repository
            )
            
            # 打印工具分析结果
            self._print_tool_results(combined_result)
        
        if not self.large_llm:
            # 没有LLM，使用工具结果或简单规则
            if combined_result and combined_result.has_any_result():
                return self._convert_combined_result_to_analysis(combined_result)
            return self._rule_based_analysis(blame_entry)
        
        # 获取blame提交的diff（使用智能截断）
        blame_diff, is_truncated = self._get_commit_diff(
            blame_commit.hexsha, current_file, current_line, context_level
        )
        
        # 构建工具分析摘要（给LLM看）
        tool_analysis_summary = self._format_tool_results_for_llm(combined_result)
        
        # 根据是否有工具结果选择不同的prompt
        if combined_result and combined_result.has_any_result():
            # 混合分析模式：把工具结果给LLM
            prompt = HYBRID_TRACKING_USER_PROMPT_TEMPLATE.format(
                fix_commit_hash=self._fix_commit_info['hash'][:12],
                fix_commit_message=self._fix_commit_info['message'][:500],
                vulnerability_type=self._vulnerability_type,
                fix_diff=self._fix_commit_info['diff'][:2000],
                current_file=current_file,
                current_line=current_line,
                vulnerable_code=blame_entry.line_str[:300] if blame_entry.line_str else "[无法获取]",
                blame_commit_hash=blame_commit.hexsha[:12],
                blame_commit_date=str(blame_commit.committed_datetime),
                blame_commit_message=blame_commit.message.strip()[:500],
                blame_author=blame_commit.author.name,
                tool_analysis_summary=tool_analysis_summary,
                blame_diff=blame_diff
            )
            system_prompt = HYBRID_TRACKING_SYSTEM_PROMPT
        else:
            # 纯LLM分析模式
            prompt = TRACKING_USER_PROMPT_TEMPLATE.format(
                fix_commit_hash=self._fix_commit_info['hash'][:12],
                fix_commit_message=self._fix_commit_info['message'][:500],
                vulnerability_type=self._vulnerability_type,
                fix_diff=self._fix_commit_info['diff'][:2000],
                current_file=current_file,
                current_line=current_line,
                vulnerable_code=blame_entry.line_str[:300] if blame_entry.line_str else "[无法获取]",
                blame_commit_hash=blame_commit.hexsha[:12],
                blame_commit_date=str(blame_commit.committed_datetime),
                blame_commit_message=blame_commit.message.strip()[:500],
                blame_author=blame_commit.author.name,
                blame_diff=blame_diff
            )
            system_prompt = TRACKING_SYSTEM_PROMPT
        
        # 如果diff被截断，在prompt中说明
        if is_truncated:
            prompt += f"\n\n## 注意\n"
            prompt += f"上述diff已被截断（当前上下文级别: {context_level}/3）。"
            prompt += f"如果缺少关键信息无法判断，请返回 NEED_MORE_INFO。"
        
        # 如果有反馈，添加到prompt
        if feedback:
            prompt += f"\n\n## 重要提示\n"
            prompt += f"之前的分析结果被拒绝了。\n"
            prompt += f"被拒绝的BIC: {feedback.get('rejected_bic', 'Unknown')[:12]}\n"
            prompt += f"拒绝原因: {feedback.get('reason', 'Unknown')}\n"
            prompt += f"建议: {feedback.get('suggestion', '无')}\n"
            prompt += f"请重新分析，避免相同的错误。"
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ]
        
        try:
            response = self.large_llm.chat(messages, temperature=0.1)
            result = self._parse_json_response(response)
            
            # 处理 NEED_MORE_INFO 情况
            if result.get('change_type') == 'NEED_MORE_INFO' and context_level < 3:
                print(f"      📋 LLM请求更多上下文 (级别 {context_level} → {context_level+1})")
                
                # 获取LLM请求的额外上下文
                need_info = result.get('need_more_info', {})
                suggested_context = need_info.get('suggested_context', 'full_diff')
                
                # 添加额外上下文
                extra_context = self._get_extended_context(
                    blame_commit.hexsha, current_file, current_line, suggested_context
                )
                
                # 递归调用，提升上下文级别
                return self._analyze_commit_with_llm(
                    blame_entry, current_file, current_line,
                    feedback, context_level + 1
                )
            
            # 如果工具提供了source_line，可以用于辅助判断
            if (combined_result and combined_result.has_any_result()):
                best_source_line = combined_result.get_best_source_line()
                if best_source_line and 'continue_tracking' in result:
                    if result['continue_tracking'].get('target_line') is None:
                        result['continue_tracking']['target_line'] = best_source_line
            
            return result
            
        except Exception as e:
            print(f"      LLM调用失败: {e}")
            # 如果LLM失败但工具成功，使用工具结果
            if combined_result and combined_result.has_any_result():
                return self._convert_combined_result_to_analysis(combined_result)
            return self._rule_based_analysis(blame_entry)
    
    def _print_tool_results(self, combined_result: CombinedToolResult):
        """打印工具分析结果"""
        if combined_result.ast_result:
            r = combined_result.ast_result
            status = "✅" if r.success else "❌"
            print(f"      🔧 AST: {status} {r.change_type} (行: {r.source_line}, 置信度: {r.confidence:.2f})")
        
        if combined_result.srcml_result:
            r = combined_result.srcml_result
            status = "✅" if r.success else "❌"
            print(f"      🔧 srcml: {status} {r.change_type} (行: {r.source_line}, 置信度: {r.confidence:.2f})")
        
        if combined_result.ast_result and combined_result.srcml_result:
            if combined_result.tools_agree():
                print(f"      ✓ 两个工具结果一致")
            else:
                print(f"      ⚠ 两个工具结果不一致")
    
    def _format_tool_results_for_llm(self, combined_result: Optional[CombinedToolResult]) -> str:
        """格式化工具结果，用于传给LLM（带置信度警告）"""
        if not combined_result:
            return "无工具分析结果（将完全依赖你的判断）"
        
        lines = []
        tools_used = []
        has_reliable_result = False  # 是否有可靠结果
        
        # 置信度阈值
        CONFIDENCE_THRESHOLD = 0.5
        
        if combined_result.ast_result:
            r = combined_result.ast_result
            tools_used.append("AST")
            lines.append("### AST 工具分析 (Java 语法树分析)")
            lines.append(f"- 分析状态: {'成功' if r.success else '失败'}")
            if r.success:
                lines.append(f"- 变更类型: {r.change_type}")
                lines.append(f"- 原始行号: {r.source_line}")
                lines.append(f"- 置信度: {r.confidence:.2f}")
                if r.confidence >= CONFIDENCE_THRESHOLD:
                    has_reliable_result = True
                else:
                    lines.append(f"- ⚠️ **警告: 置信度较低，结果可能不可靠**")
            if r.error_message:
                lines.append(f"- 错误信息: {r.error_message}")
            # 添加原始输出中的警告
            if r.raw_output and r.raw_output.get('warning'):
                lines.append(f"- ⚠️ {r.raw_output['warning']}")
            lines.append("")
        
        if combined_result.srcml_result:
            r = combined_result.srcml_result
            tools_used.append("srcml")
            lines.append("### srcml 工具分析 (基于文本匹配，准确率有限)")
            lines.append(f"- 分析状态: {'成功' if r.success else '失败'}")
            if r.success:
                lines.append(f"- 变更类型: {r.change_type}")
                lines.append(f"- 原始行号: {r.source_line}")
                lines.append(f"- 置信度: {r.confidence:.2f}")
                if r.confidence < CONFIDENCE_THRESHOLD:
                    lines.append(f"- ⚠️ **警告: 置信度很低，此结果仅供参考，请勿依赖**")
                elif r.confidence < 0.7:
                    lines.append(f"- ⚠️ **注意: 置信度一般，建议通过diff验证**")
            if r.error_message:
                lines.append(f"- 错误信息: {r.error_message}")
            # 添加原始输出中的警告
            if r.raw_output and r.raw_output.get('warning'):
                lines.append(f"- ⚠️ {r.raw_output['warning']}")
            lines.append("")
        
        # 综合信息
        lines.append("### 工具分析综合")
        lines.append(f"- 使用的工具: {', '.join(tools_used) if tools_used else '无'}")
        
        if not has_reliable_result:
            lines.append("- ⚠️ **所有工具结果置信度都较低，请完全依赖你对diff的分析**")
        elif combined_result.tools_agree():
            lines.append("- 工具结果: **一致** ✓ (可作为参考)")
        elif combined_result.ast_result and combined_result.srcml_result:
            lines.append("- 工具结果: **不一致** ⚠ (请忽略工具结果，根据代码语义判断)")
        
        best_line = combined_result.get_best_source_line()
        if best_line and has_reliable_result:
            lines.append(f"- 建议追踪的原始行号: {best_line} (仅供参考)")
        else:
            lines.append(f"- 建议追踪的原始行号: 请根据diff自行判断")
        
        return "\n".join(lines)
    
    def _convert_combined_result_to_analysis(self, combined_result: CombinedToolResult) -> Dict:
        """
        将综合工具结果转换为分析结果格式
        
        当LLM不可用时，直接使用工具结果
        """
        # 优先使用 AST 结果（对 Java 更准确）
        tool_result = combined_result.ast_result if combined_result.ast_result and combined_result.ast_result.success else combined_result.srcml_result
        
        if not tool_result or not tool_result.success:
            return self._rule_based_analysis(None)
        
        # 工具变更类型到LLM变更类型的映射
        change_type_map = {
            'Insert': 'INTRODUCED',
            'Delete': 'MODIFIED',
            'Update': 'MODIFIED',
            'Move': 'MODIFIED',
            'Unchanged': 'UNRELATED',
            'Unknown': 'MODIFIED'
        }
        
        change_type = change_type_map.get(tool_result.change_type, 'MODIFIED')
        source_line = combined_result.get_best_source_line()
        
        # 判断是否继续追踪
        should_continue = (change_type == 'MODIFIED' and source_line is not None)
        
        return {
            'change_type': change_type,
            'reasoning': f"基于工具分析: AST={combined_result.ast_result.change_type if combined_result.ast_result else 'N/A'}, srcml={combined_result.srcml_result.change_type if combined_result.srcml_result else 'N/A'}",
            'continue_tracking': {
                'should_continue': should_continue,
                'target_line': source_line,
                'target_file': None,
                'confidence': tool_result.confidence
            }
        }
    
    def _verify_bic(self, fix_commit_hash: str, bic_step: TrackingStep,
                    tracking_chain: List[TrackingStep]) -> Dict:
        """
        用小LLM验证BIC结果
        
        Args:
            fix_commit_hash: 修复提交
            bic_step: BIC步骤
            tracking_chain: 追踪链
            
        Returns:
            验证结果
        """
        # 构建追踪链字符串
        chain_str = ""
        for i, step in enumerate(tracking_chain, 1):
            chain_str += f"{i}. [{step.change_type}] {step.commit_hash[:8]} "
            chain_str += f"({step.commit_date[:10]}) - {step.commit_message[:100]}\n"
            chain_str += f"   文件: {step.file_path}, 行: {step.line_num}\n"
            chain_str += f"   代码: {step.code_snippet[:100]}\n"
            chain_str += f"   推理: {step.reasoning[:200]}\n\n"
        
        # 获取BIC的diff（验证时使用更大的上下文）
        bic_diff, _ = self._get_commit_diff(bic_step.commit_hash, bic_step.file_path,
                                            bic_step.line_num, context_level=2)
        
        prompt = VERIFICATION_USER_PROMPT_TEMPLATE.format(
            fix_commit_hash=self._fix_commit_info['hash'][:12],
            fix_commit_message=self._fix_commit_info['message'][:500],
            vulnerability_type=self._vulnerability_type,
            fix_diff=self._fix_commit_info['diff'][:2000],
            bic_commit_hash=bic_step.commit_hash[:12],
            bic_commit_date=bic_step.commit_date,
            bic_commit_message=bic_step.commit_message[:500],
            bic_author=bic_step.author,
            bic_diff=bic_diff,
            tracking_chain_str=chain_str
        )
        
        messages = [
            {"role": "system", "content": VERIFICATION_SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ]
        
        try:
            response = self.small_llm.chat(messages, temperature=0.1)
            return self._parse_json_response(response)
        except Exception as e:
            print(f"      验证LLM调用失败: {e}")
            return {"verdict": "ACCEPT", "confidence": 0.5, 
                    "reasoning": "验证失败，默认接受"}
    
    def _rule_based_analysis(self, blame_entry) -> Dict:
        """
        基于规则的分析（当LLM不可用时的后备方案）
        """
        return {
            "change_type": "MODIFIED",
            "reasoning": "基于规则的默认判断",
            "continue_tracking": {
                "should_continue": True,
                "target_line": blame_entry.line_num,
                "target_file": None,
                "confidence": 0.5
            }
        }
    
    def _get_commit_info(self, commit_hash: str) -> Dict:
        """获取提交信息"""
        commit = self.repository.commit(commit_hash)
        
        # 获取diff
        diff_text = ""
        if commit.parents:
            diffs = commit.diff(commit.parents[0], create_patch=True)
            for d in diffs[:5]:  # 最多5个文件
                if d.diff:
                    try:
                        diff_text += d.diff.decode('utf-8', errors='ignore')[:1000]
                        diff_text += "\n\n"
                    except:
                        pass
        
        return {
            'hash': commit.hexsha,
            'message': commit.message.strip(),
            'author': commit.author.name,
            'date': str(commit.committed_datetime),
            'diff': diff_text
        }
    
    def _get_commit_diff(self, commit_hash: str, file_path: str = None,
                         target_line: int = None, context_level: int = 1) -> Tuple[str, bool]:
        """
        智能获取提交的diff
        
        Args:
            commit_hash: 提交哈希
            file_path: 指定文件路径
            target_line: 目标行号（用于智能截断时优先保留该行附近内容）
            context_level: 上下文级别 (1=基础, 2=扩展, 3=完整)
            
        Returns:
            (diff_text, is_truncated) - diff文本和是否被截断的标志
        """
        try:
            commit = self.repository.commit(commit_hash)
            if not commit.parents:
                return "[初始提交]", False
            
            diffs = commit.diff(commit.parents[0], create_patch=True)
            
            # 根据context_level确定最大长度
            max_lengths = {1: 3000, 2: 8000, 3: 15000}
            max_length = max_lengths.get(context_level, 3000)
            
            diff_text = ""
            is_truncated = False
            target_file_diff = None
            
            for d in diffs:
                # 如果指定了文件，优先处理该文件
                if file_path and (d.a_path == file_path or d.b_path == file_path):
                    if d.diff:
                        try:
                            target_file_diff = d.diff.decode('utf-8', errors='ignore')
                        except:
                            pass
                    continue
                
                if d.diff:
                    try:
                        diff_text += d.diff.decode('utf-8', errors='ignore')
                        diff_text += "\n\n"
                    except:
                        pass
            
            # 目标文件的diff优先放在前面
            if target_file_diff:
                # 如果有目标行，智能截断保留该行附近
                if target_line and len(target_file_diff) > max_length:
                    target_file_diff = self._smart_truncate_diff(
                        target_file_diff, target_line, max_length
                    )
                    is_truncated = True
                diff_text = target_file_diff + "\n\n" + diff_text
            
            # 整体长度限制
            if len(diff_text) > max_length:
                diff_text = diff_text[:max_length]
                is_truncated = True
            
            if is_truncated:
                diff_text += "\n\n[... DIFF已截断，如需更多上下文请指定 ...]"
            
            return (diff_text if diff_text else "[无diff]"), is_truncated
        except Exception as e:
            return f"[获取diff失败: {e}]", False
    
    def _smart_truncate_diff(self, diff_text: str, target_line: int, 
                             max_length: int) -> str:
        """
        智能截断diff，优先保留目标行附近的内容
        
        Args:
            diff_text: 完整diff文本
            target_line: 目标行号
            max_length: 最大长度
            
        Returns:
            截断后的diff
        """
        lines = diff_text.split('\n')
        
        # 找到包含目标行的hunk
        target_hunk_start = 0
        target_hunk_end = len(lines)
        in_target_hunk = False
        
        for i, line in enumerate(lines):
            # 检测hunk头 @@ -old_start,old_count +new_start,new_count @@
            if line.startswith('@@'):
                match = re.search(r'@@ -(\d+)', line)
                if match:
                    hunk_start_line = int(match.group(1))
                    # 简单估算：如果目标行在这个hunk范围内
                    if hunk_start_line <= target_line <= hunk_start_line + 100:
                        target_hunk_start = i
                        in_target_hunk = True
                    elif in_target_hunk:
                        target_hunk_end = i
                        break
        
        # 提取目标hunk及其上下文
        # 保留文件头（前几行）
        header_end = 0
        for i, line in enumerate(lines[:10]):
            if line.startswith('@@'):
                header_end = i
                break
        
        header = '\n'.join(lines[:header_end])
        target_hunk = '\n'.join(lines[target_hunk_start:target_hunk_end])
        
        result = header + '\n' + target_hunk
        
        # 如果还有空间，添加其他hunk的摘要
        if len(result) < max_length - 200:
            result += f"\n\n[其他改动已省略，共 {len(lines) - (target_hunk_end - target_hunk_start)} 行]"
        
        return result[:max_length]
    
    def _get_extended_context(self, commit_hash: str, file_path: str,
                              target_line: int, context_type: str) -> str:
        """
        获取扩展上下文（当LLM返回NEED_MORE_INFO时调用）
        
        Args:
            commit_hash: 提交哈希
            file_path: 文件路径
            target_line: 目标行号
            context_type: 上下文类型 (full_diff / surrounding_code / file_history)
            
        Returns:
            扩展上下文信息
        """
        if context_type == 'full_diff':
            # 返回完整diff（更大的长度限制）
            diff, _ = self._get_commit_diff(commit_hash, file_path, target_line, 
                                            context_level=3)
            return diff
        
        elif context_type == 'surrounding_code':
            # 获取目标行周围的代码（修改前后的完整函数）
            try:
                commit = self.repository.commit(commit_hash)
                # 获取修改前的文件内容
                if commit.parents:
                    parent = commit.parents[0]
                    try:
                        blob = parent.tree / file_path
                        content = blob.data_stream.read().decode('utf-8', errors='ignore')
                        lines = content.split('\n')
                        
                        # 提取目标行周围50行
                        start = max(0, target_line - 25)
                        end = min(len(lines), target_line + 25)
                        
                        surrounding = '\n'.join(
                            f"{i+1}: {line}" 
                            for i, line in enumerate(lines[start:end], start=start)
                        )
                        return f"文件 {file_path} 第{start+1}-{end}行:\n```\n{surrounding}\n```"
                    except:
                        pass
                return "[无法获取surrounding_code]"
            except Exception as e:
                return f"[获取surrounding_code失败: {e}]"
        
        elif context_type == 'file_history':
            # 获取文件的最近提交历史
            try:
                commits = list(self.repository.iter_commits(
                    paths=file_path, max_count=10
                ))
                history = "文件最近10次修改:\n"
                for c in commits:
                    history += f"- {c.hexsha[:8]} ({c.committed_datetime.date()}): "
                    history += f"{c.message.strip()[:60]}\n"
                return history
            except Exception as e:
                return f"[获取file_history失败: {e}]"
        
        return "[未知的context_type]"
    
    def _infer_vulnerability_type(self, message: str) -> str:
        """从commit message推断漏洞类型"""
        message_lower = message.lower()
        
        type_keywords = {
            'SQL Injection': ['sql injection', 'sqli'],
            'XSS': ['xss', 'cross-site scripting', 'cross site scripting'],
            'CSRF': ['csrf', 'cross-site request forgery'],
            'Command Injection': ['command injection', 'code injection', 'rce'],
            'Path Traversal': ['path traversal', 'directory traversal'],
            'Authentication Bypass': ['auth bypass', 'authentication'],
            'Authorization': ['authorization', 'privilege', 'access control'],
            'Buffer Overflow': ['buffer overflow', 'buffer overrun'],
            'DoS': ['dos', 'denial of service'],
            'Information Disclosure': ['information disclosure', 'info leak'],
            'XXE': ['xxe', 'xml external entity'],
            'Deserialization': ['deserialization'],
        }
        
        for vtype, keywords in type_keywords.items():
            if any(kw in message_lower for kw in keywords):
                return vtype
        
        # 尝试匹配CVE
        cve_match = re.search(r'CVE-\d{4}-\d+', message, re.IGNORECASE)
        if cve_match:
            return f"CVE ({cve_match.group(0)})"
        
        return "Unknown Security Issue"
    
    def _parse_json_response(self, response: str) -> Dict:
        """解析LLM的JSON响应"""
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            # 尝试提取JSON块
            json_match = re.search(r'```json\s*(\{.*?\})\s*```', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(1))
            
            # 尝试找到第一个{和最后一个}
            start = response.find('{')
            end = response.rfind('}')
            if start != -1 and end != -1:
                return json.loads(response[start:end+1])
            
            raise ValueError(f"无法解析JSON响应: {response[:200]}")


# ============================================================================
# 便捷函数
# ============================================================================

def create_llm_enhanced_vszz(repo_path: str,
                              large_model: str = "gpt-5.1-codex",
                              small_model: str = "gpt-5-mini",
                              api_key: str = None,
                              base_url: str = "https://yunwu.ai/v1",
                              enable_cache: bool = True,
                              use_hybrid: bool = True,
                              ast_map_path: str = None) -> LLMEnhancedVSZZ:
    """
    创建LLM增强版V-SZZ实例
    
    Args:
        repo_path: 仓库路径
        large_model: 大模型名称
        small_model: 小模型名称
        api_key: API密钥
        base_url: API基础URL
        enable_cache: 是否启用缓存
        use_hybrid: 是否使用混合模式（AST/srcml + LLM）
        ast_map_path: AST工具路径（ASTMapEval.jar所在目录）
        
    Returns:
        LLMEnhancedVSZZ 实例
    """
    from llm_client import OpenAIClient, CachedLLMClient
    
    # 创建大LLM
    large_client = OpenAIClient(api_key=api_key, model=large_model, base_url=base_url)
    large_llm = CachedLLMClient(large_client, enable_cache=enable_cache)
    
    # 创建小LLM
    small_client = OpenAIClient(api_key=api_key, model=small_model, base_url=base_url)
    small_llm = CachedLLMClient(small_client, enable_cache=enable_cache)
    
    repo_name = os.path.basename(repo_path)
    repos_dir = os.path.dirname(repo_path)
    
    return LLMEnhancedVSZZ(
        repo_full_name=repo_name,
        repo_url=None,
        repos_dir=repos_dir,
        large_llm=large_llm,
        small_llm=small_llm,
        use_hybrid=use_hybrid,
        ast_map_path=ast_map_path
    )


def analyze_fix_commit(repo_path: str, fix_commit_hash: str,
                       api_key: str = None,
                       large_model: str = "gpt-5.1-codex",
                       small_model: str = "gpt-5-mini",
                       use_hybrid: bool = True,
                       ast_map_path: str = None) -> List[TrackingResult]:
    """
    分析单个修复提交，找出漏洞引入提交
    
    Args:
        repo_path: 仓库路径
        fix_commit_hash: 修复提交哈希
        api_key: API密钥
        large_model: 大模型名称
        small_model: 小模型名称
        use_hybrid: 是否使用混合模式（默认True）
        ast_map_path: AST工具路径
        
    Returns:
        追踪结果列表
    """
    print(f"\n{'='*70}")
    print(f"🔍 LLM-Enhanced V-SZZ 分析")
    print(f"{'='*70}")
    print(f"仓库: {repo_path}")
    print(f"修复提交: {fix_commit_hash}")
    print(f"大模型: {large_model}")
    print(f"小模型: {small_model}")
    print(f"分析模式: {'混合模式 (AST/srcml + LLM)' if use_hybrid else '纯LLM模式'}")
    print()
    
    # 创建实例
    vszz = create_llm_enhanced_vszz(
        repo_path=repo_path,
        large_model=large_model,
        small_model=small_model,
        api_key=api_key,
        enable_cache=True,
        use_hybrid=use_hybrid,
        ast_map_path=ast_map_path
    )
    
    # 获取受影响的文件
    print("📂 获取受影响的文件...")
    impacted_files = vszz.get_impacted_files(
        fix_commit_hash=fix_commit_hash,
        file_ext_to_parse=['java', 'c', 'cpp', 'h', 'hpp', 'py', 'js', 'go', 'rs'],
        only_deleted_lines=True
    )
    
    print(f"   找到 {len(impacted_files)} 个受影响文件")
    for imp in impacted_files:
        print(f"   - {imp.file_path}: {len(imp.modified_lines)} 行")
    
    # 运行分析
    print("\n🚀 开始追踪...")
    results = vszz.find_bic(fix_commit_hash, impacted_files)
    
    # 输出结果
    print(f"\n{'='*70}")
    print(f"📊 分析结果")
    print(f"{'='*70}")
    
    for i, result in enumerate(results, 1):
        print(f"\n结果 {i}:")
        print(f"  修复提交: {result.fix_commit[:12]}")
        print(f"  BIC提交: {result.bic_commit[:12] if result.bic_commit else 'None'}")
        print(f"  验证状态: {'✅ 通过' if result.verified else '⚠️ 未验证'}")
        print(f"  迭代次数: {result.iterations}")
        print(f"  追踪链长度: {len(result.tracking_chain)}")
        
        if result.tracking_chain:
            print(f"  追踪链:")
            for j, step in enumerate(result.tracking_chain, 1):
                status = "🎯" if step.change_type == "INTRODUCED" else "➡️"
                print(f"    {j}. {status} {step.commit_hash[:8]} [{step.change_type}]")
                print(f"       {step.commit_message[:60]}...")
    
    # 打印LLM统计
    if vszz.large_llm:
        vszz.large_llm.print_stats()
    if vszz.small_llm:
        vszz.small_llm.print_stats()
    
    return results
