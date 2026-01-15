"""
LLM 主导的漏洞引入追踪 (LLM-Driven SZZ)

核心设计原则：
┌─────────────────────────────────────────────────────────────┐
│  LLM 是主导者，工具只是辅助                                    │
│  - LLM 决定是否继续追踪                                        │
│  - LLM 判断是否是真正的引入点                                   │
│  - 工具（git log/blame/diff）只提供信息给 LLM 分析              │
│  - AST 工具可选，用于减少 LLM 的代码阅读量                       │
└─────────────────────────────────────────────────────────────┘

工作流程：
1. 获取漏洞修复提交的信息
2. 用 git log --follow 获取相关文件的完整历史
3. LLM 逐个分析历史提交，决定是否继续追踪
4. LLM 确认找到真正的引入点时停止
5. 小模型验证大模型的判断
"""

import os
import sys
import subprocess
import json
from typing import List, Optional, Dict, Tuple
from git import Repo

# 添加路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))))

# LLM 客户端
_llm_client = None
_small_llm_client = None


def get_llm_client():
    """获取大模型 LLM 客户端"""
    global _llm_client
    if _llm_client is None:
        try:
            from llm_client import CachedLLMClient, OpenAIClient
            
            api_key = os.environ.get('OPENAI_API_KEY', 'sk-smMd7t4GCBkCgoPZkBTE7WzZeSSOAvSvTREm5jWOhSEpA3tw')
            base_url = os.environ.get('OPENAI_BASE_URL', 'https://yunwu.ai/v1')
            model = os.environ.get('LLM_MODEL', 'gpt-5.1-codex')
            
            client = OpenAIClient(api_key=api_key, model=model, base_url=base_url)
            _llm_client = CachedLLMClient(client, enable_cache=True)
            print(f"🤖 大模型已启用: {model}")
        except Exception as e:
            print(f"⚠️ LLM 初始化失败: {e}")
    return _llm_client


def get_small_llm_client():
    """获取小模型 LLM 客户端（用于验证）"""
    global _small_llm_client
    if _small_llm_client is None:
        try:
            from llm_client import CachedLLMClient, OpenAIClient
            
            api_key = os.environ.get('OPENAI_API_KEY', 'sk-smMd7t4GCBkCgoPZkBTE7WzZeSSOAvSvTREm5jWOhSEpA3tw')
            base_url = os.environ.get('OPENAI_BASE_URL', 'https://yunwu.ai/v1')
            model = os.environ.get('SMALL_LLM_MODEL', 'gpt-5-mini')
            
            client = OpenAIClient(api_key=api_key, model=model, base_url=base_url)
            _small_llm_client = CachedLLMClient(client, enable_cache=True)
            print(f"🔍 验证模型已启用: {model}")
        except Exception as e:
            print(f"⚠️ 小模型初始化失败: {e}")
    return _small_llm_client


# ============== LLM Prompts ==============

ANALYZE_COMMIT_PROMPT = """你是漏洞引入追踪专家。你的任务是分析代码提交历史，找到漏洞代码的**真正引入点**（Vulnerability Introducing Commit, VIC）。

**重要原则：真正的引入点是漏洞代码被"首次手工编写"的地方，不是"首次出现在这个文件"的地方。**

## 漏洞修复信息
- CVE/漏洞类型: {cve_info}
- 修复提交: {fix_commit_hash}
- 修复消息: {fix_commit_message}
- 被修复的漏洞代码: 
```
{vulnerable_code}
```

## 该文件的完整提交历史（从新到旧）
{file_history_summary}

## 当前分析的提交
- 提交哈希: {current_commit_hash}
- 提交日期: {current_commit_date}  
- 提交消息: {current_commit_message}
- 这是该文件历史中的第 {commit_index} 个提交（共 {total_commits} 个）
- **后面还有 {remaining_commits} 个更早的提交可以追踪**

## 该提交的代码变更
```diff
{commit_diff}
```

## 该提交之前的文件内容（父提交中的相关代码）
```
{parent_file_content}
```

## 关键判断标准

### 什么情况下 **不是** 真正引入点（需要继续追踪）：
1. **代码修改/扩展**：在已有的漏洞代码基础上进行修改（如添加更多 replace 调用），说明漏洞代码在更早的提交中已存在
2. **代码格式修复**：提交消息包含 checkstyle、format、indent、license 等关键词
3. **代码移动/重命名**：文件从其他位置移动过来
4. **项目初始化**：批量导入代码，提交消息包含 initial、import、migrate 等
5. **diff 显示有删除行（-）**：说明之前已经有代码存在，不是首次编写

### 什么情况下 **是** 真正引入点：
1. **首次编写**：漏洞相关的函数/方法是在这个提交中从零开始编写的
2. **父提交中没有相关代码**：在父提交的文件内容中，找不到漏洞相关的代码
3. **这是文件的第一个提交**：该文件是在这个提交中首次创建，且不是从其他地方复制的

### ⚠️ 特别注意
- 如果 diff 中显示对漏洞代码行有修改（既有 - 也有 +），说明之前已有代码，应该继续追踪
- 如果后面还有更早的提交，除非有充分证据，否则应该继续追踪
- 宁可多追踪几个提交，也不要过早停止

## 返回 JSON 格式
```json
{{
    "is_vulnerability_related": true/false,
    "is_introduction_point": true/false,
    "should_continue_tracking": true/false,
    "confidence": 0.0-1.0,
    "reasoning": "详细分析理由，说明为什么判断是/不是引入点",
    "evidence": "支持你判断的具体证据（如diff中的具体行）",
    "next_action": "continue/stop"
}}
```

**再次强调：如果不确定，应该选择继续追踪（should_continue_tracking: true）**"""


VALIDATE_DECISION_PROMPT = """你是代码安全分析审核专家。请验证大模型的追踪决策是否正确。

## 漏洞信息
- 修复提交: {fix_commit_hash}
- 漏洞代码: {vulnerable_code}

## 被分析的提交
- 提交哈希: {current_commit_hash}
- 提交消息: {current_commit_message}

## 大模型的判断
- 是否是引入点: {is_introduction}
- 是否继续追踪: {should_continue}
- 置信度: {confidence}
- 理由: {reasoning}

## 代码变更
```diff
{commit_diff}
```

## 验证任务
1. 大模型的判断是否合理？
2. 如果判断有误，给出修正建议

返回 JSON：
```json
{{
    "is_valid": true/false,
    "corrected_is_introduction": null/true/false,
    "corrected_should_continue": null/true/false,
    "reasoning": "验证理由",
    "suggestion": "修正建议（如有）"
}}
```"""


class LLMDrivenSZZ:
    """
    LLM 主导的漏洞引入追踪
    
    核心理念：让 LLM 像人类安全专家一样分析代码历史，
    而不是依赖工具的机械判断。
    """
    
    def __init__(self, repo_path: str, enable_validation: bool = True,
                 max_history_depth: int = 50):
        """
        Args:
            repo_path: Git 仓库路径
            enable_validation: 是否启用小模型验证
            max_history_depth: 最大追踪深度
        """
        self.repo = Repo(repo_path)
        self.repo_path = repo_path
        self.enable_validation = enable_validation
        self.max_history_depth = max_history_depth
        
        # 统计
        self.llm_calls = 0
        self.validation_calls = 0
        self.tracked_commits = []
    
    def find_vulnerability_introduction(
        self, 
        fix_commit_hash: str,
        file_path: str,
        vulnerable_line: str,
        cve_info: str = ""
    ) -> Dict:
        """
        追踪漏洞引入点
        
        Args:
            fix_commit_hash: 修复提交哈希
            file_path: 漏洞文件路径
            vulnerable_line: 漏洞代码行
            cve_info: CVE 信息（可选）
            
        Returns:
            追踪结果
        """
        print(f"\n{'='*60}")
        print(f"🔍 开始追踪漏洞引入点")
        print(f"   修复提交: {fix_commit_hash[:12]}")
        print(f"   文件: {file_path}")
        print(f"   漏洞代码: {vulnerable_line[:50]}...")
        print(f"{'='*60}\n")
        
        # 1. 获取修复提交信息
        fix_commit = self.repo.commit(fix_commit_hash)
        fix_info = {
            'hash': fix_commit_hash,
            'message': fix_commit.message.strip()[:500],
            'date': str(fix_commit.committed_datetime)
        }
        
        # 2. 获取文件的完整历史（使用 git log --follow）
        file_history = self._get_file_history(fix_commit_hash, file_path)
        
        if not file_history:
            print("⚠️ 无法获取文件历史")
            return {'error': 'No file history found'}
        
        print(f"📜 找到 {len(file_history)} 个历史提交\n")
        
        # 3. LLM 主导：逐个分析历史提交
        result = self._llm_driven_analysis(
            fix_info=fix_info,
            file_path=file_path,
            vulnerable_line=vulnerable_line,
            file_history=file_history,
            cve_info=cve_info
        )
        
        # 4. 输出统计
        print(f"\n📊 追踪统计:")
        print(f"   大模型调用: {self.llm_calls} 次")
        print(f"   小模型验证: {self.validation_calls} 次")
        print(f"   分析提交数: {len(self.tracked_commits)}")
        
        return result
    
    def _get_file_history(self, start_commit: str, file_path: str) -> List[str]:
        """
        获取文件的历史提交列表
        使用 git log --follow 来跟踪文件重命名
        """
        try:
            # git log --follow --oneline <commit>^ -- <file>
            output = self.repo.git.log(
                '--follow', '--oneline', '--format=%H',
                f'{start_commit}^',
                '--', file_path
            )
            
            if output:
                commits = output.strip().split('\n')
                return commits[:self.max_history_depth]
            return []
        except Exception as e:
            print(f"⚠️ 获取历史失败: {e}")
            return []
    
    def _search_code_in_repo(self, code_snippet: str) -> List[Dict]:
        """
        使用 git log -S 在整个仓库中搜索代码片段的历史
        
        这可以找到：
        - 代码从其他文件复制过来的情况
        - 项目迁移前的历史
        - 代码重命名/移动的情况
        """
        results = []
        
        # 提取关键代码片段（不要太长）
        search_terms = self._extract_search_terms(code_snippet)
        
        for term in search_terms[:3]:  # 最多搜索3个关键词
            try:
                # git log -S "code" --all --format="%H|%s|%ai"
                # 注意：不使用 --ancestry-path，直接搜索所有历史
                cmd_args = ['-S', term, '--all', '--format=%H|%s|%ai', '--']
                
                output = self.repo.git.log(*cmd_args)
                
                if output:
                    for line in output.strip().split('\n')[:10]:  # 最多10个结果
                        parts = line.split('|', 2)
                        if len(parts) >= 2:
                            results.append({
                                'hash': parts[0],
                                'message': parts[1] if len(parts) > 1 else '',
                                'date': parts[2] if len(parts) > 2 else '',
                                'search_term': term
                            })
            except Exception as e:
                print(f"   ⚠️ 搜索 '{term[:20]}...' 失败: {e}")
        
        # 去重
        seen = set()
        unique_results = []
        for r in results:
            if r['hash'] not in seen:
                seen.add(r['hash'])
                unique_results.append(r)
        
        return unique_results
    
    def _extract_search_terms(self, code_snippet: str) -> List[str]:
        """从代码中提取适合搜索的关键词/片段"""
        import re
        terms = []
        
        # 1. 提取函数/方法调用
        method_calls = re.findall(r'\b(\w+)\s*\([^)]*\)', code_snippet)
        for m in method_calls:
            if len(m) > 3 and m not in ['String', 'Integer', 'new', 'return', 'print']:
                terms.append(m)
        
        # 2. 提取特征性的代码片段（如 replace(":", "_")）
        patterns = re.findall(r'\.(\w+\([^)]+\))', code_snippet)
        terms.extend(patterns[:2])
        
        # 3. 提取字符串字面量
        strings = re.findall(r'["\']([^"\'\n]+)["\']', code_snippet)
        for s in strings:
            if len(s) > 2 and len(s) < 20:
                terms.append(s)
        
        return list(set(terms))[:5]
    
    def _get_commit_diff(self, commit_hash: str, file_path: str = None) -> str:
        """获取提交的 diff"""
        try:
            commit = self.repo.commit(commit_hash)
            if not commit.parents:
                # 初始提交
                return self.repo.git.show(commit_hash, '--stat')
            
            parent = commit.parents[0]
            if file_path:
                diff = self.repo.git.diff(parent.hexsha, commit.hexsha, '--', file_path)
            else:
                diff = self.repo.git.diff(parent.hexsha, commit.hexsha)
            
            # 限制长度
            if len(diff) > 6000:
                diff = diff[:6000] + "\n... [diff truncated] ..."
            return diff
        except Exception as e:
            return f"[Error getting diff: {e}]"
    
    def _build_history_summary(self, file_history: List[str]) -> str:
        """构建文件历史摘要，让 LLM 了解整体情况"""
        summary_lines = []
        for idx, commit_hash in enumerate(file_history[:15]):  # 最多显示15个
            try:
                commit = self.repo.commit(commit_hash)
                msg = commit.message.strip().split('\n')[0][:60]
                date = commit.committed_datetime.strftime('%Y-%m-%d')
                summary_lines.append(f"  {idx+1}. [{commit_hash[:10]}] {date} - {msg}")
            except:
                summary_lines.append(f"  {idx+1}. [{commit_hash[:10]}] (无法获取信息)")
        
        if len(file_history) > 15:
            summary_lines.append(f"  ... 还有 {len(file_history) - 15} 个更早的提交")
        
        return '\n'.join(summary_lines)
    
    def _get_parent_file_content(self, commit_hash: str, file_path: str, 
                                  vulnerable_line: str) -> str:
        """
        获取父提交中的文件内容（与漏洞相关的部分）
        这是关键信息！让 LLM 知道在这个提交之前文件是什么样的
        """
        try:
            commit = self.repo.commit(commit_hash)
            if not commit.parents:
                return "[这是该文件的第一个提交，没有父提交]"
            
            parent = commit.parents[0]
            
            # 尝试获取父提交中的文件内容
            try:
                parent_content = self.repo.git.show(f'{parent.hexsha}:{file_path}')
            except:
                return "[在父提交中该文件不存在]"
            
            # 提取与漏洞代码相关的部分
            lines = parent_content.split('\n')
            
            # 搜索包含漏洞相关关键词的行
            keywords = self._extract_keywords(vulnerable_line)
            relevant_lines = []
            
            for i, line in enumerate(lines):
                if any(kw in line for kw in keywords):
                    # 获取上下文（前后各3行）
                    start = max(0, i - 3)
                    end = min(len(lines), i + 4)
                    context = lines[start:end]
                    relevant_lines.append(f"行 {start+1}-{end}:\n" + '\n'.join(context))
            
            if relevant_lines:
                result = '\n---\n'.join(relevant_lines[:3])  # 最多3段
                if len(result) > 2000:
                    result = result[:2000] + "\n... [内容截断]"
                return result
            else:
                # 如果没找到相关行，返回文件的一部分
                if len(parent_content) > 1500:
                    return parent_content[:1500] + "\n... [文件内容截断]"
                return parent_content
                
        except Exception as e:
            return f"[无法获取父提交文件内容: {e}]"
    
    def _extract_keywords(self, vulnerable_line: str) -> List[str]:
        """从漏洞代码中提取关键词"""
        # 提取函数名、变量名等
        import re
        keywords = []
        
        # 提取标识符
        identifiers = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', vulnerable_line)
        # 过滤常见关键词
        common = {'String', 'string', 'int', 'return', 'if', 'else', 'new', 'public', 
                  'private', 'void', 'class', 'static', 'final', 'this', 'null', 'true', 'false'}
        keywords = [w for w in identifiers if w not in common and len(w) > 2]
        
        return keywords[:5]  # 最多5个关键词
    
    def _is_migration_commit(self, commit_message: str, commit_diff: str) -> bool:
        """判断是否是代码迁移/导入提交"""
        migration_keywords = [
            'move', 'moved', 'migrate', 'migration', 'import', 'imported',
            'initial', 'init commit', 'copy', 'copied', 'rename', 'renamed',
            'restructure', 'refactor', 'reorganize', 'trunk'
        ]
        
        msg_lower = commit_message.lower()
        for kw in migration_keywords:
            if kw in msg_lower:
                return True
        
        # 如果是大批量新增文件
        if commit_diff:
            new_file_count = commit_diff.count('new file mode')
            if new_file_count > 10:
                return True
        
        return False
    
    def _analyze_extended_history(
        self,
        fix_info: Dict,
        file_path: str,
        vulnerable_line: str,
        extended_commits: List[Dict],
        cve_info: str,
        file_history_summary: str
    ) -> Optional[str]:
        """
        分析通过 git log -S 找到的扩展历史
        
        这些提交可能在其他文件中，或者在项目迁移之前
        """
        llm = get_llm_client()
        if not llm:
            return None
        
        print(f"\n📚 分析扩展历史...")
        
        for commit_info in extended_commits[:5]:  # 最多分析5个
            commit_hash = commit_info['hash']
            
            try:
                commit = self.repo.commit(commit_hash)
                
                # 获取该提交修改的文件
                if not commit.parents:
                    continue
                    
                parent = commit.parents[0]
                
                # 获取完整的 diff（不限于特定文件）
                diff = self.repo.git.diff(parent.hexsha, commit.hexsha, '-U3')
                if len(diff) > 8000:
                    diff = diff[:8000] + "\n... [diff truncated]"
                
                print(f"   🔎 分析: {commit_hash[:10]} - {commit_info['message'][:40]}...")
                
                # 使用简化的 prompt
                prompt = f"""你是漏洞引入追踪专家。

## 任务
通过 git log -S 搜索，我们在仓库中找到了一个更早的提交，可能包含漏洞代码的原始版本。
请判断这个提交是否是漏洞代码的**真正引入点**。

## 漏洞信息
- CVE: {cve_info}
- 漏洞代码: {vulnerable_line[:200]}

## 当前分析的提交
- 哈希: {commit_hash[:12]}
- 日期: {commit.committed_datetime}
- 消息: {commit.message.strip()[:200]}

## 代码变更
```diff
{diff}
```

## 判断标准
1. 这个提交是否首次编写/引入了漏洞相关的代码逻辑？
2. 这不是简单的代码移动/重命名，而是真正"手写"代码的地方？

返回 JSON:
```json
{{
    "is_introduction_point": true/false,
    "confidence": 0.0-1.0,
    "reasoning": "判断理由",
    "affected_file": "相关文件路径"
}}
```"""
                
                response = llm.chat([
                    {"role": "system", "content": "你是漏洞追踪专家。请用 JSON 格式回复。"},
                    {"role": "user", "content": prompt}
                ])
                self.llm_calls += 1
                
                analysis = self._parse_json_response(response)
                
                if analysis and analysis.get('is_introduction_point'):
                    print(f"   ✅ 找到更早的引入点: {commit_hash[:12]}")
                    print(f"      文件: {analysis.get('affected_file', 'N/A')}")
                    print(f"      理由: {analysis.get('reasoning', '')[:60]}...")
                    
                    # 记录
                    self.tracked_commits.append({
                        'hash': commit_hash,
                        'message': commit.message.strip()[:100],
                        'analysis': analysis,
                        'source': 'extended_search'
                    })
                    
                    return commit_hash
                else:
                    print(f"      不是引入点: {analysis.get('reasoning', '')[:50]}...")
                    
            except Exception as e:
                print(f"   ⚠️ 分析失败: {e}")
                continue
        
        return None

    def _llm_driven_analysis(
        self,
        fix_info: Dict,
        file_path: str,
        vulnerable_line: str,
        file_history: List[str],
        cve_info: str
    ) -> Dict:
        """
        LLM 主导的分析流程
        
        给 LLM 提供详尽的信息：
        - 完整的文件历史列表
        - 每个提交的 diff
        - 父提交中的文件内容
        - AST 工具的预分析结果（作为参考）
        """
        llm = get_llm_client()
        if not llm:
            return {'error': 'LLM not available'}
        
        introduction_commit = None
        self.tracked_commits = []
        
        # 构建文件历史摘要，让 LLM 了解整体情况
        file_history_summary = self._build_history_summary(file_history)
        
        for idx, commit_hash in enumerate(file_history):
            commit = self.repo.commit(commit_hash)
            commit_diff = self._get_commit_diff(commit_hash, file_path)
            
            # 获取父提交中的文件内容（关键信息！）
            parent_content = self._get_parent_file_content(commit_hash, file_path, vulnerable_line)
            
            print(f"🔎 分析提交 [{idx+1}/{len(file_history)}]: {commit_hash[:12]}")
            print(f"   消息: {commit.message.strip()[:60]}...")
            
            # 计算剩余可追踪的提交数
            remaining_commits = len(file_history) - idx - 1
            
            # 构建 prompt，给 LLM 提供详尽信息
            prompt = ANALYZE_COMMIT_PROMPT.format(
                cve_info=cve_info or "未知",
                fix_commit_hash=fix_info['hash'][:12],
                fix_commit_message=fix_info['message'][:200],
                vulnerable_code=vulnerable_line[:300],
                file_history_summary=file_history_summary,
                current_commit_hash=commit_hash[:12],
                current_commit_date=str(commit.committed_datetime),
                current_commit_message=commit.message.strip()[:300],
                commit_index=idx + 1,
                total_commits=len(file_history),
                remaining_commits=remaining_commits,
                commit_diff=commit_diff,
                parent_file_content=parent_content
            )
            
            # 调用大模型
            response = llm.chat([
                {"role": "system", "content": "你是漏洞引入追踪专家。你的任务是找到漏洞代码被首次编写的提交。请谨慎判断，如果不确定就继续追踪。请用 JSON 格式回复。"},
                {"role": "user", "content": prompt}
            ])
            self.llm_calls += 1
            
            # 解析响应
            analysis = self._parse_json_response(response)
            if not analysis:
                print(f"   ⚠️ 无法解析 LLM 响应，继续追踪")
                self.tracked_commits.append({
                    'hash': commit_hash,
                    'message': commit.message.strip()[:100],
                    'analysis': None
                })
                continue
            
            # 记录分析结果
            self.tracked_commits.append({
                'hash': commit_hash,
                'message': commit.message.strip()[:100],
                'analysis': analysis
            })
            
            print(f"   📝 LLM 判断:")
            print(f"      - 漏洞相关: {analysis.get('is_vulnerability_related')}")
            print(f"      - 是引入点: {analysis.get('is_introduction_point')}")
            print(f"      - 继续追踪: {analysis.get('should_continue_tracking')}")
            print(f"      - 置信度: {analysis.get('confidence')}")
            print(f"      - 理由: {analysis.get('reasoning', '')[:80]}...")
            if analysis.get('evidence'):
                print(f"      - 证据: {analysis.get('evidence', '')[:60]}...")
            
            # 小模型验证（如果启用且 LLM 判断为引入点）
            if self.enable_validation and analysis.get('is_introduction_point') and not analysis.get('should_continue_tracking'):
                validation = self._validate_decision(
                    fix_info=fix_info,
                    commit_hash=commit_hash,
                    commit_message=commit.message.strip(),
                    commit_diff=commit_diff,
                    vulnerable_line=vulnerable_line,
                    analysis=analysis,
                    remaining_commits=remaining_commits
                )
                
                if validation and not validation.get('is_valid', True):
                    print(f"   🔄 小模型验证失败: {validation.get('suggestion', '')[:50]}...")
                    # 小模型认为判断有误，继续追踪
                    if validation.get('corrected_should_continue') is True:
                        print(f"   ➡️ 根据验证结果继续追踪")
                        continue
                else:
                    print(f"   ✅ 小模型验证通过")
            
            # LLM 决定：是否找到引入点
            if analysis.get('is_introduction_point') and not analysis.get('should_continue_tracking'):
                introduction_commit = commit_hash
                is_migration = self._is_migration_commit(commit.message.strip(), commit_diff)
                print(f"\n🎯 找到漏洞引入点: {commit_hash[:12]}")
                print(f"   消息: {commit.message.strip()[:80]}")
                if is_migration:
                    print(f"   ⚠️ 注意: 这可能是代码迁移，真正的首次编写可能更早")
                break
            
            # 检查是否是最后一个提交
            is_last_commit = (idx == len(file_history) - 1)
            
            # LLM 决定：是否继续追踪
            if not analysis.get('should_continue_tracking'):
                if is_last_commit:
                    # 这是最后一个提交，即使 LLM 认为不是引入点，也作为边界返回
                    print(f"\n📍 已到达文件历史的最后一个提交")
                    print(f"   LLM 认为这不是真正的首次编写（可能是迁移/导入）")
                    
                    # 尝试用 git log -S 搜索更早的历史
                    print(f"\n🔎 尝试在整个仓库中搜索相似代码...")
                    extended_history = self._search_code_in_repo(vulnerable_line)
                    
                    if extended_history:
                        analyzed_hashes = {c['hash'] for c in self.tracked_commits}
                        new_commits = [c for c in extended_history if c['hash'] not in analyzed_hashes]
                        
                        if new_commits:
                            print(f"   找到 {len(new_commits)} 个可能相关的更早提交:")
                            for nc in new_commits[:5]:
                                print(f"     - {nc['hash'][:10]}: {nc['message'][:50]}...")
                            
                            extended_result = self._analyze_extended_history(
                                fix_info, file_path, vulnerable_line, new_commits, cve_info, file_history_summary
                            )
                            if extended_result:
                                introduction_commit = extended_result
                                break
                    
                    # 如果没找到更早的历史，返回当前提交作为边界
                    if not introduction_commit:
                        print(f"\n📌 将 {commit_hash[:12]} 作为可追踪范围内的引入点")
                        print(f"   （这是文件历史中包含漏洞代码的最早提交）")
                        introduction_commit = commit_hash
                        if self.tracked_commits:
                            self.tracked_commits[-1]['is_boundary'] = True
                            self.tracked_commits[-1]['note'] = '文件历史边界，可能是迁移/导入'
                else:
                    print(f"\n⏹️ LLM 决定停止追踪（非引入点，但无需继续）")
                break
            
            # 如果是最后一个提交但 LLM 仍想继续追踪
            if is_last_commit and analysis.get('should_continue_tracking'):
                # 到达文件历史的尽头，但 LLM 仍想继续追踪
                print(f"\n📍 已到达文件历史的最后一个提交")
                
                # 尝试用 git log -S 搜索更早的历史
                print(f"\n🔎 尝试在整个仓库中搜索相似代码...")
                extended_history = self._search_code_in_repo(vulnerable_line)
                
                if extended_history:
                    # 过滤掉已经分析过的提交
                    analyzed_hashes = {c['hash'] for c in self.tracked_commits}
                    new_commits = [c for c in extended_history if c['hash'] not in analyzed_hashes]
                    
                    if new_commits:
                        print(f"   找到 {len(new_commits)} 个可能相关的更早提交:")
                        for nc in new_commits[:5]:
                            print(f"     - {nc['hash'][:10]}: {nc['message'][:50]}...")
                        
                        # 将这些提交添加到待分析列表（继续循环会处理）
                        # 但由于我们已经在循环末尾，需要特殊处理
                        extended_result = self._analyze_extended_history(
                            fix_info, file_path, vulnerable_line, new_commits, cve_info, file_history_summary
                        )
                        if extended_result:
                            introduction_commit = extended_result
                            break
                
                # 如果没找到更早的历史，或者分析后仍未确定
                # 则返回当前提交作为"可追踪范围内的引入点"
                if not introduction_commit:
                    print(f"\n📌 将 {commit_hash[:12]} 作为可追踪范围内的引入点")
                    print(f"   （这是文件历史中包含漏洞代码的最早提交）")
                    introduction_commit = commit_hash
                    # 标记为边界情况
                    if self.tracked_commits:
                        self.tracked_commits[-1]['is_boundary'] = True
                        self.tracked_commits[-1]['note'] = '文件历史边界，可能是迁移/导入'
                break
                break
            
            print()  # 换行分隔
        
        return {
            'introduction_commit': introduction_commit,
            'fix_commit': fix_info['hash'],
            'file_path': file_path,
            'vulnerable_line': vulnerable_line,
            'tracked_commits': self.tracked_commits,
            'llm_calls': self.llm_calls,
            'validation_calls': self.validation_calls
        }
    
    def _validate_decision(
        self,
        fix_info: Dict,
        commit_hash: str,
        commit_message: str,
        commit_diff: str,
        vulnerable_line: str,
        analysis: Dict,
        remaining_commits: int = 0
    ) -> Optional[Dict]:
        """使用小模型验证大模型的决策"""
        small_llm = get_small_llm_client()
        if not small_llm:
            return None
        
        try:
            # 增强验证 prompt
            validation_prompt = f"""你是代码安全分析审核专家。请严格验证大模型的追踪决策是否正确。

## 漏洞信息
- 修复提交: {fix_info['hash'][:12]}
- 漏洞代码: {vulnerable_line[:200]}

## 被分析的提交
- 提交哈希: {commit_hash[:12]}
- 提交消息: {commit_message[:150]}
- **后面还有 {remaining_commits} 个更早的提交可以追踪**

## 大模型的判断
- 是否是引入点: {analysis.get('is_introduction_point')}
- 是否继续追踪: {analysis.get('should_continue_tracking')}
- 置信度: {analysis.get('confidence', 0)}
- 理由: {analysis.get('reasoning', '')[:400]}
- 证据: {analysis.get('evidence', '')[:200]}

## 代码变更
```diff
{commit_diff[:3000]}
```

## 关键验证点
1. **如果后面还有更早的提交，应该谨慎判断为引入点**
2. 提交消息是否包含 checkstyle、format、indent？（如果是，可能不是引入点）
3. diff 中是否显示对漏洞代码的修改（而非首次添加）？
4. 是否有证据表明漏洞代码是首次在这里编写的？

返回 JSON：
```json
{{
    "is_valid": true/false,
    "corrected_should_continue": null/true/false,
    "reasoning": "验证理由",
    "suggestion": "修正建议（如有）"
}}
```"""
            
            response = small_llm.chat([
                {"role": "system", "content": "你是代码安全审核专家。如果不确定，建议继续追踪。请用 JSON 格式回复。"},
                {"role": "user", "content": validation_prompt}
            ])
            self.validation_calls += 1
            
            return self._parse_json_response(response)
        except Exception as e:
            print(f"   ⚠️ 验证失败: {e}")
            return None
    
    def _parse_json_response(self, response: str) -> Optional[Dict]:
        """解析 JSON 响应"""
        import re
        
        try:
            return json.loads(response)
        except:
            pass
        
        # 尝试提取 JSON 块
        json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group())
            except:
                pass
        
        # 更宽松的匹配
        json_match = re.search(r'\{.*\}', response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group())
            except:
                pass
        
        return None


def run_llm_szz(
    repo_path: str,
    fix_commit: str,
    file_path: str,
    vulnerable_line: str,
    cve_info: str = ""
) -> Dict:
    """
    运行 LLM 主导的漏洞追踪
    
    Args:
        repo_path: 仓库路径
        fix_commit: 修复提交哈希
        file_path: 漏洞文件路径
        vulnerable_line: 漏洞代码行
        cve_info: CVE 信息
        
    Returns:
        追踪结果
    """
    szz = LLMDrivenSZZ(repo_path)
    return szz.find_vulnerability_introduction(
        fix_commit_hash=fix_commit,
        file_path=file_path,
        vulnerable_line=vulnerable_line,
        cve_info=cve_info
    )


# ============== 测试代码 ==============
if __name__ == "__main__":
    # 测试：CVE-2015-1830 (activemq)
    # 正确的引入点应该是 e6d20f3932b556377218ac2e353a2cc99d26d1ea
    
    result = run_llm_szz(
        repo_path=r"C:\Users\lxp\Desktop\Improved V-SZZ\repos\activemq",
        fix_commit="729c4731574ffffaf58ebefdbaeb3bd19ed1c7b7",
        file_path="activemq-fileserver/src/main/java/org/apache/activemq/util/FilenameGuardFilter.java",
        vulnerable_line='String guarded = filename.replace(":", "_").replace("\\\\", "").replace("/", "");',
        cve_info="CVE-2015-1830 (CWE-22 Path Traversal)"
    )
    
    print("\n" + "="*60)
    print("📋 最终结果:")
    print("="*60)
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
