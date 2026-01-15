"""
LLM 增强版 MySZZ

设计原则：
- 保持原始 V-SZZ 流程完全不变（git blame → srcml过滤注释 → AST映射）
- 只在关键位置（判断是否是引入点）加入 LLM 验证
- LLM 调用最小化，只在必要时调用
"""

import os
import sys
import logging as log
import traceback
from typing import List, Set, Optional, Dict

from szz.my_szz import MySZZ, compute_line_ratio, remove_whitespace, MAXSIZE

# LLM 客户端（延迟导入，避免循环依赖）
_llm_client = None
_small_llm_client = None  # 小模型客户端


def get_llm_client():
    """获取大模型 LLM 客户端（单例）"""
    global _llm_client
    if _llm_client is None:
        try:
            # 尝试导入 LLM 客户端
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))))
            from llm_client import CachedLLMClient, OpenAIClient
            
            api_key = os.environ.get('OPENAI_API_KEY', 'sk-smMd7t4GCBkCgoPZkBTE7WzZeSSOAvSvTREm5jWOhSEpA3tw')
            base_url = os.environ.get('OPENAI_BASE_URL', 'https://yunwu.ai/v1')
            model = os.environ.get('LLM_MODEL', 'gpt-5.1-codex')  # 大模型，用于追踪决策
            
            if api_key:
                client = OpenAIClient(api_key=api_key, model=model, base_url=base_url)
                _llm_client = CachedLLMClient(client, enable_cache=True)
                print(f"🤖 LLM 已启用: {model}")
            else:
                print("⚠️ 未配置 API 密钥，LLM 验证已禁用")
        except Exception as e:
            print(f"⚠️ LLM 初始化失败: {e}")
    return _llm_client


def get_small_llm_client():
    """获取小模型 LLM 客户端（单例）- 用于验证大模型结果"""
    global _small_llm_client
    if _small_llm_client is None:
        try:
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))))
            from llm_client import CachedLLMClient, OpenAIClient
            
            api_key = os.environ.get('OPENAI_API_KEY', 'sk-smMd7t4GCBkCgoPZkBTE7WzZeSSOAvSvTREm5jWOhSEpA3tw')
            base_url = os.environ.get('OPENAI_BASE_URL', 'https://yunwu.ai/v1')
            small_model = os.environ.get('SMALL_LLM_MODEL', 'gpt-5-mini')  # 小模型，用于验证
            
            if api_key:
                client = OpenAIClient(api_key=api_key, model=small_model, base_url=base_url)
                _small_llm_client = CachedLLMClient(client, enable_cache=True)
                print(f"🔍 验证模型已启用: {small_model}")
            else:
                print("⚠️ 未配置 API 密钥，小模型验证已禁用")
        except Exception as e:
            print(f"⚠️ 小模型初始化失败: {e}")
    return _small_llm_client


# LLM 验证 Prompt
VERIFY_INTRODUCTION_PROMPT = """你是代码安全分析专家。请判断以下提交是否是漏洞代码的**真正引入点**（Vulnerability Introducing Commit, VIC）。

## 漏洞修复信息
- 修复提交: {fix_commit_hash}
- 修复消息: {fix_commit_message}
- 漏洞代码行: {vulnerable_line}

## 当前分析的提交
- 提交哈希: {current_commit_hash}
- 提交日期: {current_commit_date}
- 提交消息: {current_commit_message}
- 变更类型（AST工具判断）: {change_type}

## 代码变更
```diff
{commit_diff}
```

## 重要判断标准

### 不是真正引入点的情况（需要继续追踪）：
1. **代码移动/重命名**：文件从其他位置移动过来，漏洞代码已经存在
2. **代码复制**：从项目其他文件复制代码过来，漏洞逻辑在源文件中已存在
3. **项目初始化/迁移**：大量代码批量导入，可能是从其他仓库迁移
4. **重构**：函数/类重构，代码逻辑未改变

### 是真正引入点的情况：
1. **首次编写漏洞逻辑**：开发者在此提交中首次编写了不安全的代码
2. **修改引入漏洞**：对原本安全的代码进行修改，导致引入漏洞
3. **新功能开发**：开发新功能时引入了安全缺陷

### 特别注意 "New File" 类型：
- 如果提交消息包含 "initial"、"import"、"migrate"、"copy"、"move" 等关键词，很可能不是真正引入点
- 如果文件是从其他地方复制来的，应标记为不是引入点
- 只有当漏洞代码确实是在这个提交中**首次编写**时，才是真正引入点

请返回 JSON 格式：
```json
{{
    "is_introduction": true或false,
    "confidence": 0.0到1.0,
    "reasoning": "详细分析理由",
    "possible_origin": "如果不是引入点，说明代码可能来自哪里（如：其他文件、其他仓库、初始化导入等）"
}}
```"""


# 小模型验证 Prompt
VALIDATE_DECISION_PROMPT = """你是代码安全分析审核专家。请严格验证以下追踪决策是否正确。

## 背景
我们正在追踪漏洞引入点（Vulnerability Introducing Commit, VIC）。
VIC 必须是漏洞代码**首次被编写**的提交，不是移动/复制/迁移代码的提交。

## 漏洞修复信息
- 修复提交: {fix_commit_hash}
- 漏洞代码行: {vulnerable_line}

## 被分析的提交
- 提交哈希: {current_commit_hash}
- 提交消息: {current_commit_message}
- AST工具判断: {change_type}

## 大模型的判断
- 结论: {large_model_decision}
- 置信度: {large_model_confidence}
- 理由: {large_model_reasoning}

## 代码变更片段
```diff
{commit_diff_snippet}
```

## 验证重点

### 如果大模型判断是 is_introduction=True，检查：
1. 代码是否是从其他文件复制来的？（如果是，则判断错误）
2. 提交消息是否包含 "initial"、"import"、"migrate"、"copy"、"move"？（可能不是真正引入点）
3. 是否是批量导入/项目初始化？（可能不是真正引入点）

### 如果大模型判断是 is_introduction=False，检查：
1. 是否有证据表明代码确实来自其他地方？
2. 如果没有证据，可能应该判断为 True

## 严格标准
- 只有当漏洞代码是**首次手工编写**时，才应判断为 is_introduction=True
- 如果代码可能来自其他地方（即使无法确定来源），应该倾向于 is_introduction=False

返回 JSON 格式：
```json
{{
    "is_valid": true或false,
    "corrected_decision": null或true或false,
    "reasoning": "详细验证理由",
    "suggestion": "如果判断需要修正，给出具体建议"
}}
```"""


class MySZZWithLLM(MySZZ):
    """
    LLM 增强版 MySZZ
    
    工作流程：
    1. 完全复用 MySZZ 的追踪逻辑（git blame + srcml + AST）
    2. 当 AST 判断为 Insert/New File（即找到引入点）时，调用大模型验证
    3. 大模型判断后，小模型验证决策的合理性
    4. 如果小模型认为判断错误，反馈给大模型重新分析
    5. 最大重试次数: 3
    """
    
    def __init__(self, repo_full_name: str, repo_url: str, repos_dir: str = None, 
                 use_temp_dir: bool = True, ast_map_path=None,
                 enable_llm: bool = True, fix_commit_info: Dict = None,
                 max_iterations: int = 3):
        super().__init__(repo_full_name, repo_url, repos_dir, use_temp_dir, ast_map_path)
        self.enable_llm = enable_llm
        self.fix_commit_info = fix_commit_info or {}
        self.llm_calls = 0  # 大模型调用次数
        self.validation_calls = 0  # 小模型验证次数
        self.max_iterations = max_iterations  # 最大重试次数
    
    def find_bic(self, fix_commit_hash: str, impacted_files: List, **kwargs):
        """
        查找漏洞引入提交（带 LLM 验证）
        
        完全保持原始 MySZZ 的流程，只在关键位置加入 LLM 验证
        """
        log.info(f"find_bic() with LLM enhancement, kwargs: {kwargs}")
        
        # 保存修复提交信息供 LLM 使用
        try:
            fix_commit = self.repository.commit(fix_commit_hash)
            self.fix_commit_info = {
                'hash': fix_commit_hash,
                'message': fix_commit.message.strip()[:500],
                'date': str(fix_commit.committed_datetime)
            }
        except:
            pass
        
        ignore_revs_file_path = kwargs.get('ignore_revs_file_path', None)
        
        bug_introd_commits = []
        for imp_file in impacted_files:
            try:
                blame_data = self._blame(
                    rev='{commit_id}^'.format(commit_id=fix_commit_hash),
                    file_path=imp_file.file_path,
                    modified_lines=imp_file.modified_lines,
                    ignore_revs_file_path=ignore_revs_file_path,
                    ignore_whitespaces=False,
                    skip_comments=True  # srcml 过滤注释
                )

                for entry in blame_data:
                    print(entry.commit, entry.line_num, entry.line_str)
                    previous_commits = []
                    
                    blame_result = entry
                    max_depth = 50  # 防止无限循环
                    depth = 0
                    
                    while depth < max_depth:
                        depth += 1
                        
                        if imp_file.file_path.endswith(".java"):
                            # Java 文件：使用 AST 映射
                            mapped_line_num, change_type = self.map_modified_line_java(blame_result, imp_file.file_path)
                            previous_commits.append((blame_result.commit.hexsha, blame_result.line_num, blame_result.line_str, change_type))
                            
                            # ========== LLM 增强点（双模型验证 + 反馈循环）==========
                            # 当 AST 判断为 Insert 或 New File 时，用大模型+小模型验证
                            if change_type in ("Insert", "New File") and self.enable_llm:
                                llm_verdict = self._llm_verify_with_validation(
                                    blame_result=blame_result,
                                    change_type=change_type,
                                    vulnerable_line=entry.line_str
                                )
                                
                                if llm_verdict and not llm_verdict.get('is_introduction', True):
                                    # LLM 认为这不是真正的引入点，尝试继续追踪
                                    print(f"   🤖 LLM: 不是引入点，继续追踪 (原因: {llm_verdict.get('reasoning', '')[:50]}...)")
                                    if llm_verdict.get('validated'):
                                        print(f"   ✅ 验证通过")
                                    
                                    # ★ 关键改进：即使是 New File，也尝试用 git log 继续追踪
                                    if change_type == "New File":
                                        print(f"   🔍 尝试用 git log --follow 继续追踪...")
                                        next_commit = self._find_previous_commit_by_git_log(
                                            blame_result.commit.hexsha,
                                            imp_file.file_path,
                                            blame_result.line_str
                                        )
                                        if next_commit:
                                            print(f"   ✅ 找到前一个提交: {next_commit[:12]}")
                                            # 更新 blame_result 继续追踪
                                            try:
                                                blame_data2 = self._blame(
                                                    rev='{commit_id}^'.format(commit_id=next_commit),
                                                    file_path=imp_file.file_path,
                                                    modified_lines=[blame_result.line_num],  # 使用当前行号
                                                    ignore_revs_file_path=ignore_revs_file_path,
                                                    ignore_whitespaces=False,
                                                    skip_comments=True
                                                )
                                                blame_data2_list = list(blame_data2)
                                                if blame_data2_list:
                                                    blame_result = blame_data2_list[0]
                                                    continue  # 继续追踪
                                            except:
                                                pass
                                        print(f"   ⚠️ 无法继续追踪（git log 未找到更早的提交）")
                                        break
                                    # 否则继续追踪（非 New File）
                                else:
                                    # LLM 确认是引入点
                                    print(f"   🤖 LLM: 确认是引入点")
                                    if llm_verdict and llm_verdict.get('validated'):
                                        print(f"   ✅ 验证通过")
                                    break  # 找到真正的引入点，停止追踪
                            # ========== LLM 增强点结束 ==========
                        else:
                            # 非 Java 文件：使用 Levenshtein 匹配
                            mapped_line_num = self.map_modified_line(blame_result, imp_file.file_path)
                            previous_commits.append((blame_result.commit.hexsha, blame_result.line_num, blame_result.line_str))
                        
                        if mapped_line_num == -1:
                            break
                        
                        blame_data2 = self._blame(
                            rev='{commit_id}^'.format(commit_id=blame_result.commit.hexsha),
                            file_path=imp_file.file_path,
                            modified_lines=[mapped_line_num],
                            ignore_revs_file_path=ignore_revs_file_path,
                            ignore_whitespaces=False,
                            skip_comments=True
                        )
                        blame_result = list(blame_data2)[0]

                    bug_introd_commits.append({
                        'line_num': entry.line_num, 
                        'line_str': entry.line_str, 
                        'file_path': entry.file_path, 
                        'previous_commits': previous_commits
                    })
            except:
                print(traceback.format_exc())

        print(f"\n📊 LLM 调用统计:")
        print(f"   大模型 (gpt-5.1-codex): {self.llm_calls} 次")
        print(f"   小模型 (gpt-5-mini) 验证: {self.validation_calls} 次")
        return bug_introd_commits
    
    def _llm_verify_with_validation(self, blame_result, change_type: str, 
                                     vulnerable_line: str) -> Optional[Dict]:
        """
        使用大模型验证 + 小模型校验的双重验证机制
        
        流程：
        1. 大模型 (gpt-5.1-codex) 做出追踪决策
        2. 小模型 (gpt-5-mini) 验证决策合理性
        3. 如果小模型认为有问题，反馈给大模型重新分析
        4. 最多重试 max_iterations 次
        """
        large_llm = get_llm_client()
        small_llm = get_small_llm_client()
        
        if not large_llm:
            return None
        
        commit = blame_result.commit
        commit_diff = self._get_commit_diff_str(commit.hexsha)
        
        # 初始大模型决策
        large_result = self._call_large_model(blame_result, change_type, vulnerable_line, commit_diff)
        if not large_result:
            return None
        
        self.llm_calls += 1
        
        # 如果没有小模型，直接返回大模型结果
        if not small_llm:
            return large_result
        
        # 小模型验证循环
        for iteration in range(self.max_iterations):
            validation = self._call_small_model_validation(
                blame_result, change_type, vulnerable_line, commit_diff, large_result
            )
            self.validation_calls += 1
            
            if validation and validation.get('is_valid', True):
                # 小模型验证通过
                large_result['validated'] = True
                large_result['validation_iterations'] = iteration + 1
                return large_result
            elif validation and not validation.get('is_valid', True):
                # 小模型认为有问题，反馈给大模型重新分析
                print(f"   🔄 小模型验证失败 (第{iteration+1}次)，反馈: {validation.get('suggestion', '')[:50]}...")
                
                if iteration < self.max_iterations - 1:
                    # 带反馈重新调用大模型
                    large_result = self._call_large_model_with_feedback(
                        blame_result, change_type, vulnerable_line, commit_diff,
                        previous_decision=large_result,
                        feedback=validation.get('suggestion', '')
                    )
                    self.llm_calls += 1
                    if not large_result:
                        break
        
        # 达到最大重试次数，标记未验证
        if large_result:
            large_result['validated'] = False
            large_result['validation_iterations'] = self.max_iterations
        return large_result
    
    def _call_large_model(self, blame_result, change_type: str, 
                          vulnerable_line: str, commit_diff: str) -> Optional[Dict]:
        """调用大模型进行追踪决策"""
        llm = get_llm_client()
        if not llm:
            return None
        
        try:
            commit = blame_result.commit
            prompt = VERIFY_INTRODUCTION_PROMPT.format(
                fix_commit_hash=self.fix_commit_info.get('hash', 'Unknown')[:12],
                fix_commit_message=self.fix_commit_info.get('message', 'Unknown')[:200],
                vulnerable_line=vulnerable_line[:200] if vulnerable_line else '',
                current_commit_hash=commit.hexsha[:12],
                current_commit_date=str(commit.committed_datetime),
                current_commit_message=commit.message.strip()[:200],
                change_type=change_type,
                commit_diff=commit_diff[:3000]
            )
            
            response = llm.chat([
                {"role": "system", "content": "你是代码安全分析专家。请用 JSON 格式回复。"},
                {"role": "user", "content": prompt}
            ])
            
            return self._parse_json_response(response)
        except Exception as e:
            print(f"   ⚠️ 大模型调用失败: {e}")
            return None
    
    def _call_large_model_with_feedback(self, blame_result, change_type: str,
                                         vulnerable_line: str, commit_diff: str,
                                         previous_decision: Dict, feedback: str) -> Optional[Dict]:
        """带反馈调用大模型重新分析"""
        llm = get_llm_client()
        if not llm:
            return None
        
        try:
            commit = blame_result.commit
            base_prompt = VERIFY_INTRODUCTION_PROMPT.format(
                fix_commit_hash=self.fix_commit_info.get('hash', 'Unknown')[:12],
                fix_commit_message=self.fix_commit_info.get('message', 'Unknown')[:200],
                vulnerable_line=vulnerable_line[:200] if vulnerable_line else '',
                current_commit_hash=commit.hexsha[:12],
                current_commit_date=str(commit.committed_datetime),
                current_commit_message=commit.message.strip()[:200],
                change_type=change_type,
                commit_diff=commit_diff[:3000]
            )
            
            feedback_prompt = f"""
{base_prompt}

## 重新分析请求
你之前的判断被审核模型认为有问题：
- 之前的判断: is_introduction = {previous_decision.get('is_introduction')}
- 审核反馈: {feedback}

请根据反馈重新分析，给出修正后的判断。"""
            
            response = llm.chat([
                {"role": "system", "content": "你是代码安全分析专家。请用 JSON 格式回复。"},
                {"role": "user", "content": feedback_prompt}
            ])
            
            return self._parse_json_response(response)
        except Exception as e:
            print(f"   ⚠️ 大模型重新分析失败: {e}")
            return None
    
    def _call_small_model_validation(self, blame_result, change_type: str,
                                      vulnerable_line: str, commit_diff: str,
                                      large_result: Dict) -> Optional[Dict]:
        """调用小模型验证大模型的决策"""
        small_llm = get_small_llm_client()
        if not small_llm:
            return None
        
        try:
            commit = blame_result.commit
            prompt = VALIDATE_DECISION_PROMPT.format(
                fix_commit_hash=self.fix_commit_info.get('hash', 'Unknown')[:12],
                vulnerable_line=vulnerable_line[:200] if vulnerable_line else '',
                current_commit_hash=commit.hexsha[:12],
                current_commit_message=commit.message.strip()[:100],
                change_type=change_type,
                large_model_decision=large_result.get('is_introduction'),
                large_model_confidence=large_result.get('confidence', 0),
                large_model_reasoning=large_result.get('reasoning', '')[:300],
                commit_diff_snippet=commit_diff[:1500]  # 小模型用更短的上下文
            )
            
            response = small_llm.chat([
                {"role": "system", "content": "你是代码安全分析审核专家。请用 JSON 格式回复。"},
                {"role": "user", "content": prompt}
            ])
            
            return self._parse_json_response(response)
        except Exception as e:
            print(f"   ⚠️ 小模型验证失败: {e}")
            return None
    
    def _parse_json_response(self, response: str) -> Optional[Dict]:
        """解析 JSON 响应"""
        import json
        import re
        
        try:
            # 尝试直接解析
            return json.loads(response)
        except:
            pass
        
        # 提取 JSON 块
        json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group())
            except:
                pass
        
        return None
    
    def _llm_verify_introduction(self, blame_result, change_type: str, 
                                  vulnerable_line: str) -> Optional[Dict]:
        """
        使用 LLM 验证是否是真正的引入点
        
        Args:
            blame_result: blame 结果
            change_type: AST 判断的变更类型
            vulnerable_line: 漏洞代码行
            
        Returns:
            LLM 判断结果 {"is_introduction": bool, "confidence": float, "reasoning": str}
        """
        llm = get_llm_client()
        if not llm:
            return None
        
        try:
            self.llm_calls += 1
            
            # 获取提交的 diff
            commit = blame_result.commit
            commit_diff = self._get_commit_diff_str(commit.hexsha)
            
            prompt = VERIFY_INTRODUCTION_PROMPT.format(
                fix_commit_hash=self.fix_commit_info.get('hash', 'Unknown')[:12],
                fix_commit_message=self.fix_commit_info.get('message', 'Unknown')[:200],
                vulnerable_line=vulnerable_line[:200] if vulnerable_line else '',
                current_commit_hash=commit.hexsha[:12],
                current_commit_date=str(commit.committed_datetime),
                current_commit_message=commit.message.strip()[:200],
                change_type=change_type,
                commit_diff=commit_diff[:3000]  # 限制长度
            )
            
            response = llm.chat([
                {"role": "system", "content": "你是代码安全分析专家。请用 JSON 格式回复。"},
                {"role": "user", "content": prompt}
            ])
            
            # 解析 JSON 响应
            import json
            import re
            
            # 提取 JSON
            json_match = re.search(r'\{[^{}]*"is_introduction"[^{}]*\}', response, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
                return result
            
            return None
            
        except Exception as e:
            print(f"   ⚠️ LLM 验证失败: {e}")
            return None
    
    def _get_commit_diff_str(self, commit_hash: str) -> str:
        """获取提交的 diff 字符串"""
        try:
            commit = self.repository.commit(commit_hash)
            if not commit.parents:
                return "[Initial commit - no diff available]"
            
            parent = commit.parents[0]
            diff = self.repository.git.diff(parent.hexsha, commit.hexsha)
            return diff[:5000]  # 限制长度
        except Exception as e:
            return f"[Failed to get diff: {e}]"

    def _find_previous_commit_by_git_log(self, current_commit: str, file_path: str, 
                                          target_line: str = None) -> Optional[str]:
        """
        当 AST 判断为 New File 时，使用 git log --follow 查找前一个修改该文件的提交
        
        这用于处理 AST 工具误判的情况，例如：
        - checkstyle 格式修复被误判为 New File
        - 大量代码重排被误判为 New File
        
        Args:
            current_commit: 当前提交哈希
            file_path: 文件路径
            target_line: 目标代码行（可选，用于更精确的匹配）
            
        Returns:
            前一个提交的哈希，如果没有找到则返回 None
        """
        try:
            # 使用 git log --follow 获取文件历史
            # --follow 参数可以跟踪文件重命名
            log_output = self.repository.git.log(
                '--follow', '--oneline', 
                f'{current_commit}^',  # 从当前提交的父提交开始
                '--', file_path
            )
            
            if log_output:
                lines = log_output.strip().split('\n')
                if lines:
                    # 返回第一个（最近的）提交
                    first_commit = lines[0].split()[0]
                    return first_commit
            
            return None
        except Exception as e:
            print(f"   ⚠️ git log 查找失败: {e}")
            return None
