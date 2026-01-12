#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
LLM BFC验证模块
使用大语言模型验证和精化BFC识别结果
"""

import json
import os
from typing import Dict, List
from git import Repo


class LLMBFCVerifier:
    """
    使用LLM验证BFC的类
    阶段1: 验证候选BFC是否真的是安全修复
    """
    
    def __init__(self, repo_path: str, llm_client=None):
        """
        初始化LLM验证器
        
        Args:
            repo_path: Git仓库路径
            llm_client: LLM客户端（如OpenAI, Anthropic等）
        """
        self.repo_path = repo_path
        self.repo = Repo(repo_path)
        self.llm = llm_client
    
    def verify_bfc(self, candidate: Dict, include_diff: bool = True) -> Dict:
        """
        验证单个BFC候选
        
        Args:
            candidate: 候选BFC信息
            include_diff: 是否在prompt中包含完整diff
            
        Returns:
            验证结果
        """
        commit = self.repo.commit(candidate['commit_hash'])
        
        # 构建prompt
        prompt = self._build_verification_prompt(candidate, commit, include_diff)
        
        # 调用LLM
        if self.llm is None:
            # 如果没有LLM客户端，返回模拟结果
            print(f"⚠️ 警告: 未配置LLM客户端，返回基于规则的结果")
            return self._rule_based_verification(candidate)
        
        try:
            response = self._call_llm(prompt)
            result = self._parse_llm_response(response)
            
            # 添加额外信息
            result['commit_hash'] = candidate['commit_hash']
            result['original_score'] = candidate['total_score']
            
            return result
        
        except Exception as e:
            print(f"❌ LLM调用失败: {e}")
            return self._rule_based_verification(candidate)
    
    def verify_batch(self, candidates: List[Dict], 
                    max_verify: int = 20) -> List[Dict]:
        """
        批量验证BFC候选
        
        Args:
            candidates: 候选列表
            max_verify: 最多验证数量（控制成本）
        """
        print(f"\n🤖 开始LLM验证（最多 {max_verify} 个）...")
        
        verified = []
        
        # 优先验证高分候选
        candidates_sorted = sorted(candidates, 
                                   key=lambda x: x['total_score'], 
                                   reverse=True)
        
        for i, candidate in enumerate(candidates_sorted[:max_verify], 1):
            print(f"\n处理 {i}/{min(max_verify, len(candidates))}: {candidate['short_hash']}")
            
            result = self.verify_bfc(candidate)
            verified.append(result)
            
            # 显示结果
            if result['is_valid_bfc']:
                print(f"  ✓ 验证通过 (置信度: {result['confidence']:.2f})")
                print(f"    类型: {result.get('vulnerability_type', 'Unknown')}")
            else:
                print(f"  ✗ 不是BFC (置信度: {result['confidence']:.2f})")
        
        # 过滤出验证通过的
        valid_bfcs = [r for r in verified 
                     if r['is_valid_bfc'] and r['confidence'] >= 0.7]
        
        print(f"\n✓ 验证完成: {len(valid_bfcs)}/{len(verified)} 个通过验证")
        
        return verified
    
    def _build_verification_prompt(self, candidate: Dict, 
                                   commit, include_diff: bool) -> str:
        """构建LLM验证prompt"""
        
        # 获取diff
        diff_text = ""
        if include_diff and len(commit.parents) > 0:
            try:
                diffs = commit.diff(commit.parents[0], create_patch=True)
                diff_lines = []
                for diff in diffs[:5]:  # 只取前5个文件
                    if diff.diff:
                        try:
                            diff_lines.append(diff.diff.decode('utf-8', errors='ignore'))
                        except:
                            pass
                diff_text = '\n'.join(diff_lines[:2000])  # 限制长度
            except:
                diff_text = "[无法获取diff]"
        
        # 获取修改的文件列表
        files = list(commit.stats.files.keys())
        files_str = '\n'.join(f"  - {f}" for f in files[:10])
        
        prompt = f"""请分析以下Git提交，判断它是否是安全漏洞修复提交（BFC - Bug Fixing Commit）。

# 提交信息
- Commit Hash: {candidate['commit_hash']}
- 日期: {candidate['date']}
- 作者: {candidate['author']}
- 提交消息:
```
{candidate['message']}
```

# 修改统计
- 修改文件数: {candidate['files_changed']}
- 新增行数: {candidate['insertions']}
- 删除行数: {candidate['deletions']}

# 修改的文件
{files_str}

# 代码变更
```diff
{diff_text}
```

# 初步分析
- 消息分析: {candidate.get('message_reason', '无')}
- 检测到的模式: {', '.join(candidate.get('code_patterns', [])) or '无'}

---

请深入分析并回答以下问题：

1. **这是安全漏洞修复吗？** 
   - 考虑：是否修复了具体的安全问题？
   - 考虑：是否只是一般性的代码改进？
   - 考虑：是否是重构或功能添加？

2. **如果是安全修复，漏洞类型是什么？**
   - SQL注入、XSS、CSRF、认证问题、权限提升等
   - 具体的CWE编号（如果能识别）

3. **置信度如何？** (0.0-1.0)
   - 考虑：证据是否充分？
   - 考虑：是否有模糊不清的地方？

4. **核心修复是在哪些文件？**
   - 区分：核心安全修复 vs 测试文件 vs 文档更新

5. **修复的是什么安全问题？**
   - 用1-2句话描述漏洞机制

请以JSON格式输出：
```json
{{
    "is_valid_bfc": true或false,
    "confidence": 0.0到1.0之间的数字,
    "vulnerability_type": "漏洞类型（如SQL Injection）",
    "cwe_id": "CWE编号（如CWE-89）或null",
    "severity": "High/Medium/Low或null",
    "core_fix_files": ["核心修复文件1", "核心修复文件2"],
    "excluded_files": ["测试或文档文件"],
    "vulnerability_description": "简短描述漏洞",
    "fix_description": "简短描述修复方式",
    "reasoning": "你的分析推理过程",
    "evidence": ["证据1", "证据2"]
}}
```

只输出JSON，不要其他内容。"""
        
        return prompt
    
    def _call_llm(self, prompt: str) -> str:
        """
        调用LLM API
        需要根据具体的LLM客户端实现
        """
        # 这里需要根据实际使用的LLM实现
        # 示例：OpenAI
        if hasattr(self.llm, 'chat') and hasattr(self.llm.chat, 'completions'):
            response = self.llm.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "你是一个专业的安全漏洞分析专家。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                response_format={"type": "json_object"}
            )
            return response.choices[0].message.content
        
        # 示例：Anthropic Claude
        elif hasattr(self.llm, 'messages') and hasattr(self.llm.messages, 'create'):
            response = self.llm.messages.create(
                model="claude-3-opus-20240229",
                max_tokens=2000,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            return response.content[0].text
        
        else:
            raise ValueError("不支持的LLM客户端类型")
    
    def _parse_llm_response(self, response: str) -> Dict:
        """解析LLM返回的JSON"""
        try:
            # 尝试直接解析
            return json.loads(response)
        except json.JSONDecodeError:
            # 尝试提取JSON块
            import re
            json_match = re.search(r'```json\s*(\{.*?\})\s*```', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(1))
            
            # 尝试找到第一个{和最后一个}
            start = response.find('{')
            end = response.rfind('}')
            if start != -1 and end != -1:
                return json.loads(response[start:end+1])
            
            raise ValueError("无法解析LLM响应为JSON")
    
    def _rule_based_verification(self, candidate: Dict) -> Dict:
        """
        基于规则的验证（当没有LLM时的后备方案）
        """
        score = candidate['total_score']
        
        # 简单的规则
        if score >= 20:
            confidence = 0.8
            is_valid = True
        elif score >= 10:
            confidence = 0.6
            is_valid = True
        else:
            confidence = 0.4
            is_valid = False
        
        return {
            'is_valid_bfc': is_valid,
            'confidence': confidence,
            'vulnerability_type': 'Unknown',
            'cwe_id': None,
            'severity': None,
            'core_fix_files': candidate.get('modified_files', []),
            'excluded_files': [],
            'vulnerability_description': '基于规则的判断',
            'fix_description': '基于规则的判断',
            'reasoning': f'基于关键词和模式的规则判断，总分：{score}',
            'evidence': candidate.get('code_patterns', []),
            'commit_hash': candidate['commit_hash'],
            'original_score': score
        }
    
    def export_verified_bfcs(self, verified: List[Dict], 
                            output_file: str = 'verified_bfcs.json'):
        """导出验证结果"""
        output_path = os.path.join(os.path.dirname(self.repo_path), output_file)
        
        # 只导出验证通过的
        valid_bfcs = [v for v in verified 
                     if v['is_valid_bfc'] and v['confidence'] >= 0.7]
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(valid_bfcs, f, indent=2, ensure_ascii=False)
        
        print(f"\n✓ 验证通过的BFC已导出到: {output_path}")
        print(f"  共 {len(valid_bfcs)} 个BFC")
        
        return output_path
    
    def print_verification_summary(self, verified: List[Dict]):
        """打印验证摘要"""
        print("\n" + "=" * 80)
        print("📊 BFC验证结果摘要")
        print("=" * 80)
        
        valid = [v for v in verified if v['is_valid_bfc']]
        high_conf = [v for v in valid if v['confidence'] >= 0.8]
        medium_conf = [v for v in valid if 0.6 <= v['confidence'] < 0.8]
        
        print(f"\n总计验证: {len(verified)} 个")
        print(f"  ✓ 验证通过: {len(valid)} 个")
        print(f"    - 高置信度 (>=0.8): {len(high_conf)} 个")
        print(f"    - 中置信度 (0.6-0.8): {len(medium_conf)} 个")
        print(f"  ✗ 未通过: {len(verified) - len(valid)} 个")
        
        # 漏洞类型统计
        if valid:
            print("\n漏洞类型分布:")
            vuln_types = {}
            for v in valid:
                vtype = v.get('vulnerability_type', 'Unknown')
                vuln_types[vtype] = vuln_types.get(vtype, 0) + 1
            
            for vtype, count in sorted(vuln_types.items(), 
                                      key=lambda x: x[1], reverse=True):
                print(f"  - {vtype}: {count}")
        
        print()


def demo_without_llm():
    """演示不使用真实LLM的情况"""
    print("演示模式：不使用真实LLM，基于规则验证")
    print("如需使用真实LLM，请配置LLM客户端")


if __name__ == '__main__':
    demo_without_llm()
