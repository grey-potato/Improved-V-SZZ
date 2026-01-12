#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
BFC (Bug-Fixing Commit) 自动识别模块
使用多种方法自动识别仓库中的漏洞修复提交
"""

import re
import os
import json
from datetime import datetime, timedelta
from typing import List, Dict, Set
from git import Repo


class BFCIdentifier:
    """
    自动识别BFC的类
    组合多种方法：commit message关键词、代码模式、PR标签等
    """
    
    def __init__(self, repo_path: str):
        """
        初始化BFC识别器
        
        Args:
            repo_path: Git仓库路径
        """
        self.repo_path = repo_path
        self.repo = Repo(repo_path)
        
        # 安全关键词（优先级排序）
        self.security_keywords = {
            'high': [
                'cve', 'vulnerability', 'exploit', 'security fix',
                'security issue', 'security patch', 'security vulnerability'
            ],
            'medium': [
                'security', 'injection', 'xss', 'csrf', 'xxe',
                'authentication', 'authorization', 'privilege',
                'buffer overflow', 'memory leak', 'dos', 'denial of service'
            ],
            'low': [
                'validate', 'sanitize', 'escape', 'filter',
                'access control', 'permission', 'safe'
            ]
        }
        
        # 代码安全模式（正则表达式）
        self.security_code_patterns = [
            # SQL注入修复
            (r'preparedStatement|PreparedStatement', 'SQL Injection Prevention'),
            (r'execute\([^)]*\?[^)]*\)', 'Parameterized Query'),
            (r'setString|setInt|setLong', 'Prepared Statement Parameter'),
            
            # XSS修复
            (r'escapeHtml|htmlspecialchars|encodeForHTML', 'XSS Prevention'),
            (r'sanitize|DOMPurify', 'Input Sanitization'),
            
            # 认证/密码修复
            (r'bcrypt|scrypt|pbkdf2|argon2', 'Secure Password Hashing'),
            (r'MessageDigest\.isEqual|constantTimeCompare', 'Timing Attack Prevention'),
            (r'SecureRandom|crypto\.getRandomValues', 'Secure Random'),
            
            # 输入验证
            (r'Pattern\.compile.*validate', 'Input Validation'),
            (r'Validator\.|validator\.', 'Validation Framework'),
            
            # 访问控制
            (r'@PreAuthorize|@Secured|@RolesAllowed', 'Access Control Annotation'),
            (r'checkPermission|hasRole|isGranted', 'Permission Check'),
            
            # HTTPS/TLS
            (r'https://|TLSv1\.2|TLSv1\.3', 'Secure Communication'),
            
            # 文件路径遍历
            (r'Path\.normalize|canonicalize', 'Path Traversal Prevention'),
            (r'FilenameUtils\.normalize', 'Filename Validation'),
        ]
    
    def find_candidate_bfcs(self, 
                           max_commits: int = 500,
                           since_date: str = None,
                           branch: str = 'HEAD') -> List[Dict]:
        """
        查找候选BFC
        
        Args:
            max_commits: 最多检查的提交数
            since_date: 开始日期（格式: YYYY-MM-DD）
            branch: 分支名
            
        Returns:
            候选BFC列表
        """
        print(f"🔍 开始扫描仓库提交（最多{max_commits}个）...")
        
        candidates = []
        
        # 构建git log参数
        kwargs = {'max_count': max_commits}
        if since_date:
            kwargs['since'] = since_date
        
        # 遍历提交
        for i, commit in enumerate(self.repo.iter_commits(branch, **kwargs)):
            if i % 100 == 0:
                print(f"  已扫描 {i} 个提交...")
            
            # 方法1: 基于commit message
            message_score, message_reason = self._analyze_commit_message(commit.message)
            
            # 方法2: 基于代码变更
            code_score, code_patterns = self._analyze_code_changes(commit)
            
            # 综合评分
            total_score = message_score + code_score
            
            if total_score > 0:
                candidate = {
                    'commit_hash': commit.hexsha,
                    'short_hash': commit.hexsha[:8],
                    'date': datetime.fromtimestamp(commit.committed_date).isoformat(),
                    'author': commit.author.name,
                    'author_email': commit.author.email,
                    'message': commit.message.strip(),
                    'message_score': message_score,
                    'message_reason': message_reason,
                    'code_score': code_score,
                    'code_patterns': code_patterns,
                    'total_score': total_score,
                    'files_changed': len(commit.stats.files),
                    'insertions': commit.stats.total['insertions'],
                    'deletions': commit.stats.total['deletions'],
                }
                candidates.append(candidate)
        
        # 按分数排序
        candidates.sort(key=lambda x: x['total_score'], reverse=True)
        
        print(f"✓ 找到 {len(candidates)} 个候选BFC")
        
        return candidates
    
    def _analyze_commit_message(self, message: str) -> tuple:
        """
        分析commit message是否包含安全关键词
        
        Returns:
            (score, reason)
        """
        message_lower = message.lower()
        score = 0
        reasons = []
        
        # 高优先级关键词
        for keyword in self.security_keywords['high']:
            if keyword in message_lower:
                score += 10
                reasons.append(f"包含高优先级关键词: '{keyword}'")
        
        # 中优先级关键词
        for keyword in self.security_keywords['medium']:
            if keyword in message_lower:
                score += 5
                reasons.append(f"包含中优先级关键词: '{keyword}'")
        
        # 低优先级关键词
        for keyword in self.security_keywords['low']:
            if keyword in message_lower:
                score += 2
                reasons.append(f"包含低优先级关键词: '{keyword}'")
        
        # 检查是否包含"fix"类词汇
        fix_words = ['fix', 'patch', 'resolve', 'correct', 'address']
        has_fix = any(word in message_lower for word in fix_words)
        if has_fix and score > 0:
            score += 3
            reasons.append("包含修复类关键词")
        
        return score, '; '.join(reasons) if reasons else ''
    
    def _analyze_code_changes(self, commit) -> tuple:
        """
        分析代码变更是否包含安全相关模式
        
        Returns:
            (score, patterns_found)
        """
        score = 0
        patterns_found = []
        
        try:
            # 获取diff
            if len(commit.parents) == 0:
                # 初始提交，跳过
                return 0, []
            
            diffs = commit.diff(commit.parents[0], create_patch=True)
            
            for diff in diffs:
                if diff.diff is None:
                    continue
                
                try:
                    diff_text = diff.diff.decode('utf-8', errors='ignore')
                except:
                    continue
                
                # 检查每个安全模式
                for pattern, description in self.security_code_patterns:
                    if re.search(pattern, diff_text, re.IGNORECASE):
                        score += 3
                        patterns_found.append(description)
        
        except Exception as e:
            # 某些提交可能无法获取diff
            pass
        
        return score, list(set(patterns_found))
    
    def filter_by_files(self, candidates: List[Dict], 
                       exclude_patterns: List[str] = None) -> List[Dict]:
        """
        根据修改的文件类型过滤候选
        
        Args:
            candidates: 候选BFC列表
            exclude_patterns: 排除的文件模式（如测试文件、文档等）
        """
        if exclude_patterns is None:
            exclude_patterns = [
                r'test.*\.py$', r'.*_test\.py$', r'.*Test\.java$',
                r'README', r'CHANGELOG', r'\.md$',
                r'\.txt$', r'\.yml$', r'\.yaml$'
            ]
        
        filtered = []
        
        for candidate in candidates:
            commit = self.repo.commit(candidate['commit_hash'])
            
            # 获取修改的文件
            files = list(commit.stats.files.keys())
            
            # 检查是否都是排除的文件
            all_excluded = all(
                any(re.search(pattern, f) for pattern in exclude_patterns)
                for f in files
            )
            
            if not all_excluded:
                candidate['modified_files'] = files
                filtered.append(candidate)
        
        return filtered
    
    def export_candidates(self, candidates: List[Dict], 
                         output_file: str = 'bfc_candidates.json'):
        """
        导出候选BFC到JSON文件
        """
        output_path = os.path.join(os.path.dirname(self.repo_path), output_file)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(candidates, f, indent=2, ensure_ascii=False)
        
        print(f"✓ 候选BFC已导出到: {output_path}")
        
        return output_path
    
    def print_summary(self, candidates: List[Dict], top_n: int = 10):
        """
        打印候选BFC摘要
        """
        print("\n" + "=" * 80)
        print(f"📊 BFC候选摘要（共 {len(candidates)} 个）")
        print("=" * 80)
        
        if not candidates:
            print("未找到候选BFC")
            return
        
        # 显示top N
        print(f"\n🔝 Top {min(top_n, len(candidates))} 候选（按分数排序）:\n")
        
        for i, candidate in enumerate(candidates[:top_n], 1):
            print(f"{i}. {candidate['short_hash']} (分数: {candidate['total_score']})")
            print(f"   日期: {candidate['date']}")
            print(f"   作者: {candidate['author']}")
            print(f"   消息: {candidate['message'][:80]}...")
            
            if candidate['message_reason']:
                print(f"   原因: {candidate['message_reason']}")
            
            if candidate['code_patterns']:
                print(f"   模式: {', '.join(candidate['code_patterns'][:3])}")
            
            print()
        
        # 统计
        print("📈 统计信息:")
        print(f"   - 高分候选 (>=20分): {sum(1 for c in candidates if c['total_score'] >= 20)}")
        print(f"   - 中分候选 (10-19分): {sum(1 for c in candidates if 10 <= c['total_score'] < 20)}")
        print(f"   - 低分候选 (<10分): {sum(1 for c in candidates if c['total_score'] < 10)}")
        print()


def main():
    """测试函数"""
    import sys
    
    if len(sys.argv) < 2:
        print("用法: python bfc_identifier.py <仓库路径> [最大提交数]")
        sys.exit(1)
    
    repo_path = sys.argv[1]
    max_commits = int(sys.argv[2]) if len(sys.argv) > 2 else 500
    
    # 创建识别器
    identifier = BFCIdentifier(repo_path)
    
    # 查找候选
    candidates = identifier.find_candidate_bfcs(max_commits=max_commits)
    
    # 过滤（排除测试和文档）
    candidates = identifier.filter_by_files(candidates)
    
    # 显示摘要
    identifier.print_summary(candidates)
    
    # 导出
    identifier.export_candidates(candidates)


if __name__ == '__main__':
    main()
