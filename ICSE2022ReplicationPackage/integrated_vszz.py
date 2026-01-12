#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
集成版V-SZZ：自动识别BFC + V-SZZ分析
无需手动标注，直接分析任意Git仓库
"""

import os
import sys
import json
import re
from datetime import datetime
from typing import List, Dict, Set
from git import Repo

# 导入V-SZZ
sys.path.append(os.path.join(os.path.dirname(__file__), 
                             'icse2021-szz-replication-package/tools/pyszz/'))
from szz.my_szz import MySZZ


class IntegratedVSZZ:
    """
    集成版V-SZZ分析器
    功能：自动识别BFC → V-SZZ分析 → 输出BIC
    """
    
    def __init__(self, repo_path: str, llm_client=None):
        """
        初始化集成分析器
        
        Args:
            repo_path: Git仓库路径
            llm_client: LLM客户端（可选，用于提高BFC识别准确度）
        """
        self.repo_path = repo_path
        self.repo_name = os.path.basename(repo_path)
        self.repo = Repo(repo_path)
        self.llm_client = llm_client
        
        # 安全关键词
        self.security_keywords = {
            'high': ['cve', 'vulnerability', 'exploit', 'security fix', 
                    'security issue', 'security patch'],
            'medium': ['security', 'injection', 'xss', 'csrf', 'xxe',
                      'authentication', 'authorization', 'privilege',
                      'buffer overflow', 'dos'],
            'low': ['validate', 'sanitize', 'escape', 'filter']
        }
        
        # 初始化V-SZZ
        self.vszz = None
        self._init_vszz()
    
    def _init_vszz(self):
        """初始化V-SZZ实例"""
        try:
            ast_map_path = os.path.join(
                os.path.dirname(__file__), 
                'ASTMapEval_jar'
            )
            
            self.vszz = MySZZ(
                repo_full_name=self.repo_name,
                repo_url=None,
                repos_dir=os.path.dirname(self.repo_path),
                use_temp_dir=False,
                ast_map_path=ast_map_path
            )
            print(f"✓ V-SZZ初始化成功")
        except Exception as e:
            print(f"❌ V-SZZ初始化失败: {e}")
            self.vszz = None
    
    def analyze_repository(self, 
                          max_commits: int = 500,
                          max_bfcs: int = 10,
                          min_score: int = 10) -> Dict:
        """
        完整分析流程：识别BFC → LLM验证 → V-SZZ分析 → 输出结果
        
        Args:
            max_commits: 最多扫描的提交数
            max_bfcs: 最多分析的BFC数量
            min_score: BFC候选最低分数（用于初步筛选）
            
        Returns:
            完整分析结果
        """
        print("=" * 80)
        print(f"🚀 集成V-SZZ分析: {self.repo_name}")
        print("=" * 80)
        
        # 检查LLM配置
        if not self.llm_client:
            print("❌ 错误：必须配置LLM客户端")
            print("   使用 --openai-key 参数或设置 OPENAI_API_KEY 环境变量")
            print("   示例: python integrated_vszz.py repo --openai-key sk-xxx")
            return {'bfcs': [], 'results': {}}
        
        # 阶段1：识别候选BFC
        print(f"\n【阶段1】扫描候选BFC (扫描最近{max_commits}个提交)...")
        bfcs = self._identify_bfcs(max_commits, min_score)
        
        if not bfcs:
            print("❌ 未找到BFC候选，分析结束")
            return {'bfcs': [], 'results': {}}
        
        print(f"✓ 找到 {len(bfcs)} 个候选")
        
        # 阶段1.5：LLM验证（必须）
        print(f"\n【阶段1.5】LLM验证BFC (处理前{max_bfcs}个候选)...")
        verified_bfcs = self._verify_with_llm(bfcs, max_verify=max_bfcs)
        
        if not verified_bfcs:
            print("❌ LLM验证后没有通过的BFC")
            return {'bfcs': [], 'results': {}}
        
        print(f"✓ LLM验证通过 {len(verified_bfcs)} 个BFC")
        
        # 阶段2：V-SZZ分析
        print(f"\n【阶段2】V-SZZ分析 (处理{len(verified_bfcs)}个BFC)...")
        results = self._run_vszz_analysis(verified_bfcs)
        
        # 输出结果
        print(f"\n【阶段3】生成报告...")
        output_file = self._save_results(verified_bfcs, results)
        
        print("\n" + "=" * 80)
        print("✅ 分析完成")
        print("=" * 80)
        print(f"📊 统计:")
        print(f"  - 扫描提交: {max_commits}")
        print(f"  - 初步候选: {len(bfcs)}")
        print(f"  - LLM验证通过: {len(verified_bfcs)}")
        print(f"  - 成功分析: {len(results)}")
        print(f"  - 总BIC: {sum(len(bics) for bics in results.values())}")
        print(f"\n💾 结果已保存: {output_file}")
        
        return {
            'repository': self.repo_name,
            'bfcs': verified_bfcs,
            'results': results,
            'output_file': output_file
        }
    
    def scan_only(self, max_commits: int = 500, min_score: int = 10) -> str:
        """
        只扫描识别BFC，不运行V-SZZ
        
        Args:
            max_commits: 最多扫描的提交数
            min_score: BFC最低分数
            
        Returns:
            保存的JSON文件路径
        """
        print("=" * 80)
        print(f"🔍 扫描模式: {self.repo_name}")
        print("=" * 80)
        
        print(f"\n扫描最近{max_commits}个提交...")
        bfcs = self._identify_bfcs(max_commits, min_score)
        
        if not bfcs:
            print("❌ 未找到BFC候选")
            return None
        
        # 保存候选
        output_file = self._save_candidates(bfcs)
        
        print(f"\n✅ 扫描完成")
        print(f"   找到 {len(bfcs)} 个BFC候选")
        print(f"   已保存到: {output_file}")
        print(f"\n💡 使用以下命令分析特定BFC:")
        print(f"   python integrated_vszz.py {self.repo_path} --analyze-from {os.path.basename(output_file)} --ids 1,2,3")
        
        return output_file
    
    def analyze_specific_commits(self, commit_hashes: List[str]) -> Dict:
        """
        分析指定的commits
        
        Args:
            commit_hashes: commit hash列表
            
        Returns:
            分析结果
        """
        print("=" * 80)
        print(f"🎯 分析指定Commits: {self.repo_name}")
        print("=" * 80)
        
        bfcs = []
        for commit_hash in commit_hashes:
            try:
                commit = self.repo.commit(commit_hash)
                
                # 构建BFC信息
                files = list(commit.stats.files.keys())
                core_files = [f for f in files if self._is_core_file(f)]
                
                bfc = {
                    'commit_hash': commit.hexsha,
                    'short_hash': commit.hexsha[:8],
                    'date': datetime.fromtimestamp(commit.committed_date).isoformat(),
                    'author': commit.author.name,
                    'message': commit.message.strip(),
                    'score': 100,  # 手动指定视为高优先级
                    'reason': '手动指定',
                    'files': files,
                    'core_files': core_files,
                    'stats': {
                        'insertions': commit.stats.total['insertions'],
                        'deletions': commit.stats.total['deletions'],
                        'files_changed': len(files)
                    }
                }
                bfcs.append(bfc)
                print(f"✓ 加载commit: {commit.hexsha[:8]} - {commit.message[:50]}...")
                
            except Exception as e:
                print(f"❌ 无法加载commit {commit_hash}: {e}")
        
        if not bfcs:
            print("❌ 没有有效的commit")
            return {'bfcs': [], 'results': {}}
        
        # 运行V-SZZ
        print(f"\n【V-SZZ分析】处理 {len(bfcs)} 个commit...")
        results = self._run_vszz_analysis(bfcs)
        
        # 保存结果
        output_file = self._save_results(bfcs, results)
        
        print(f"\n✅ 分析完成")
        print(f"   成功分析: {len(results)}")
        print(f"   总BIC: {sum(len(bics) for bics in results.values())}")
        print(f"   结果: {output_file}")
        
        return {
            'repository': self.repo_name,
            'bfcs': bfcs,
            'results': results,
            'output_file': output_file
        }
    
    def analyze_by_cve(self, cve_id: str, max_commits: int = 1000) -> Dict:
        """
        分析指定CVE的修复commits
        
        Args:
            cve_id: CVE编号（如 CVE-2023-1234）
            max_commits: 最多扫描的提交数
            
        Returns:
            分析结果
        """
        print("=" * 80)
        print(f"🔎 分析CVE: {cve_id}")
        print("=" * 80)
        
        print(f"\n扫描最近{max_commits}个提交，查找 {cve_id}...")
        
        bfcs = []
        cve_lower = cve_id.lower()
        
        for commit in self.repo.iter_commits('HEAD', max_count=max_commits):
            if cve_lower in commit.message.lower():
                files = list(commit.stats.files.keys())
                core_files = [f for f in files if self._is_core_file(f)]
                
                if core_files:
                    bfc = {
                        'commit_hash': commit.hexsha,
                        'short_hash': commit.hexsha[:8],
                        'date': datetime.fromtimestamp(commit.committed_date).isoformat(),
                        'author': commit.author.name,
                        'message': commit.message.strip(),
                        'score': 100,
                        'reason': f'包含CVE: {cve_id}',
                        'files': files,
                        'core_files': core_files,
                        'cve_id': cve_id,
                        'stats': {
                            'insertions': commit.stats.total['insertions'],
                            'deletions': commit.stats.total['deletions'],
                            'files_changed': len(files)
                        }
                    }
                    bfcs.append(bfc)
                    print(f"✓ 找到: {commit.hexsha[:8]} - {commit.message[:60]}...")
        
        if not bfcs:
            print(f"❌ 未找到包含 {cve_id} 的commit")
            return {'bfcs': [], 'results': {}}
        
        print(f"\n✓ 找到 {len(bfcs)} 个相关commit")
        
        # 运行V-SZZ
        print(f"\n【V-SZZ分析】...")
        results = self._run_vszz_analysis(bfcs)
        
        # 保存结果
        output_file = self._save_results(bfcs, results)
        
        print(f"\n✅ {cve_id} 分析完成")
        print(f"   相关commits: {len(bfcs)}")
        print(f"   总BIC: {sum(len(bics) for bics in results.values())}")
        print(f"   结果: {output_file}")
        
        return {
            'repository': self.repo_name,
            'cve_id': cve_id,
            'bfcs': bfcs,
            'results': results,
            'output_file': output_file
        }
    
    def analyze_from_file(self, candidates_file: str, ids: List[int] = None) -> Dict:
        """
        从候选文件中选择BFC进行分析
        
        Args:
            candidates_file: 候选BFC的JSON文件
            ids: 要分析的BFC ID列表（None表示全部）
            
        Returns:
            分析结果
        """
        print("=" * 80)
        print(f"📂 从文件加载BFC")
        print("=" * 80)
        
        # 加载候选
        with open(candidates_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        all_candidates = data.get('candidates', [])
        
        if not all_candidates:
            print("❌ 文件中没有候选BFC")
            return {'bfcs': [], 'results': {}}
        
        print(f"✓ 加载了 {len(all_candidates)} 个候选")
        
        # 选择要分析的
        if ids:
            selected = [c for c in all_candidates if c.get('id') in ids]
            print(f"✓ 选择 {len(selected)} 个BFC进行分析 (IDs: {ids})")
        else:
            selected = all_candidates
            print(f"✓ 分析全部 {len(selected)} 个BFC")
        
        if not selected:
            print("❌ 没有选中任何BFC")
            return {'bfcs': [], 'results': {}}
        
        # 显示选中的BFC
        print("\n选中的BFC:")
        for bfc in selected:
            print(f"  {bfc.get('id', '?')}. {bfc['short_hash']} - {bfc['message'][:50]}...")
        
        # 运行V-SZZ
        print(f"\n【V-SZZ分析】...")
        results = self._run_vszz_analysis(selected)
        
        # 更新候选文件（标记已分析）
        for bfc in selected:
            for c in all_candidates:
                if c['commit_hash'] == bfc['commit_hash']:
                    c['analyzed'] = True
                    c['bic_count'] = len(results.get(bfc['commit_hash'], []))
        
        with open(candidates_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        # 保存结果
        output_file = self._save_results(selected, results)
        
        print(f"\n✅ 分析完成")
        print(f"   成功分析: {len(results)}")
        print(f"   总BIC: {sum(len(bics) for bics in results.values())}")
        print(f"   结果: {output_file}")
        
        return {
            'repository': self.repo_name,
            'bfcs': selected,
            'results': results,
            'output_file': output_file
        }
    
    def interactive_mode(self, max_commits: int = 500, min_score: int = 10) -> Dict:
        """
        交互式选择模式
        """
        print("=" * 80)
        print(f"🎮 交互模式: {self.repo_name}")
        print("=" * 80)
        
        # 扫描候选
        print(f"\n扫描最近{max_commits}个提交...")
        bfcs = self._identify_bfcs(max_commits, min_score)
        
        if not bfcs:
            print("❌ 未找到BFC候选")
            return {'bfcs': [], 'results': {}}
        
        # 显示候选
        print(f"\n找到 {len(bfcs)} 个BFC候选:\n")
        for i, bfc in enumerate(bfcs[:20], 1):  # 显示前20个
            print(f"[{i:2d}] {bfc['short_hash']} (分数:{bfc['score']:2d}) - {bfc['message'][:60]}")
        
        if len(bfcs) > 20:
            print(f"... 还有 {len(bfcs)-20} 个候选")
        
        # 用户选择
        print(f"\n请选择要分析的BFC:")
        print(f"  - 输入编号，用逗号分隔（如: 1,3,5）")
        print(f"  - 输入范围（如: 1-5）")
        print(f"  - 输入 'all' 分析全部")
        print(f"  - 输入 'q' 退出")
        
        choice = input("\n> ").strip()
        
        if choice.lower() == 'q':
            print("退出")
            return {'bfcs': [], 'results': {}}
        
        # 解析选择
        selected_ids = []
        if choice.lower() == 'all':
            selected_ids = list(range(1, len(bfcs) + 1))
        elif '-' in choice:
            # 范围
            parts = choice.split('-')
            if len(parts) == 2:
                try:
                    start = int(parts[0])
                    end = int(parts[1])
                    selected_ids = list(range(start, end + 1))
                except:
                    print("❌ 无效的范围")
                    return {'bfcs': [], 'results': {}}
        else:
            # 逗号分隔
            try:
                selected_ids = [int(x.strip()) for x in choice.split(',')]
            except:
                print("❌ 无效的输入")
                return {'bfcs': [], 'results': {}}
        
        # 选择BFC
        selected = [bfcs[i-1] for i in selected_ids if 0 < i <= len(bfcs)]
        
        if not selected:
            print("❌ 没有选中任何BFC")
            return {'bfcs': [], 'results': {}}
        
        print(f"\n✓ 选择了 {len(selected)} 个BFC")
        
        # 运行V-SZZ
        print(f"\n【V-SZZ分析】...")
        results = self._run_vszz_analysis(selected)
        
        # 保存结果
        output_file = self._save_results(selected, results)
        
        print(f"\n✅ 分析完成")
        print(f"   结果: {output_file}")
        
        return {
            'repository': self.repo_name,
            'bfcs': selected,
            'results': results,
            'output_file': output_file
        }
        
        print("\n" + "=" * 80)
        print("✅ 分析完成")
        print("=" * 80)
        print(f"📊 统计:")
        print(f"  - 扫描提交: {max_commits}")
        print(f"  - BFC候选: {len(bfcs)}")
        print(f"  - 分析BFC: {len(bfcs_to_analyze)}")
        print(f"  - 成功分析: {len(results)}")
        print(f"  - 总BIC: {sum(len(bics) for bics in results.values())}")
        print(f"\n💾 结果已保存: {output_file}")
        
        return {
            'repository': self.repo_name,
            'bfcs': bfcs_to_analyze,
            'results': results,
            'output_file': output_file
        }
    
    def _identify_bfcs(self, max_commits: int, min_score: int) -> List[Dict]:
        """
        识别BFC候选
        使用关键词和代码模式
        """
        candidates = []
        
        for i, commit in enumerate(self.repo.iter_commits('HEAD', max_count=max_commits)):
            if i % 100 == 0 and i > 0:
                print(f"  扫描进度: {i}/{max_commits}")
            
            # 分析commit message
            score, reason = self._score_commit(commit)
            
            if score >= min_score:
                # 获取修改的文件
                files = list(commit.stats.files.keys())
                
                # 过滤测试和文档文件
                core_files = [f for f in files if self._is_core_file(f)]
                
                if core_files:  # 必须有核心代码文件
                    # 尝试提取CVE编号
                    cve_match = re.search(r'CVE-\d{4}-\d+', commit.message, re.IGNORECASE)
                    cve_id = cve_match.group(0).upper() if cve_match else None
                    
                    # 尝试识别漏洞类型
                    vuln_type = self._identify_vulnerability_type(commit.message)
                    
                    candidates.append({
                        'commit_hash': commit.hexsha,
                        'short_hash': commit.hexsha[:8],
                        'date': datetime.fromtimestamp(commit.committed_date).isoformat(),
                        'author': commit.author.name,
                        'message': commit.message.strip(),
                        'score': score,
                        'reason': reason,
                        'cve_id': cve_id,
                        'vulnerability_type': vuln_type,
                        'files': files,
                        'core_files': core_files,
                        'analyzed': False,
                        'bic_count': None,
                        'stats': {
                            'insertions': commit.stats.total['insertions'],
                            'deletions': commit.stats.total['deletions'],
                            'files_changed': len(files)
                        }
                    })
        
        # 按分数排序
        candidates.sort(key=lambda x: x['score'], reverse=True)
        
        # 添加ID
        for i, c in enumerate(candidates, 1):
            c['id'] = i
        
        # 显示top候选
        self._print_candidates(candidates[:10])
        
        return candidates
    
    def _identify_vulnerability_type(self, message: str) -> str:
        """识别漏洞类型"""
        message_lower = message.lower()
        
        vuln_types = {
            'SQL Injection': ['sql injection', 'sqli', 'prepared statement'],
            'XSS': ['xss', 'cross-site scripting', 'cross site scripting'],
            'CSRF': ['csrf', 'cross-site request forgery'],
            'XXE': ['xxe', 'xml external entity'],
            'Authentication': ['authentication', 'auth bypass', 'login'],
            'Authorization': ['authorization', 'privilege', 'access control'],
            'Buffer Overflow': ['buffer overflow', 'buffer overrun'],
            'Path Traversal': ['path traversal', 'directory traversal'],
            'Command Injection': ['command injection', 'code injection'],
            'Deserialization': ['deserialization', 'unsafe deserialization'],
            'DoS': ['dos', 'denial of service', 'resource exhaustion'],
        }
        
        for vtype, keywords in vuln_types.items():
            if any(kw in message_lower for kw in keywords):
                return vtype
        
        return 'Unknown'
    
    def _save_candidates(self, candidates: List[Dict]) -> str:
        """保存候选BFC到JSON文件"""
        output_dir = os.path.join(os.path.dirname(__file__), 'integrated_results')
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = os.path.join(output_dir, 
                                   f"{self.repo_name}_candidates_{timestamp}.json")
        
        data = {
            'repository': self.repo_name,
            'scan_date': timestamp,
            'total_commits_scanned': len(list(self.repo.iter_commits('HEAD', max_count=500))),
            'candidates_found': len(candidates),
            'candidates': candidates
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        return output_file
    
    def _score_commit(self, commit) -> tuple:
        """
        给commit打分
        Returns: (score, reason)
        """
        message = commit.message.lower()
        score = 0
        reasons = []
        
        # 检查安全关键词
        for keyword in self.security_keywords['high']:
            if keyword in message:
                score += 10
                reasons.append(f"高优先级:{keyword}")
        
        for keyword in self.security_keywords['medium']:
            if keyword in message:
                score += 5
                reasons.append(f"中优先级:{keyword}")
        
        for keyword in self.security_keywords['low']:
            if keyword in message:
                score += 2
                reasons.append(f"低优先级:{keyword}")
        
        # 检查fix关键词
        if any(word in message for word in ['fix', 'patch', 'resolve']):
            if score > 0:  # 必须有安全关键词才加分
                score += 3
                reasons.append("修复类")
        
        # 检查代码模式
        try:
            if len(commit.parents) > 0:
                diffs = commit.diff(commit.parents[0], create_patch=True)
                for diff in diffs[:5]:  # 只检查前5个文件
                    if diff.diff:
                        try:
                            diff_text = diff.diff.decode('utf-8', errors='ignore')
                            # 简单模式检测
                            if re.search(r'preparedStatement|sanitize|escape|bcrypt', 
                                       diff_text, re.IGNORECASE):
                                score += 3
                                reasons.append("安全代码模式")
                                break
                        except:
                            pass
        except:
            pass
        
        return score, '; '.join(reasons)
    
    def _is_core_file(self, filepath: str) -> bool:
        """判断是否是核心代码文件（排除测试、文档等）"""
        exclude_patterns = [
            r'test', r'Test', r'README', r'CHANGELOG', 
            r'\.md$', r'\.txt$', r'\.yml$', r'\.yaml$',
            r'\.xml$', r'\.properties$'
        ]
        return not any(re.search(p, filepath) for p in exclude_patterns)
    
    def _verify_with_llm(self, candidates: List[Dict], max_verify: int) -> List[Dict]:
        """使用LLM验证BFC"""
        if not self.llm_client:
            print("❌ 错误：未配置LLM客户端")
            return []
        
        verified = []
        
        for i, candidate in enumerate(candidates[:max_verify], 1):
            print(f"  验证 {i}/{min(max_verify, len(candidates))}: {candidate['short_hash']}")
            
            # 构建简化prompt
            prompt = self._build_prompt(candidate)
            
            try:
                # 调用LLM
                response = self._call_llm(prompt)
                result = json.loads(response)
                
                if result.get('is_valid_bfc') and result.get('confidence', 0) >= 0.7:
                    candidate['llm_verified'] = True
                    candidate['confidence'] = result['confidence']
                    candidate['vulnerability_type'] = result.get('vulnerability_type')
                    candidate['cwe_id'] = result.get('cwe_id')
                    candidate['severity'] = result.get('severity')
                    candidate['vulnerability_description'] = result.get('vulnerability_description')
                    verified.append(candidate)
                    print(f"    ✓ 通过 (置信度: {result['confidence']:.2f}, 类型: {result.get('vulnerability_type', 'Unknown')})")
                else:
                    conf = result.get('confidence', 0)
                    print(f"    ✗ 未通过 (置信度: {conf:.2f})")
            except Exception as e:
                print(f"    ❌ LLM调用失败: {e}")
        
        return verified
    
    def _build_prompt(self, candidate: Dict) -> str:
        """构建LLM prompt"""
        return f"""分析以下commit是否是安全漏洞修复：

Commit: {candidate['commit_hash']}
Message: {candidate['message']}
Files: {', '.join(candidate['core_files'][:5])}
Score: {candidate['score']} ({candidate['reason']})

回答JSON格式：
{{"is_valid_bfc": true/false, "confidence": 0.0-1.0, "vulnerability_type": "类型"}}"""
    
    def _call_llm(self, prompt: str) -> str:
        """调用LLM"""
        if hasattr(self.llm_client, 'chat') and hasattr(self.llm_client.chat, 'completions'):
            # OpenAI
            response = self.llm_client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                response_format={"type": "json_object"}
            )
            return response.choices[0].message.content
        else:
            raise ValueError("不支持的LLM客户端")
    
    def _print_candidates(self, candidates: List[Dict]):
        """打印候选BFC"""
        if not candidates:
            return
        
        print(f"\n🔝 Top {len(candidates)} BFC候选:")
        for i, c in enumerate(candidates, 1):
            print(f"\n{i}. {c['short_hash']} (分数: {c['score']})")
            print(f"   {c['date']} | {c['author']}")
            print(f"   {c['message'][:70]}...")
            print(f"   原因: {c['reason']}")
            print(f"   核心文件: {len(c['core_files'])}")
    
    def _run_vszz_analysis(self, bfcs: List[Dict]) -> Dict:
        """运行V-SZZ分析"""
        if not self.vszz:
            print("❌ V-SZZ未初始化")
            return {}
        
        results = {}
        
        for i, bfc in enumerate(bfcs, 1):
            commit_hash = bfc['commit_hash']
            short_hash = bfc['short_hash']
            
            print(f"\n分析 {i}/{len(bfcs)}: {short_hash}")
            print(f"  消息: {bfc['message'][:60]}...")
            
            try:
                # 获取受影响的文件
                print(f"  → 获取受影响文件...")
                imp_files = self.vszz.get_impacted_files(
                    fix_commit_hash=commit_hash,
                    file_ext_to_parse=['c', 'java', 'cpp', 'h', 'hpp', 'py'],
                    only_deleted_lines=True
                )
                
                if not imp_files:
                    print(f"  ⚠️ 无受影响文件")
                    continue
                
                print(f"  → 受影响文件: {len(imp_files)}")
                
                # 查找BIC
                print(f"  → 查找BIC...")
                bics = self.vszz.find_bic(
                    fix_commit_hash=commit_hash,
                    impacted_files=imp_files
                )
                
                results[commit_hash] = bics
                
                if bics:
                    print(f"  ✓ 找到 {len(bics)} 个BIC候选")
                    # 显示前3个
                    for j, bic in enumerate(list(bics)[:3], 1):
                        print(f"      {j}. {bic[:8]}")
                else:
                    print(f"  ⚠️ 未找到BIC")
                
            except Exception as e:
                print(f"  ❌ 分析失败: {e}")
                import traceback
                traceback.print_exc()
        
        return results
    
    def _save_results(self, bfcs: List[Dict], results: Dict) -> str:
        """保存结果"""
        output_dir = os.path.join(os.path.dirname(__file__), 'integrated_results')
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = os.path.join(output_dir, 
                                   f"{self.repo_name}_{timestamp}.json")
        
        # 构建输出数据
        output_data = {
            'repository': {
                'name': self.repo_name,
                'path': self.repo_path
            },
            'analysis_info': {
                'timestamp': timestamp,
                'bfc_count': len(bfcs),
                'successful_analysis': len(results),
                'total_bics': sum(len(bics) for bics in results.values())
            },
            'bfcs': [],
            'bic_mapping': {}
        }
        
        # 添加BFC和BIC信息
        for bfc in bfcs:
            commit_hash = bfc['commit_hash']
            bics = results.get(commit_hash, [])
            
            output_data['bfcs'].append({
                'commit_hash': commit_hash,
                'short_hash': bfc['short_hash'],
                'date': bfc['date'],
                'author': bfc['author'],
                'message': bfc['message'],
                'score': bfc['score'],
                'reason': bfc['reason'],
                'llm_verified': bfc.get('llm_verified', False),
                'confidence': bfc.get('confidence'),
                'vulnerability_type': bfc.get('vulnerability_type'),
                'core_files': bfc['core_files'],
                'stats': bfc['stats'],
                'bic_count': len(bics)
            })
            
            if bics:
                output_data['bic_mapping'][commit_hash] = list(bics)
        
        # 保存JSON
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        # 生成可读报告
        report_file = output_file.replace('.json', '_report.txt')
        self._generate_report(output_data, report_file)
        
        return output_file
    
    def _generate_report(self, data: Dict, report_file: str):
        """生成可读报告"""
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write(f"V-SZZ 分析报告\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"仓库: {data['repository']['name']}\n")
            f.write(f"路径: {data['repository']['path']}\n")
            f.write(f"时间: {data['analysis_info']['timestamp']}\n\n")
            
            f.write("统计信息:\n")
            f.write(f"  BFC数量: {data['analysis_info']['bfc_count']}\n")
            f.write(f"  成功分析: {data['analysis_info']['successful_analysis']}\n")
            f.write(f"  总BIC数: {data['analysis_info']['total_bics']}\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("详细结果\n")
            f.write("=" * 80 + "\n\n")
            
            for i, bfc in enumerate(data['bfcs'], 1):
                f.write(f"{i}. BFC: {bfc['short_hash']}\n")
                f.write(f"   提交: {bfc['commit_hash']}\n")
                f.write(f"   日期: {bfc['date']}\n")
                f.write(f"   作者: {bfc['author']}\n")
                f.write(f"   消息: {bfc['message']}\n")
                f.write(f"   分数: {bfc['score']} ({bfc['reason']})\n")
                
                if bfc.get('llm_verified'):
                    f.write(f"   LLM验证: 是 (置信度: {bfc['confidence']})\n")
                    f.write(f"   漏洞类型: {bfc.get('vulnerability_type')}\n")
                
                f.write(f"   核心文件: {len(bfc['core_files'])}\n")
                for file in bfc['core_files'][:5]:
                    f.write(f"     - {file}\n")
                
                bics = data['bic_mapping'].get(bfc['commit_hash'], [])
                f.write(f"   BIC数量: {len(bics)}\n")
                for j, bic in enumerate(bics[:5], 1):
                    f.write(f"     {j}. {bic}\n")
                
                f.write("\n")


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='集成V-SZZ：自动识别BFC并分析',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 1. 完整分析（需要LLM）
  python integrated_vszz.py repo_path --openai-key sk-xxx
  
  # 2. 使用环境变量
  $env:OPENAI_API_KEY="sk-xxx"
  python integrated_vszz.py repo_path
  
  # 3. 只扫描，不分析（不需要LLM）
  python integrated_vszz.py repo_path --scan-only
  
  # 4. 分析指定commit
  python integrated_vszz.py repo_path --commit abc123 --openai-key sk-xxx
  
  # 5. 分析指定CVE
  python integrated_vszz.py repo_path --cve CVE-2023-1234 --openai-key sk-xxx
  
  # 6. 从扫描结果中选择分析
  python integrated_vszz.py repo_path --analyze-from candidates.json --ids 1,3,5 --openai-key sk-xxx
        """
    )
    
    parser.add_argument('repo_path', help='Git仓库路径')
    
    # 模式选择
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('--scan-only', action='store_true',
                           help='只扫描识别BFC，不运行V-SZZ')
    mode_group.add_argument('--commit', 
                           help='直接分析指定commit（可用逗号分隔多个）')
    mode_group.add_argument('--cve', 
                           help='分析指定CVE的fix commits（如 CVE-2023-1234）')
    mode_group.add_argument('--analyze-from', 
                           help='从JSON文件加载候选BFC')
    mode_group.add_argument('--interactive', action='store_true',
                           help='交互式选择模式')
    
    # 扫描参数
    parser.add_argument('--max-commits', type=int, default=500, 
                       help='最多扫描的提交数 (默认: 500)')
    parser.add_argument('--max-bfcs', type=int, default=10, 
                       help='最多分析的BFC数 (默认: 10)')
    parser.add_argument('--min-score', type=int, default=10, 
                       help='BFC最低分数 (默认: 10)')
    
    # 分析参数
    parser.add_argument('--ids', 
                       help='要分析的BFC ID（逗号分隔，如 1,3,5）')
    
    # LLM参数（必需）
    parser.add_argument('--openai-key', required=False,
                       help='OpenAI API Key (或设置环境变量 OPENAI_API_KEY)')
    
    args = parser.parse_args()
    
    # 配置LLM（强制要求，除了scan-only模式）
    llm_client = None
    if not args.scan_only:
        try:
            from openai import OpenAI
            if args.openai_key:
                llm_client = OpenAI(api_key=args.openai_key)
            else:
                llm_client = OpenAI()  # 使用环境变量
            print("✓ OpenAI客户端配置成功\n")
        except Exception as e:
            if not (args.scan_only or args.analyze_from):
                print(f"❌ LLM配置失败: {e}")
                print("\n本系统需要LLM验证BFC。请:")
                print("  1. 设置环境变量: $env:OPENAI_API_KEY='sk-your-key'")
                print("  2. 或使用参数: --openai-key sk-your-key")
                print("\n如果只想扫描候选，使用: --scan-only")
                sys.exit(1)
    
    # 创建分析器
    analyzer = IntegratedVSZZ(args.repo_path, llm_client)
    
    # 根据模式执行
    try:
        if args.scan_only:
            # 只扫描
            analyzer.scan_only(args.max_commits, args.min_score)
            
        elif args.commit:
            # 分析指定commit
            commits = [c.strip() for c in args.commit.split(',')]
            analyzer.analyze_specific_commits(commits)
            
        elif args.cve:
            # 分析指定CVE
            analyzer.analyze_by_cve(args.cve, args.max_commits)
            
        elif args.analyze_from:
            # 从文件加载
            ids = None
            if args.ids:
                ids = [int(x.strip()) for x in args.ids.split(',')]
            analyzer.analyze_from_file(args.analyze_from, ids)
            
        elif args.interactive:
            # 交互模式
            analyzer.interactive_mode(args.max_commits, args.min_score)
            
        else:
            # 默认：完整分析
            analyzer.analyze_repository(
                max_commits=args.max_commits,
                max_bfcs=args.max_bfcs,
                min_score=args.min_score
            )
    
    except KeyboardInterrupt:
        print("\n\n⚠️ 用户中断")
    except Exception as e:
        print(f"\n❌ 分析失败: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
