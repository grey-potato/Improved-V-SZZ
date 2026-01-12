#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
阶段1：BFC识别和验证的完整流程
整合BFC识别器和LLM验证器
"""

import sys
import os
import json
from bfc_identifier import BFCIdentifier
from llm_bfc_verifier import LLMBFCVerifier


class Stage1BFCAnalysis:
    """
    阶段1完整分析流程：
    1. 自动识别候选BFC
    2. LLM验证和精化
    3. 输出高质量的BFC列表供V-SZZ使用
    """
    
    def __init__(self, repo_path: str, llm_client=None):
        """
        初始化阶段1分析
        
        Args:
            repo_path: Git仓库路径
            llm_client: LLM客户端（可选）
        """
        self.repo_path = repo_path
        self.identifier = BFCIdentifier(repo_path)
        self.verifier = LLMBFCVerifier(repo_path, llm_client)
        self.llm_client = llm_client
    
    def analyze(self, 
                max_commits: int = 500,
                max_verify: int = 20,
                min_confidence: float = 0.7,
                export_results: bool = True) -> dict:
        """
        执行完整的阶段1分析
        
        Args:
            max_commits: 最多扫描的提交数
            max_verify: 最多LLM验证数
            min_confidence: 最低置信度阈值
            export_results: 是否导出结果
            
        Returns:
            分析结果字典
        """
        print("=" * 80)
        print("🚀 阶段1：BFC识别和验证")
        print("=" * 80)
        
        # 步骤1：识别候选BFC
        print("\n【步骤1/3】识别候选BFC...")
        candidates = self.identifier.find_candidate_bfcs(max_commits=max_commits)
        
        # 过滤文件
        candidates = self.identifier.filter_by_files(candidates)
        
        self.identifier.print_summary(candidates, top_n=10)
        
        if not candidates:
            print("❌ 未找到候选BFC，分析结束")
            return {'candidates': [], 'verified': [], 'final_bfcs': []}
        
        # 步骤2：LLM验证
        print("\n【步骤2/3】LLM验证BFC...")
        
        if self.llm_client is None:
            print("⚠️ 警告：未配置LLM客户端，将使用基于规则的验证")
            print("   建议配置LLM以获得更准确的结果")
        
        verified = self.verifier.verify_batch(candidates, max_verify=max_verify)
        
        self.verifier.print_verification_summary(verified)
        
        # 步骤3：过滤最终BFC
        print("\n【步骤3/3】生成最终BFC列表...")
        
        final_bfcs = [
            v for v in verified 
            if v['is_valid_bfc'] and v['confidence'] >= min_confidence
        ]
        
        print(f"✓ 最终确认 {len(final_bfcs)} 个BFC（置信度 >= {min_confidence}）")
        
        # 导出结果
        if export_results:
            self._export_all_results(candidates, verified, final_bfcs)
        
        # 构建结果
        result = {
            'repo_path': self.repo_path,
            'statistics': {
                'total_scanned': max_commits,
                'candidates_found': len(candidates),
                'verified_count': len(verified),
                'final_bfcs': len(final_bfcs)
            },
            'candidates': candidates,
            'verified': verified,
            'final_bfcs': final_bfcs
        }
        
        return result
    
    def _export_all_results(self, candidates, verified, final_bfcs):
        """导出所有结果"""
        base_dir = os.path.dirname(self.repo_path)
        
        # 候选BFC
        candidates_file = os.path.join(base_dir, 'stage1_candidates.json')
        with open(candidates_file, 'w', encoding='utf-8') as f:
            json.dump(candidates, f, indent=2, ensure_ascii=False)
        print(f"\n💾 候选BFC: {candidates_file}")
        
        # 验证结果
        verified_file = os.path.join(base_dir, 'stage1_verified.json')
        with open(verified_file, 'w', encoding='utf-8') as f:
            json.dump(verified, f, indent=2, ensure_ascii=False)
        print(f"💾 验证结果: {verified_file}")
        
        # 最终BFC
        final_file = os.path.join(base_dir, 'stage1_final_bfcs.json')
        with open(final_file, 'w', encoding='utf-8') as f:
            json.dump(final_bfcs, f, indent=2, ensure_ascii=False)
        print(f"💾 最终BFC: {final_file}")
        
        # 生成V-SZZ兼容格式
        vszz_format = self._convert_to_vszz_format(final_bfcs)
        vszz_file = os.path.join(base_dir, 'stage1_vszz_input.json')
        with open(vszz_file, 'w', encoding='utf-8') as f:
            json.dump(vszz_format, f, indent=2, ensure_ascii=False)
        print(f"💾 V-SZZ输入: {vszz_file}")
    
    def _convert_to_vszz_format(self, final_bfcs):
        """
        转换为V-SZZ兼容的格式
        类似于现有的label.json结构
        """
        project_name = os.path.basename(self.repo_path)
        
        result = {
            project_name: {}
        }
        
        for i, bfc in enumerate(final_bfcs, 1):
            # 使用索引或CVE ID作为key
            cve_key = bfc.get('cve_id') or f"AUTO-{i:03d}"
            
            result[project_name][cve_key] = {
                'cwe': bfc.get('cwe_id', 'Unknown'),
                'vulnerability_type': bfc.get('vulnerability_type', 'Unknown'),
                'severity': bfc.get('severity', 'Unknown'),
                'fixing_commits': {
                    bfc['commit_hash']: {
                        'confidence': bfc['confidence'],
                        'description': bfc.get('vulnerability_description', ''),
                        'core_files': bfc.get('core_fix_files', []),
                        'date': bfc.get('date', ''),
                        'author': bfc.get('author', '')
                    }
                }
            }
        
        return result
    
    def get_bfc_commits(self) -> list:
        """
        获取BFC提交列表（供V-SZZ使用）
        """
        result = self.analyze(export_results=False)
        return [bfc['commit_hash'] for bfc in result['final_bfcs']]


def main():
    """主函数"""
    if len(sys.argv) < 2:
        print("用法: python stage1_bfc_analysis.py <仓库路径> [LLM配置]")
        print("\n示例:")
        print("  python stage1_bfc_analysis.py /path/to/repo")
        print("  python stage1_bfc_analysis.py /path/to/repo --use-openai")
        sys.exit(1)
    
    repo_path = sys.argv[1]
    
    # 检查是否配置LLM
    llm_client = None
    if len(sys.argv) > 2 and sys.argv[2] == '--use-openai':
        try:
            from openai import OpenAI
            llm_client = OpenAI()  # 需要设置OPENAI_API_KEY环境变量
            print("✓ 已配置OpenAI客户端")
        except ImportError:
            print("❌ 无法导入openai，请安装: pip install openai")
        except Exception as e:
            print(f"❌ OpenAI配置错误: {e}")
    
    # 创建分析器
    analyzer = Stage1BFCAnalysis(repo_path, llm_client)
    
    # 执行分析
    result = analyzer.analyze(
        max_commits=500,
        max_verify=20,
        min_confidence=0.7
    )
    
    # 显示最终结果
    print("\n" + "=" * 80)
    print("✅ 阶段1分析完成")
    print("=" * 80)
    print(f"\n📊 统计:")
    print(f"  扫描提交: {result['statistics']['total_scanned']}")
    print(f"  候选BFC: {result['statistics']['candidates_found']}")
    print(f"  验证数量: {result['statistics']['verified_count']}")
    print(f"  最终BFC: {result['statistics']['final_bfcs']}")
    
    if result['final_bfcs']:
        print(f"\n✨ 成功识别 {len(result['final_bfcs'])} 个安全修复提交!")
        print("   可以继续进行阶段2（V-SZZ分析）")
    else:
        print("\n⚠️ 未找到高置信度的BFC")
        print("   建议：")
        print("   1. 降低置信度阈值")
        print("   2. 增加扫描的提交数量")
        print("   3. 配置LLM以获得更准确的验证")


if __name__ == '__main__':
    main()
