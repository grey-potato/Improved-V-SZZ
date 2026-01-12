#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
阶段1使用示例
演示如何使用新的BFC识别和验证模块
"""

import os
from stage1_bfc_analysis import Stage1BFCAnalysis


def example_without_llm():
    """
    示例1：不使用LLM（基于规则）
    适合快速测试或没有LLM API的情况
    """
    print("=" * 80)
    print("示例1：基于规则的BFC识别（不使用LLM）")
    print("=" * 80)
    
    # 使用现有的某个项目仓库
    repo_path = r'c:\Users\lxp\Desktop\V-SZZ-main\repos\activemq'
    
    if not os.path.exists(repo_path):
        print(f"❌ 仓库不存在: {repo_path}")
        print("   请先克隆一个仓库进行测试")
        return
    
    # 创建分析器（不传入LLM客户端）
    analyzer = Stage1BFCAnalysis(repo_path, llm_client=None)
    
    # 执行分析
    result = analyzer.analyze(
        max_commits=200,     # 扫描最近200个提交
        max_verify=10,       # 验证前10个候选
        min_confidence=0.5,  # 较低的阈值（因为没有LLM）
        export_results=True
    )
    
    # 获取BFC列表
    bfc_commits = [bfc['commit_hash'] for bfc in result['final_bfcs']]
    
    print(f"\n✓ 识别到 {len(bfc_commits)} 个BFC:")
    for commit in bfc_commits[:5]:  # 显示前5个
        print(f"  - {commit}")
    
    return result


def example_with_openai():
    """
    示例2：使用OpenAI进行LLM验证
    需要配置OPENAI_API_KEY环境变量
    """
    print("=" * 80)
    print("示例2：使用OpenAI LLM验证BFC")
    print("=" * 80)
    
    repo_path = r'c:\Users\lxp\Desktop\V-SZZ-main\repos\activemq'
    
    if not os.path.exists(repo_path):
        print(f"❌ 仓库不存在: {repo_path}")
        return
    
    # 配置OpenAI
    try:
        from openai import OpenAI
        llm_client = OpenAI()  # 需要设置环境变量 OPENAI_API_KEY
        print("✓ OpenAI客户端配置成功")
    except ImportError:
        print("❌ 请安装OpenAI: pip install openai")
        return
    except Exception as e:
        print(f"❌ OpenAI配置失败: {e}")
        print("   请设置环境变量: OPENAI_API_KEY")
        return
    
    # 创建分析器
    analyzer = Stage1BFCAnalysis(repo_path, llm_client)
    
    # 执行分析
    result = analyzer.analyze(
        max_commits=200,
        max_verify=5,        # LLM验证成本较高，少验证几个
        min_confidence=0.7,  # 可以使用更高的阈值
        export_results=True
    )
    
    return result


def example_custom_workflow():
    """
    示例3：自定义工作流程
    分步骤执行，可以在中间检查结果
    """
    print("=" * 80)
    print("示例3：自定义工作流程")
    print("=" * 80)
    
    from bfc_identifier import BFCIdentifier
    from llm_bfc_verifier import LLMBFCVerifier
    
    repo_path = r'c:\Users\lxp\Desktop\V-SZZ-main\repos\activemq'
    
    if not os.path.exists(repo_path):
        print(f"❌ 仓库不存在: {repo_path}")
        return
    
    # 步骤1：识别候选
    print("\n步骤1：识别候选BFC...")
    identifier = BFCIdentifier(repo_path)
    candidates = identifier.find_candidate_bfcs(max_commits=100)
    candidates = identifier.filter_by_files(candidates)
    
    print(f"找到 {len(candidates)} 个候选")
    
    # 检查候选
    identifier.print_summary(candidates, top_n=5)
    
    # 步骤2：手动筛选（可选）
    print("\n步骤2：筛选高分候选...")
    high_score = [c for c in candidates if c['total_score'] >= 15]
    print(f"高分候选: {len(high_score)} 个")
    
    # 步骤3：验证
    print("\n步骤3：验证候选...")
    verifier = LLMBFCVerifier(repo_path, llm_client=None)
    verified = verifier.verify_batch(high_score, max_verify=5)
    
    # 步骤4：导出
    verifier.export_verified_bfcs(verified)
    
    return verified


def example_integrate_with_vszz():
    """
    示例4：与V-SZZ集成
    演示如何将识别的BFC传递给V-SZZ
    """
    print("=" * 80)
    print("示例4：与V-SZZ集成")
    print("=" * 80)
    
    repo_path = r'c:\Users\lxp\Desktop\V-SZZ-main\repos\activemq'
    
    if not os.path.exists(repo_path):
        print(f"❌ 仓库不存在: {repo_path}")
        return
    
    # 阶段1：识别BFC
    print("\n【阶段1】识别和验证BFC...")
    analyzer = Stage1BFCAnalysis(repo_path, llm_client=None)
    bfc_commits = analyzer.get_bfc_commits()
    
    print(f"✓ 识别到 {len(bfc_commits)} 个BFC")
    
    if not bfc_commits:
        print("❌ 未找到BFC，无法继续")
        return
    
    # 阶段2：运行V-SZZ
    print("\n【阶段2】运行V-SZZ分析...")
    
    # 导入V-SZZ
    import sys
    sys.path.append(os.path.join(os.path.dirname(__file__), 
                                  'icse2021-szz-replication-package/tools/pyszz/'))
    
    try:
        from szz.my_szz import MySZZ
        
        # 创建V-SZZ实例
        my_szz = MySZZ(
            repo_full_name='activemq',
            repo_url=None,
            repos_dir=os.path.dirname(repo_path),
            use_temp_dir=False,
            ast_map_path=r'c:\Users\lxp\Desktop\V-SZZ-main\ICSE2022ReplicationPackage\ASTMapEval_jar'
        )
        
        # 对每个BFC运行V-SZZ
        results = {}
        for i, commit in enumerate(bfc_commits[:2], 1):  # 测试前2个
            print(f"\n处理 {i}/{min(2, len(bfc_commits))}: {commit[:8]}")
            
            try:
                # 获取受影响的文件
                imp_files = my_szz.get_impacted_files(
                    fix_commit_hash=commit,
                    file_ext_to_parse=['c', 'java', 'cpp', 'h', 'hpp'],
                    only_deleted_lines=True
                )
                
                # 查找BIC
                bics = my_szz.find_bic(
                    fix_commit_hash=commit,
                    impacted_files=imp_files
                )
                
                results[commit] = bics
                print(f"  ✓ 找到 {len(bics)} 个BIC候选")
                
            except Exception as e:
                print(f"  ❌ 分析失败: {e}")
        
        print(f"\n✓ V-SZZ分析完成，共处理 {len(results)} 个BFC")
        
        return results
        
    except ImportError as e:
        print(f"❌ 无法导入V-SZZ: {e}")
        print("   请确保V-SZZ模块可用")


def main():
    """主函数"""
    print("\n选择示例:")
    print("1. 基于规则的BFC识别（不使用LLM）")
    print("2. 使用OpenAI LLM验证")
    print("3. 自定义工作流程")
    print("4. 与V-SZZ集成")
    print("5. 运行所有示例")
    
    choice = input("\n请选择 (1-5): ").strip()
    
    if choice == '1':
        example_without_llm()
    elif choice == '2':
        example_with_openai()
    elif choice == '3':
        example_custom_workflow()
    elif choice == '4':
        example_integrate_with_vszz()
    elif choice == '5':
        print("\n运行所有示例...\n")
        example_without_llm()
        print("\n" + "-" * 80 + "\n")
        example_custom_workflow()
        print("\n" + "-" * 80 + "\n")
        example_integrate_with_vszz()
    else:
        print("无效的选择")


if __name__ == '__main__':
    main()
