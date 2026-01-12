#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
快速分析脚本
简化的命令行接口 - 需要OpenAI API Key
"""

import os
import sys
from integrated_vszz import IntegratedVSZZ


def analyze_repo(repo_path, openai_key=None, max_commits=300, max_bfcs=5):
    """
    快速分析一个仓库
    
    Args:
        repo_path: 仓库路径
        openai_key: OpenAI API密钥
        max_commits: 扫描提交数
        max_bfcs: 分析BFC数
    """
    if not os.path.exists(repo_path):
        print(f"❌ 仓库不存在: {repo_path}")
        return None
    
    # 配置LLM
    try:
        from openai import OpenAI
        if openai_key:
            llm_client = OpenAI(api_key=openai_key)
        else:
            llm_client = OpenAI()  # 使用环境变量
        print("✓ OpenAI配置成功\n")
    except Exception as e:
        print(f"❌ OpenAI配置失败: {e}")
        print("\n请配置API Key:")
        print("  方法1: 设置环境变量")
        print("    $env:OPENAI_API_KEY='sk-your-key'")
        print("  方法2: 命令行参数")
        print("    python quick_analyze.py repo_path sk-your-key")
        return None
    
    print(f"\n分析仓库: {os.path.basename(repo_path)}")
    print(f"扫描: {max_commits} 个提交")
    print(f"LLM验证: 前 {max_bfcs} 个候选")
    print(f"模式: LLM验证 → V-SZZ分析\n")
    
    # 创建分析器
    analyzer = IntegratedVSZZ(repo_path, llm_client)
    
    # 执行分析
    result = analyzer.analyze_repository(
        max_commits=max_commits,
        max_bfcs=max_bfcs,
        min_score=10
    )
    
    return result


def main():
    """主函数"""
    if len(sys.argv) < 2:
        print("快速分析工具（需要LLM验证）")
        print("\n用法:")
        print("  python quick_analyze.py <仓库路径> [OpenAI-Key]")
        print("  python quick_analyze.py <仓库路径> [OpenAI-Key] <扫描数> <分析数>")
        print("\n示例:")
        print("  # 使用环境变量中的API Key")
        print("  python quick_analyze.py ../repos/activemq")
        print("\n  # 指定API Key")
        print("  python quick_analyze.py ../repos/activemq sk-xxx")
        print("\n  # 自定义参数")
        print("  python quick_analyze.py ../repos/activemq sk-xxx 500 10")
        print("\n配置环境变量:")
        print("  $env:OPENAI_API_KEY='sk-your-key'")
        sys.exit(1)
    
    repo_path = sys.argv[1]
    openai_key = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2].startswith('sk-') else None
    
    # 如果第二个参数是API key，从第3个参数开始是数字参数
    if openai_key:
        max_commits = int(sys.argv[3]) if len(sys.argv) > 3 else 300
        max_bfcs = int(sys.argv[4]) if len(sys.argv) > 4 else 5
    else:
        max_commits = int(sys.argv[2]) if len(sys.argv) > 2 else 300
        max_bfcs = int(sys.argv[3]) if len(sys.argv) > 3 else 5
    
    result = analyze_repo(repo_path, openai_key, max_commits, max_bfcs)
    
    if result:
        print("\n" + "=" * 80)
        print("✅ 分析完成！")
        print("=" * 80)
        print(f"\n查看结果:")
        print(f"  JSON: {result['output_file']}")
        print(f"  报告: {result['output_file'].replace('.json', '_report.txt')}")


if __name__ == '__main__':
    main()
