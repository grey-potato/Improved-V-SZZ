#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
LLM-Enhanced V-SZZ 运行示例
支持混合模式（AST/srcml + LLM）和纯LLM模式
"""

import os
import sys
import argparse

# 添加当前目录到路径
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

from llm_vszz import analyze_fix_commit, create_llm_enhanced_vszz


def main():
    parser = argparse.ArgumentParser(
        description='LLM-Enhanced V-SZZ: 使用大语言模型增强的漏洞引入提交追踪',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 使用混合模式分析（默认：AST/srcml + LLM）
  python run_llm_vszz.py /path/to/repo abc123def456
  
  # 使用纯LLM模式（不使用AST/srcml工具）
  python run_llm_vszz.py /path/to/repo abc123 --pure-llm
  
  # 指定API密钥
  python run_llm_vszz.py /path/to/repo abc123 --api-key sk-xxx
  
  # 使用自定义模型
  python run_llm_vszz.py /path/to/repo abc123 --large-model gpt-5.2 --small-model gpt-4.1-mini
  
  # 禁用缓存
  python run_llm_vszz.py /path/to/repo abc123 --no-cache

混合模式工作流程:
  1. Java文件 → AST工具(ASTMapEval.jar)分析 → LLM验证/增强
  2. C/C++文件 → srcml工具分析 → LLM验证/增强
  3. 其他文件 → 直接使用LLM分析
  4. 小LLM验证最终结果

环境变量:
  OPENAI_API_KEY: API密钥 (云雾API或OpenAI)
  OPENAI_BASE_URL: API基础URL (默认使用云雾API: https://yunwu.ai/v1)
        """
    )
    
    parser.add_argument('repo_path', help='Git仓库路径')
    parser.add_argument('fix_commit', help='修复提交的哈希值')
    
    parser.add_argument('--api-key', help='OpenAI API密钥 (或设置环境变量 OPENAI_API_KEY)')
    parser.add_argument('--base-url', default='https://yunwu.ai/v1',
                       help='API基础URL (默认: https://yunwu.ai/v1)')
    
    parser.add_argument('--large-model', default='gpt-5.1-codex',
                       help='大模型名称，用于追踪决策 (默认: gpt-5.1-codex)')
    parser.add_argument('--small-model', default='gpt-5-mini',
                       help='小模型名称，用于结果验证 (默认: gpt-5-mini)')
    
    # 混合模式相关参数
    parser.add_argument('--pure-llm', action='store_true',
                       help='使用纯LLM模式（不使用AST/srcml工具）')
    parser.add_argument('--ast-path', 
                       help='AST工具路径 (ASTMapEval.jar所在目录)')
    
    parser.add_argument('--no-cache', action='store_true',
                       help='禁用LLM响应缓存')
    parser.add_argument('--max-depth', type=int, default=30,
                       help='最大追踪深度 (默认: 30)')
    parser.add_argument('--max-iterations', type=int, default=3,
                       help='验证失败后最大重试次数 (默认: 3)')
    
    parser.add_argument('--output', '-o', help='输出结果到JSON文件')
    
    args = parser.parse_args()
    
    # 验证仓库路径
    if not os.path.exists(args.repo_path):
        print(f"❌ 仓库路径不存在: {args.repo_path}")
        sys.exit(1)
    
    if not os.path.exists(os.path.join(args.repo_path, '.git')):
        print(f"❌ 不是有效的Git仓库: {args.repo_path}")
        sys.exit(1)
    
    # 获取API密钥
    api_key = args.api_key or os.environ.get('OPENAI_API_KEY')
    if not api_key:
        print("❌ 未配置API密钥")
        print("   请使用 --api-key 参数或设置 OPENAI_API_KEY 环境变量")
        sys.exit(1)
    
    # 获取base_url（默认使用云雾API）
    base_url = args.base_url
    if base_url is None:
        base_url = os.environ.get('OPENAI_BASE_URL', 'https://yunwu.ai/v1')
    
    # 确定是否使用混合模式
    use_hybrid = not args.pure_llm
    
    # 确定AST工具路径
    ast_path = args.ast_path
    if ast_path is None and use_hybrid:
        # 默认使用当前目录下的 ASTMapEval_jar
        default_ast_path = os.path.join(current_dir, 'ASTMapEval_jar')
        if os.path.exists(default_ast_path):
            ast_path = default_ast_path
    
    try:
        # 运行分析
        results = analyze_fix_commit(
            repo_path=args.repo_path,
            fix_commit_hash=args.fix_commit,
            api_key=api_key,
            large_model=args.large_model,
            small_model=args.small_model,
            use_hybrid=use_hybrid,
            ast_map_path=ast_path
        )
        
        # 保存结果
        if args.output:
            import json
            output_data = []
            for r in results:
                output_data.append({
                    'fix_commit': r.fix_commit,
                    'bic_commit': r.bic_commit,
                    'verified': r.verified,
                    'iterations': r.iterations,
                    'tracking_chain': [
                        {
                            'commit_hash': s.commit_hash,
                            'commit_date': s.commit_date,
                            'commit_message': s.commit_message,
                            'file_path': s.file_path,
                            'line_num': s.line_num,
                            'change_type': s.change_type,
                            'reasoning': s.reasoning,
                            'confidence': s.confidence
                        }
                        for s in r.tracking_chain
                    ]
                })
            
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            print(f"\n💾 结果已保存到: {args.output}")
        
        print("\n✅ 分析完成!")
        
    except KeyboardInterrupt:
        print("\n\n⚠️ 用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ 分析失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
