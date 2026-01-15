#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
LLM 驱动的漏洞引入追踪工具

使用方式:
    # 基本用法
    python run.py <仓库路径> <修复提交> <漏洞文件> <漏洞代码关键词>
    
    # 示例
    python run.py C:/repos/activemq 729c4731 FilenameGuardFilter.java "guard"
    
    # 带 CVE 信息
    python run.py C:/repos/activemq 729c4731 FilenameGuardFilter.java "guard" --cve "CVE-2015-1830"
    
    # 指定输出文件
    python run.py C:/repos/activemq 729c4731 FilenameGuardFilter.java "guard" -o result.json
"""

import os
import sys
import json
import argparse

# 添加路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'icse2021-szz-replication-package', 'tools', 'pyszz'))

# 默认 API 配置
DEFAULT_API_KEY = 'sk-smMd7t4GCBkCgoPZkBTE7WzZeSSOAvSvTREm5jWOhSEpA3tw'
DEFAULT_BASE_URL = 'https://yunwu.ai/v1'
DEFAULT_LARGE_MODEL = 'gpt-5.1-codex'
DEFAULT_SMALL_MODEL = 'gpt-5-mini'


def setup_environment(args):
    """设置环境变量"""
    os.environ['OPENAI_API_KEY'] = args.api_key or DEFAULT_API_KEY
    os.environ['OPENAI_BASE_URL'] = args.base_url or DEFAULT_BASE_URL
    os.environ['LLM_MODEL'] = args.model or DEFAULT_LARGE_MODEL
    os.environ['SMALL_LLM_MODEL'] = args.small_model or DEFAULT_SMALL_MODEL


def find_file_in_commit(repo_path, commit_hash, filename_pattern):
    """在提交中查找匹配的文件"""
    import git
    repo = git.Repo(repo_path)
    commit = repo.commit(commit_hash)
    
    matches = []
    for diff in commit.diff(commit.parents[0] if commit.parents else None):
        path = diff.a_path or diff.b_path
        if path and filename_pattern.lower() in path.lower():
            matches.append(path)
    
    return matches


def find_vulnerable_line(repo_path, commit_hash, file_path, keyword):
    """在修复提交的 diff 中查找包含关键词的删除行"""
    import git
    repo = git.Repo(repo_path)
    commit = repo.commit(commit_hash)
    
    if not commit.parents:
        return None
    
    diff = repo.git.diff(commit.parents[0].hexsha, commit.hexsha, '--', file_path, unified=3)
    
    # 查找删除的行（漏洞代码通常在删除行中）
    for line in diff.split('\n'):
        if line.startswith('-') and not line.startswith('---'):
            if keyword.lower() in line.lower():
                return line[1:].strip()  # 去掉 '-' 前缀
    
    # 如果没找到删除行，查找修改的行
    for line in diff.split('\n'):
        if keyword.lower() in line.lower():
            clean_line = line.lstrip('+-')
            return clean_line.strip()
    
    return None


def main():
    parser = argparse.ArgumentParser(
        description='LLM 驱动的漏洞引入追踪工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 基本用法
  python run.py C:/repos/activemq 729c4731 FilenameGuardFilter.java "guard"
  
  # 带 CVE 信息（提高准确性）
  python run.py C:/repos/activemq 729c4731 FilenameGuardFilter.java "guard" --cve "CVE-2015-1830 (CWE-22)"
  
  # 输出到文件
  python run.py C:/repos/activemq 729c4731 FilenameGuardFilter.java "guard" -o result.json
  
  # 禁用验证（更快但可能不准）
  python run.py C:/repos/activemq 729c4731 FilenameGuardFilter.java "guard" --no-validate
        """
    )
    
    # 必需参数
    parser.add_argument('repo', help='Git 仓库路径')
    parser.add_argument('commit', help='修复提交哈希（完整或前缀）')
    parser.add_argument('file', help='漏洞文件名或路径（支持部分匹配）')
    parser.add_argument('keyword', help='漏洞代码关键词（用于定位漏洞行）')
    
    # 可选参数
    parser.add_argument('--cve', help='CVE 信息，如 "CVE-2015-1830 (CWE-22)"')
    parser.add_argument('-o', '--output', help='输出 JSON 文件路径')
    parser.add_argument('--no-validate', action='store_true', help='禁用小模型验证')
    parser.add_argument('--max-depth', type=int, default=50, help='最大追踪深度 (默认: 50)')
    
    # API 配置
    parser.add_argument('--api-key', help='API 密钥')
    parser.add_argument('--base-url', help='API 基础 URL')
    parser.add_argument('--model', help=f'大模型名称 (默认: {DEFAULT_LARGE_MODEL})')
    parser.add_argument('--small-model', help=f'小模型名称 (默认: {DEFAULT_SMALL_MODEL})')
    
    args = parser.parse_args()
    
    # 设置环境
    setup_environment(args)
    
    # 验证仓库路径
    if not os.path.isdir(args.repo):
        print(f"❌ 错误: 仓库路径不存在: {args.repo}")
        sys.exit(1)
    
    if not os.path.isdir(os.path.join(args.repo, '.git')):
        print(f"❌ 错误: 不是有效的 Git 仓库: {args.repo}")
        sys.exit(1)
    
    print("="*70)
    print("🔍 LLM 驱动的漏洞引入追踪")
    print("="*70)
    print()
    
    # 查找文件
    print(f"📂 仓库: {args.repo}")
    print(f"🔧 修复提交: {args.commit}")
    print(f"📄 查找文件: {args.file}")
    
    file_matches = find_file_in_commit(args.repo, args.commit, args.file)
    
    if not file_matches:
        print(f"❌ 错误: 在提交 {args.commit} 中未找到匹配 '{args.file}' 的文件")
        sys.exit(1)
    
    if len(file_matches) > 1:
        print(f"\n⚠️ 找到多个匹配文件:")
        for i, f in enumerate(file_matches, 1):
            print(f"   {i}. {f}")
        print(f"\n使用第一个: {file_matches[0]}")
    
    file_path = file_matches[0]
    print(f"   → 匹配文件: {file_path}")
    
    # 查找漏洞代码行
    print(f"\n🔎 查找包含 '{args.keyword}' 的漏洞代码...")
    vulnerable_line = find_vulnerable_line(args.repo, args.commit, file_path, args.keyword)
    
    if vulnerable_line:
        print(f"   → 找到: {vulnerable_line[:80]}{'...' if len(vulnerable_line) > 80 else ''}")
    else:
        vulnerable_line = args.keyword  # 使用关键词作为后备
        print(f"   → 未找到精确匹配，使用关键词: {args.keyword}")
    
    # 导入并运行
    print(f"\n{'='*70}")
    print("🚀 开始追踪...")
    print("="*70)
    
    from szz.llm_driven_szz import LLMDrivenSZZ
    
    szz = LLMDrivenSZZ(
        args.repo, 
        enable_validation=not args.no_validate,
        max_depth=args.max_depth
    )
    
    result = szz.find_vulnerability_introduction(
        fix_commit_hash=args.commit,
        file_path=file_path,
        vulnerable_line=vulnerable_line,
        cve_info=args.cve or "未知漏洞"
    )
    
    # 输出结果
    print("\n" + "="*70)
    print("📋 追踪结果")
    print("="*70)
    
    intro_commit = result.get('introduction_commit')
    if intro_commit:
        print(f"\n✅ 漏洞引入提交: {intro_commit}")
        if result.get('introduction_message'):
            msg = result['introduction_message']
            print(f"   提交消息: {msg[:60]}{'...' if len(msg) > 60 else ''}")
        if result.get('introduction_date'):
            print(f"   提交日期: {result['introduction_date']}")
    else:
        print("\n⚠️ 未能确定漏洞引入提交")
    
    print(f"\n📊 统计:")
    print(f"   LLM 调用次数: {result.get('llm_calls', 0)}")
    print(f"   验证调用次数: {result.get('validation_calls', 0)}")
    print(f"   分析提交数: {result.get('commits_analyzed', 0)}")
    
    # 保存结果
    if args.output:
        output_path = args.output
    else:
        os.makedirs('results', exist_ok=True)
        repo_name = os.path.basename(args.repo.rstrip('/\\'))
        output_path = f"results/{repo_name}-{args.commit[:8]}.json"
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False, default=str)
    
    print(f"\n💾 详细结果已保存到: {output_path}")
    
    return result


if __name__ == "__main__":
    main()
