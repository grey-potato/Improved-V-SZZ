#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
LLM 驱动的漏洞引入追踪工具

使用方式:
    # 运行所有已克隆仓库的所有 CVE
    python run.py
    
    # 运行单个仓库的所有 CVE
    python run.py activemq
    
    # 运行单个仓库的单个 CVE
    python run.py activemq CVE-2015-1830
    
    # 运行单个仓库的单个提交
    python run.py activemq --commit 729c4731574f
"""

import os
import sys
import json
import argparse
from datetime import datetime

# 添加路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'icse2021-szz-replication-package', 'tools', 'pyszz'))

# 默认配置
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPOS_DIR = os.path.join(os.path.dirname(SCRIPT_DIR), 'repos')
LABEL_FILE = os.path.join(SCRIPT_DIR, 'data', 'label.json')
RESULTS_DIR = os.path.join(SCRIPT_DIR, 'results')

DEFAULT_API_KEY = 'sk-smMd7t4GCBkCgoPZkBTE7WzZeSSOAvSvTREm5jWOhSEpA3tw'
DEFAULT_BASE_URL = 'https://yunwu.ai/v1'
DEFAULT_LARGE_MODEL = 'gpt-5.1-codex'
DEFAULT_SMALL_MODEL = 'gpt-5-mini'


def setup_environment(args):
    """设置环境变量"""
    os.environ['OPENAI_API_KEY'] = getattr(args, 'api_key', None) or DEFAULT_API_KEY
    os.environ['OPENAI_BASE_URL'] = getattr(args, 'base_url', None) or DEFAULT_BASE_URL
    os.environ['LLM_MODEL'] = getattr(args, 'model', None) or DEFAULT_LARGE_MODEL
    os.environ['SMALL_LLM_MODEL'] = getattr(args, 'small_model', None) or DEFAULT_SMALL_MODEL


def load_labels():
    """加载标注数据"""
    if not os.path.exists(LABEL_FILE):
        print(f"❌ 标注文件不存在: {LABEL_FILE}")
        return {}
    
    with open(LABEL_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)


def get_available_repos():
    """获取已克隆的仓库列表"""
    if not os.path.exists(REPOS_DIR):
        return []
    
    repos = []
    for name in os.listdir(REPOS_DIR):
        repo_path = os.path.join(REPOS_DIR, name)
        if os.path.isdir(repo_path) and os.path.isdir(os.path.join(repo_path, '.git')):
            repos.append(name)
    return repos


def get_vulnerable_line(repo_path, fix_commit, file_path, line_num):
    """从仓库获取漏洞代码行"""
    import git
    try:
        repo = git.Repo(repo_path)
        commit = repo.commit(fix_commit)
        if commit.parents:
            parent = commit.parents[0]
            content = repo.git.show(f'{parent.hexsha}:{file_path}')
            lines = content.split('\n')
            if 0 < int(line_num) <= len(lines):
                return lines[int(line_num) - 1].strip()
    except Exception as e:
        pass
    return None


def analyze_single_case(szz, repo_name, cve_id, cwe, fix_commit, file_path, line_num, expected_vic):
    """分析单个漏洞用例"""
    repo_path = os.path.join(REPOS_DIR, repo_name)
    
    # 获取漏洞代码行
    vulnerable_line = get_vulnerable_line(repo_path, fix_commit, file_path, line_num)
    if not vulnerable_line:
        vulnerable_line = f"line {line_num}"
    
    print(f"\n{'='*70}")
    print(f"📋 {cve_id} ({cwe})")
    print(f"   修复提交: {fix_commit[:12]}")
    print(f"   文件: {file_path}")
    print(f"   行号: {line_num}")
    print(f"   期望VIC: {expected_vic[:12] if expected_vic else 'N/A'}")
    print(f"   漏洞代码: {vulnerable_line[:60]}...")
    print("="*70)
    
    try:
        result = szz.find_vulnerability_introduction(
            fix_commit_hash=fix_commit,
            file_path=file_path,
            vulnerable_line=vulnerable_line,
            cve_info=f"{cve_id} ({cwe})"
        )
        
        found_vic = result.get('introduction_commit', '')
        is_correct = expected_vic and found_vic and found_vic.startswith(expected_vic[:12])
        
        return {
            'cve': cve_id,
            'cwe': cwe,
            'fix_commit': fix_commit,
            'file_path': file_path,
            'line_num': line_num,
            'expected_vic': expected_vic,
            'found_vic': found_vic,
            'is_correct': is_correct,
            'llm_calls': result.get('llm_calls', 0),
            'validation_calls': result.get('validation_calls', 0),
            'result': result
        }
    except Exception as e:
        print(f"   ❌ 分析失败: {e}")
        return {
            'cve': cve_id,
            'error': str(e),
            'is_correct': False
        }


def run_repo(repo_name, labels, args, cve_filter=None):
    """运行单个仓库的分析"""
    from szz.llm_driven_szz import LLMDrivenSZZ
    
    repo_path = os.path.join(REPOS_DIR, repo_name)
    if not os.path.exists(repo_path):
        print(f"❌ 仓库不存在: {repo_path}")
        return []
    
    if repo_name not in labels:
        print(f"❌ 仓库 {repo_name} 没有标注数据")
        return []
    
    repo_labels = labels[repo_name]
    
    # 过滤 CVE
    if cve_filter:
        if cve_filter not in repo_labels:
            print(f"❌ {repo_name} 中不存在 {cve_filter}")
            return []
        repo_labels = {cve_filter: repo_labels[cve_filter]}
    
    print(f"\n{'#'*70}")
    print(f"# 仓库: {repo_name}")
    print(f"# CVE 数量: {len(repo_labels)}")
    print(f"{'#'*70}")
    
    szz = LLMDrivenSZZ(
        repo_path,
        enable_validation=not getattr(args, 'no_validate', False),
        max_history_depth=getattr(args, 'max_depth', 50)
    )
    
    results = []
    
    for cve_id, cve_data in repo_labels.items():
        cwe = cve_data.get('cwe', 'Unknown')
        fixing_commits = cve_data.get('fixing_commits', {})
        
        for fix_commit, files in fixing_commits.items():
            for file_path, lines in files.items():
                for line_num, line_data in lines.items():
                    vic_list = line_data.get('Vulnerability Introducing Commit', [])
                    expected_vic = vic_list[0] if vic_list else None
                    
                    # 跳过没有 VIC 标注的
                    if not expected_vic:
                        continue
                    
                    case_result = analyze_single_case(
                        szz, repo_name, cve_id, cwe,
                        fix_commit, file_path, line_num, expected_vic
                    )
                    results.append(case_result)
    
    return results


def run_single_commit(repo_name, commit_hash, args):
    """运行单个提交的分析"""
    from szz.llm_driven_szz import LLMDrivenSZZ
    import git
    
    repo_path = os.path.join(REPOS_DIR, repo_name)
    if not os.path.exists(repo_path):
        print(f"❌ 仓库不存在: {repo_path}")
        return None
    
    print(f"\n{'#'*70}")
    print(f"# 仓库: {repo_name}")
    print(f"# 修复提交: {commit_hash}")
    print(f"{'#'*70}")
    
    # 获取提交中修改的文件
    repo = git.Repo(repo_path)
    try:
        commit = repo.commit(commit_hash)
    except Exception as e:
        print(f"❌ 无法找到提交: {commit_hash}")
        return None
    
    if not commit.parents:
        print(f"❌ 该提交没有父提交")
        return None
    
    # 列出修改的文件
    diffs = commit.diff(commit.parents[0])
    files = []
    for diff in diffs:
        path = diff.a_path or diff.b_path
        if path and path.endswith(('.java', '.c', '.cpp', '.py', '.js', '.php')):
            files.append(path)
    
    if not files:
        print(f"⚠️ 未找到代码文件，列出所有修改:")
        for diff in diffs:
            print(f"   - {diff.a_path or diff.b_path}")
        return None
    
    print(f"\n📄 修改的代码文件:")
    for i, f in enumerate(files, 1):
        print(f"   {i}. {f}")
    
    # 让用户选择或自动选择第一个
    selected_file = files[0]
    print(f"\n→ 分析文件: {selected_file}")
    
    # 获取 diff 中的关键行
    diff_text = repo.git.diff(commit.parents[0].hexsha, commit.hexsha, '--', selected_file)
    
    # 找第一个删除的代码行作为漏洞代码
    vulnerable_line = None
    for line in diff_text.split('\n'):
        if line.startswith('-') and not line.startswith('---'):
            content = line[1:].strip()
            if content and len(content) > 5:  # 忽略太短的行
                vulnerable_line = content
                break
    
    if not vulnerable_line:
        vulnerable_line = "unknown vulnerability"
    
    print(f"→ 漏洞代码: {vulnerable_line[:60]}...")
    
    szz = LLMDrivenSZZ(
        repo_path,
        enable_validation=not getattr(args, 'no_validate', False),
        max_history_depth=getattr(args, 'max_depth', 50)
    )
    
    result = szz.find_vulnerability_introduction(
        fix_commit_hash=commit_hash,
        file_path=selected_file,
        vulnerable_line=vulnerable_line,
        cve_info=f"Manual analysis for {commit_hash[:12]}"
    )
    
    return {
        'repo': repo_name,
        'fix_commit': commit_hash,
        'file_path': selected_file,
        'vulnerable_line': vulnerable_line,
        'found_vic': result.get('introduction_commit'),
        'result': result
    }


def print_summary(all_results, elapsed_time):
    """打印汇总结果"""
    print("\n" + "="*70)
    print("📊 测试汇总")
    print("="*70)
    
    total = len(all_results)
    correct = sum(1 for r in all_results if r.get('is_correct'))
    errors = sum(1 for r in all_results if 'error' in r)
    
    accuracy = (correct / total * 100) if total > 0 else 0
    
    print(f"  准确率: {correct}/{total} ({accuracy:.1f}%)")
    print(f"  错误数: {errors}")
    print(f"  耗时: {elapsed_time:.1f}s")
    print()
    
    for r in all_results:
        cve = r.get('cve', 'N/A')
        expected = r.get('expected_vic', '')[:12] if r.get('expected_vic') else 'N/A'
        found = r.get('found_vic', '')[:12] if r.get('found_vic') else 'None'
        status = '✅' if r.get('is_correct') else '❌'
        
        if 'error' in r:
            print(f"  ⚠️ {cve}: 错误 - {r['error'][:40]}")
        else:
            print(f"  {status} {cve}: 期望 {expected}, 找到 {found}")


def main():
    parser = argparse.ArgumentParser(
        description='LLM 驱动的漏洞引入追踪工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用模式:
  1. 运行所有仓库:
     python run.py
     
  2. 运行单个仓库:
     python run.py activemq
     
  3. 运行单个 CVE:
     python run.py activemq CVE-2015-1830
     
  4. 运行单个提交:
     python run.py activemq --commit 729c4731574f
        """
    )
    
    # 位置参数
    parser.add_argument('repo', nargs='?', help='仓库名称 (不指定则运行所有仓库)')
    parser.add_argument('cve', nargs='?', help='CVE 编号 (不指定则运行仓库所有 CVE)')
    
    # 单提交模式
    parser.add_argument('--commit', '-c', help='指定修复提交哈希（单提交分析模式）')
    
    # 可选参数
    parser.add_argument('--no-validate', action='store_true', help='禁用小模型验证')
    parser.add_argument('--max-depth', type=int, default=0, help='最大追踪深度 (默认: 0=无限制)')
    parser.add_argument('-o', '--output', help='输出 JSON 文件路径')
    parser.add_argument('--list', '-l', action='store_true', help='列出可用的仓库和 CVE')
    
    # API 配置
    parser.add_argument('--api-key', help='API 密钥')
    parser.add_argument('--base-url', help='API 基础 URL')
    parser.add_argument('--model', help=f'大模型名称 (默认: {DEFAULT_LARGE_MODEL})')
    parser.add_argument('--small-model', help=f'小模型名称 (默认: {DEFAULT_SMALL_MODEL})')
    
    args = parser.parse_args()
    
    # 设置环境
    setup_environment(args)
    
    # 加载标注数据
    labels = load_labels()
    available_repos = get_available_repos()
    
    # 列出模式
    if args.list:
        print("\n📦 可用仓库:")
        for repo in available_repos:
            cve_count = len(labels.get(repo, {}))
            print(f"   - {repo} ({cve_count} CVEs)")
            if repo in labels:
                for cve in list(labels[repo].keys())[:5]:
                    print(f"       • {cve}")
                if len(labels[repo]) > 5:
                    print(f"       • ... 还有 {len(labels[repo]) - 5} 个")
        return
    
    print("="*70)
    print("🔍 LLM 驱动的漏洞引入追踪")
    print(f"   时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)
    
    start_time = datetime.now()
    all_results = []
    
    # 单提交模式
    if args.commit:
        if not args.repo:
            print("❌ 使用 --commit 时必须指定仓库名称")
            sys.exit(1)
        
        result = run_single_commit(args.repo, args.commit, args)
        if result:
            all_results = [result]
            print(f"\n✅ 找到 VIC: {result.get('found_vic', 'N/A')}")
    
    # CVE 模式
    elif args.repo:
        if args.repo not in available_repos:
            print(f"❌ 仓库 {args.repo} 未克隆")
            print(f"   可用仓库: {', '.join(available_repos)}")
            sys.exit(1)
        
        all_results = run_repo(args.repo, labels, args, args.cve)
    
    # 全部模式
    else:
        if not available_repos:
            print(f"❌ repos 目录中没有克隆的仓库: {REPOS_DIR}")
            sys.exit(1)
        
        for repo_name in available_repos:
            if repo_name in labels:
                results = run_repo(repo_name, labels, args)
                all_results.extend(results)
    
    elapsed = (datetime.now() - start_time).total_seconds()
    
    # 打印汇总
    if all_results and not args.commit:
        print_summary(all_results, elapsed)
    
    # 保存结果
    if all_results:
        os.makedirs(RESULTS_DIR, exist_ok=True)
        
        if args.output:
            output_path = args.output
        else:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            if args.repo:
                output_path = os.path.join(RESULTS_DIR, f"{args.repo}-{timestamp}.json")
            else:
                output_path = os.path.join(RESULTS_DIR, f"all-{timestamp}.json")
        
        # 简化结果用于保存
        save_results = []
        for r in all_results:
            save_r = {k: v for k, v in r.items() if k != 'result'}
            if 'result' in r:
                save_r['tracked_commits'] = r['result'].get('tracked_commits', [])
            save_results.append(save_r)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(save_results, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"\n💾 结果已保存到: {output_path}")


if __name__ == "__main__":
    main()
