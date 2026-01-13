#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
V-SZZ 简单运行示例
这个脚本展示如何运行V-SZZ算法
"""
import os
import sys
import json

# 确保可以导入当前目录的模块
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

from setting import *

# 添加pyszz到路径
pyszz_path = os.path.join(SZZ_FOLDER, 'tools', 'pyszz')
if os.path.exists(pyszz_path) and pyszz_path not in sys.path:
    sys.path.insert(0, pyszz_path)

from szz.my_szz import MySZZ
from data_loader import load_annotated_commits

def run_vszz_example():
    """
    运行V-SZZ的简单示例
    注意：需要先在REPOS_DIR中克隆对应的Git仓库
    """
    print("=" * 60)
    print("V-SZZ 运行示例")
    print("=" * 60)
    
    # 加载标注的提交
    project_commits = load_annotated_commits()
    
    # 选择第一个项目作为示例
    first_project = list(project_commits.keys())[0]
    first_commits = project_commits[first_project]
    
    print(f"\n项目: {first_project}")
    print(f"修复提交数量: {len(first_commits)}")
    print(f"示例修复提交: {first_commits[0] if first_commits else '无'}")
    
    # 检查仓库是否存在
    repo_path = os.path.join(REPOS_DIR, first_project)
    if not os.path.exists(repo_path):
        print(f"\n⚠ 警告: 仓库不存在 {repo_path}")
        print(f"\n需要先克隆仓库到 {REPOS_DIR} 目录")
        print("\n示例命令:")
        print(f"  cd {REPOS_DIR}")
        print(f"  git clone <仓库URL> {first_project}")
        return
    
    print(f"\n✓ 仓库已存在: {repo_path}")
    
    # 验证提交是否存在
    print("\n验证提交...")
    from git import Repo as GitRepo
    git_repo = GitRepo(repo_path)
    
    commit_to_check = first_commits[0]
    try:
        git_commit = git_repo.commit(commit_to_check)
        print(f"✓ 提交存在于Git仓库: {commit_to_check[:8]}")
        print(f"  提交时间: {git_commit.committed_datetime}")
        print(f"  作者: {git_commit.author.name}")
        print(f"  消息: {git_commit.message.split(chr(10))[0][:50]}...")
    except Exception as e:
        print(f"✗ 提交不存在于Git仓库: {e}")
        print(f"  可能需要 git fetch --all 获取所有分支")
        return
    
    # 创建V-SZZ实例
    print("\n初始化V-SZZ...")
    try:
        my_szz = MySZZ(
            repo_full_name=first_project, 
            repo_url=None,  # 使用本地仓库
            repos_dir=REPOS_DIR, 
            use_temp_dir=False, 
            ast_map_path=AST_MAP_PATH
        )
        
        # 处理第一个修复提交
        commit = first_commits[0]
        print(f"\n正在分析修复提交: {commit}")
        
        # 获取受影响的文件
        print("  - 获取受影响的文件...")
        imp_files = my_szz.get_impacted_files(
            fix_commit_hash=commit,
            file_ext_to_parse=['c', 'java', 'cpp', 'h', 'hpp'],
            only_deleted_lines=True
        )
        print(f"  - 找到 {len(imp_files)} 个受影响的文件")
        
        # 查找引入漏洞的提交
        print("  - 查找引入漏洞的提交...")
        bug_introducing_commits = my_szz.find_bic(
            fix_commit_hash=commit,
            impacted_files=imp_files,
            ignore_revs_file_path=None
        )
        
        print(f"\n结果:")
        print(f"  修复提交: {commit}")
        print(f"  引入漏洞的提交数量: {len(bug_introducing_commits)}")
        
        if bug_introducing_commits:
            print(f"  引入漏洞的提交:")
            for bic in bug_introducing_commits[:5]:  # 最多显示5个
                print(f"    - {bic}")
        
        print("\n" + "=" * 60)
        print("V-SZZ 运行成功！")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n✗ 错误: {str(e)}")
        print("\n可能的原因:")
        print("  1. 仓库路径不正确")
        print("  2. 提交哈希不存在")
        print("  3. 缺少必要的依赖")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    run_vszz_example()
