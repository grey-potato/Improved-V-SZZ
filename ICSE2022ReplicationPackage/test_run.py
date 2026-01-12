#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
简单的V-SZZ测试脚本
"""
import os
import sys
import json

from setting import *

sys.path.append(os.path.join(SZZ_FOLDER, 'tools/pyszz/'))

from data_loader import load_annotated_commits

def test_vszz():
    """
    测试V-SZZ是否能运行
    """
    print("=" * 60)
    print("V-SZZ 测试脚本")
    print("=" * 60)
    
    # 检查配置
    print(f"\n工作目录: {WORK_DIR}")
    print(f"仓库目录: {REPOS_DIR}")
    print(f"数据目录: {DATA_FOLDER}")
    print(f"SZZ目录: {SZZ_FOLDER}")
    
    # 检查数据文件是否存在
    label_file = os.path.join(DATA_FOLDER, 'label.json')
    if os.path.exists(label_file):
        print(f"\n✓ 标签文件存在: {label_file}")
        
        # 加载标注的提交
        project_commits = load_annotated_commits()
        print(f"\n找到 {len(project_commits)} 个项目:")
        for project in list(project_commits.keys())[:5]:  # 只显示前5个
            commit_count = len(project_commits[project])
            print(f"  - {project}: {commit_count} 个修复提交")
    else:
        print(f"\n✗ 标签文件不存在: {label_file}")
        return False
    
    print("\n" + "=" * 60)
    print("环境检查完成！可以开始运行V-SZZ")
    print("=" * 60)
    
    return True

if __name__ == "__main__":
    test_vszz()
