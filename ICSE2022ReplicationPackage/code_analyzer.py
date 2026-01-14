#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
代码分析工具封装
支持 AST (Java) 和 srcml (C/C++) 的代码变更分析
"""

import os
import sys
import json
import subprocess
import shutil
from typing import Dict, Tuple, Optional, List
from dataclasses import dataclass


@dataclass
class ToolAnalysisResult:
    """单个工具的分析结果"""
    tool_used: str  # "ast" / "srcml" / "none"
    success: bool
    change_type: str  # "Insert" / "Delete" / "Update" / "Move" / "Unknown"
    source_line: Optional[int]  # 变更前的行号
    target_line: Optional[int]  # 变更后的行号
    confidence: float  # 工具的置信度
    raw_output: Dict  # 工具原始输出
    error_message: Optional[str]


@dataclass
class CombinedToolResult:
    """
    综合工具分析结果
    
    设计原则：工具只是辅助，LLM 永远是最终决策者
    工具的作用是提供额外信息帮助 LLM 做出更准确的判断
    """
    ast_result: Optional[ToolAnalysisResult]  # AST 分析结果（仅 Java）
    srcml_result: Optional[ToolAnalysisResult]  # srcml 分析结果
    file_path: str
    line_num: int
    
    def has_any_result(self) -> bool:
        """是否有任何工具返回了结果"""
        return ((self.ast_result and self.ast_result.success) or 
                (self.srcml_result and self.srcml_result.success))
    
    def get_best_source_line(self) -> Optional[int]:
        """获取最可信的源行号（AST 优先，因为更精确）"""
        if self.ast_result and self.ast_result.success and self.ast_result.source_line:
            return self.ast_result.source_line
        if self.srcml_result and self.srcml_result.success and self.srcml_result.source_line:
            return self.srcml_result.source_line
        return None
    
    def tools_agree(self) -> bool:
        """两个工具的结果是否一致"""
        if not (self.ast_result and self.ast_result.success and 
                self.srcml_result and self.srcml_result.success):
            return False
        return self.ast_result.change_type == self.srcml_result.change_type
    
    def to_dict(self) -> Dict:
        """转换为字典，用于传给 LLM"""
        result = {
            'file_path': self.file_path,
            'line_num': self.line_num,
            'tools_used': [],
            'tools_agree': False,
            'best_source_line': self.get_best_source_line()
        }
        
        if self.ast_result:
            result['tools_used'].append('AST')
            result['ast'] = {
                'success': self.ast_result.success,
                'change_type': self.ast_result.change_type,
                'source_line': self.ast_result.source_line,
                'confidence': self.ast_result.confidence,
                'error': self.ast_result.error_message
            }
        
        if self.srcml_result:
            result['tools_used'].append('srcml')
            result['srcml'] = {
                'success': self.srcml_result.success,
                'change_type': self.srcml_result.change_type,
                'source_line': self.srcml_result.source_line,
                'confidence': self.srcml_result.confidence,
                'error': self.srcml_result.error_message
            }
        
        result['tools_agree'] = self.tools_agree()
        return result


class ASTAnalyzer:
    """
    Java AST 分析器
    使用 ASTMapEval.jar 进行代码变更映射
    """
    
    def __init__(self, ast_map_path: str, repo_path: str, repo_name: str):
        """
        初始化 AST 分析器
        
        Args:
            ast_map_path: ASTMapEval.jar 所在目录
            repo_path: Git仓库路径
            repo_name: 仓库名称
        """
        self.ast_map_path = ast_map_path
        self.repo_path = repo_path
        self.repo_name = repo_name
        self.cache_dir = os.path.join(ast_map_path, 'temp')
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # 检查 Java 环境
        self.java_available = self._check_java()
        
        # 检查 JAR 文件
        self.jar_path = os.path.join(ast_map_path, 'ASTMapEval.jar')
        self.jar_available = os.path.exists(self.jar_path)
    
    def _check_java(self) -> bool:
        """检查 Java 是否可用"""
        try:
            result = subprocess.run(['java', '-version'], 
                                   capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def is_available(self) -> bool:
        """检查 AST 分析器是否可用"""
        return self.java_available and self.jar_available
    
    def analyze(self, commit_hash: str, file_path: str, 
                line_num: int) -> ToolAnalysisResult:
        """
        分析 Java 代码变更
        
        Args:
            commit_hash: 提交哈希
            file_path: 文件路径
            line_num: 目标行号
            
        Returns:
            分析结果
        """
        if not self.is_available():
            return ToolAnalysisResult(
                tool_used="ast",
                success=False,
                change_type="Unknown",
                source_line=None,
                target_line=line_num,
                confidence=0.0,
                raw_output={},
                error_message="AST工具不可用（缺少Java或JAR文件）"
            )
        
        try:
            # 规范化文件路径
            file_path = file_path.replace('\\', '/')
            
            # 缓存文件
            cache_file = os.path.join(self.cache_dir, f"{self.repo_name}.json")
            output_file = os.path.join(self.cache_dir, "tmp.json")
            
            # 检查缓存
            mapping_results = self._get_from_cache(cache_file, commit_hash, file_path)
            
            if mapping_results is None:
                # 运行 AST 工具
                cmd = [
                    "java", "-jar", self.jar_path,
                    "-p", self.repo_name,
                    "-c", commit_hash,
                    "-o", output_file,
                    "-f", file_path
                ]
                
                subprocess.check_output(
                    cmd, cwd=self.ast_map_path, 
                    stderr=subprocess.DEVNULL, timeout=60
                )
                
                with open(output_file, 'r', encoding='utf-8') as f:
                    mapping_results = json.load(f)
                
                # 保存到缓存
                self._save_to_cache(cache_file, commit_hash, file_path, mapping_results)
            
            # 解析结果
            return self._parse_ast_result(mapping_results, file_path, line_num)
            
        except subprocess.TimeoutExpired:
            return ToolAnalysisResult(
                tool_used="ast",
                success=False,
                change_type="Unknown",
                source_line=None,
                target_line=line_num,
                confidence=0.0,
                raw_output={},
                error_message="AST分析超时"
            )
        except Exception as e:
            return ToolAnalysisResult(
                tool_used="ast",
                success=False,
                change_type="Unknown",
                source_line=None,
                target_line=line_num,
                confidence=0.0,
                raw_output={},
                error_message=f"AST分析失败: {str(e)}"
            )
    
    def _get_from_cache(self, cache_file: str, commit_hash: str, 
                        file_path: str) -> Optional[List]:
        """从缓存获取结果"""
        if not os.path.exists(cache_file):
            return None
        
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                cache = json.load(f)
            
            if commit_hash in cache and file_path in cache[commit_hash]:
                return cache[commit_hash][file_path]
        except:
            pass
        
        return None
    
    def _save_to_cache(self, cache_file: str, commit_hash: str,
                       file_path: str, results: List):
        """保存结果到缓存"""
        cache = {}
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    cache = json.load(f)
            except:
                pass
        
        if commit_hash not in cache:
            cache[commit_hash] = {}
        cache[commit_hash][file_path] = results
        
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(cache, f, indent=2)
    
    def _parse_ast_result(self, mapping_results: List, file_path: str,
                          line_num: int) -> ToolAnalysisResult:
        """解析 AST 映射结果"""
        target_stmt = None
        
        for result in mapping_results:
            result_file = result.get('dst') or result.get('targetFile', '')
            if result_file == file_path:
                for stmt in result.get('stmt', []):
                    if stmt.get('srcStmtStartLine') == line_num:
                        target_stmt = stmt
                        break
                if target_stmt:
                    break
        
        if target_stmt is None:
            return ToolAnalysisResult(
                tool_used="ast",
                success=True,
                change_type="Insert",  # 没找到映射，可能是新增
                source_line=None,
                target_line=line_num,
                confidence=0.8,
                raw_output={"mapping_results": mapping_results},
                error_message=None
            )
        
        change_type = target_stmt.get('stmtChangeType', 'Unknown')
        source_line = target_stmt.get('srcStmtStartLine')
        
        # Insert 表示这行是新增的（即引入点）
        if change_type == "Insert":
            return ToolAnalysisResult(
                tool_used="ast",
                success=True,
                change_type="Insert",
                source_line=None,
                target_line=line_num,
                confidence=0.9,
                raw_output=target_stmt,
                error_message=None
            )
        
        return ToolAnalysisResult(
            tool_used="ast",
            success=True,
            change_type=change_type,
            source_line=source_line,
            target_line=line_num,
            confidence=0.85,
            raw_output=target_stmt,
            error_message=None
        )


class SrcMLAnalyzer:
    """
    C/C++ srcml 分析器
    使用 srcml 进行代码解析和变更分析
    """
    
    def __init__(self, repo_path: str):
        """
        初始化 srcml 分析器
        
        Args:
            repo_path: Git仓库路径
        """
        self.repo_path = repo_path
        self.srcml_available = self._check_srcml()
    
    def _check_srcml(self) -> bool:
        """检查 srcml 是否可用"""
        try:
            result = subprocess.run(['srcml', '--version'], 
                                   capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def is_available(self) -> bool:
        """检查 srcml 分析器是否可用"""
        return self.srcml_available
    
    def analyze(self, commit_hash: str, file_path: str,
                line_num: int, repo) -> ToolAnalysisResult:
        """
        分析 C/C++ 代码变更
        
        使用 srcml 将代码转换为 XML，然后分析结构变化
        
        Args:
            commit_hash: 提交哈希
            file_path: 文件路径
            line_num: 目标行号
            repo: Git仓库对象
            
        Returns:
            分析结果
        """
        if not self.is_available():
            return ToolAnalysisResult(
                tool_used="srcml",
                success=False,
                change_type="Unknown",
                source_line=None,
                target_line=line_num,
                confidence=0.0,
                raw_output={},
                error_message="srcml工具不可用"
            )
        
        try:
            commit = repo.commit(commit_hash)
            if not commit.parents:
                return ToolAnalysisResult(
                    tool_used="srcml",
                    success=True,
                    change_type="Insert",
                    source_line=None,
                    target_line=line_num,
                    confidence=0.9,
                    raw_output={},
                    error_message=None
                )
            
            parent = commit.parents[0]
            
            # 获取变更前后的文件内容
            try:
                old_content = (parent.tree / file_path).data_stream.read().decode('utf-8', errors='ignore')
            except:
                # 文件在父提交中不存在，是新文件
                return ToolAnalysisResult(
                    tool_used="srcml",
                    success=True,
                    change_type="Insert",
                    source_line=None,
                    target_line=line_num,
                    confidence=0.9,
                    raw_output={"reason": "new_file"},
                    error_message=None
                )
            
            try:
                new_content = (commit.tree / file_path).data_stream.read().decode('utf-8', errors='ignore')
            except:
                # 文件被删除
                return ToolAnalysisResult(
                    tool_used="srcml",
                    success=True,
                    change_type="Delete",
                    source_line=line_num,
                    target_line=None,
                    confidence=0.9,
                    raw_output={"reason": "file_deleted"},
                    error_message=None
                )
            
            # 使用 srcml 解析
            old_xml = self._parse_with_srcml(old_content, file_path)
            new_xml = self._parse_with_srcml(new_content, file_path)
            
            if old_xml and new_xml:
                # 分析结构变化
                result = self._analyze_structure_change(
                    old_xml, new_xml, old_content, new_content, line_num
                )
                return result
            else:
                return ToolAnalysisResult(
                    tool_used="srcml",
                    success=False,
                    change_type="Unknown",
                    source_line=None,
                    target_line=line_num,
                    confidence=0.0,
                    raw_output={},
                    error_message="srcml解析失败"
                )
            
        except Exception as e:
            return ToolAnalysisResult(
                tool_used="srcml",
                success=False,
                change_type="Unknown",
                source_line=None,
                target_line=line_num,
                confidence=0.0,
                raw_output={},
                error_message=f"srcml分析失败: {str(e)}"
            )
    
    def _parse_with_srcml(self, content: str, file_path: str) -> Optional[str]:
        """使用 srcml 解析代码"""
        try:
            # 确定语言
            ext = os.path.splitext(file_path)[1].lower()
            lang_map = {
                '.c': 'C',
                '.h': 'C',
                '.cpp': 'C++',
                '.hpp': 'C++',
                '.cc': 'C++',
                '.cxx': 'C++'
            }
            language = lang_map.get(ext, 'C++')
            
            # 调用 srcml
            result = subprocess.run(
                ['srcml', '-l', language, '-'],
                input=content.encode('utf-8'),
                capture_output=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return result.stdout.decode('utf-8', errors='ignore')
            return None
        except:
            return None
    
    def _analyze_structure_change(self, old_xml: str, new_xml: str,
                                   old_content: str, new_content: str,
                                   target_line: int) -> ToolAnalysisResult:
        """
        分析代码结构变化
        
        简化实现：基于行内容匹配找到对应的旧行
        """
        new_lines = new_content.split('\n')
        old_lines = old_content.split('\n')
        
        if target_line > len(new_lines):
            return ToolAnalysisResult(
                tool_used="srcml",
                success=False,
                change_type="Unknown",
                source_line=None,
                target_line=target_line,
                confidence=0.0,
                raw_output={},
                error_message="目标行号超出范围"
            )
        
        target_content = new_lines[target_line - 1].strip()
        
        # 跳过空行和纯注释行（这些匹配意义不大）
        if not target_content or target_content.startswith('//') or target_content.startswith('/*'):
            return ToolAnalysisResult(
                tool_used="srcml",
                success=False,
                change_type="Unknown",
                source_line=None,
                target_line=target_line,
                confidence=0.0,
                raw_output={"reason": "empty_or_comment_line"},
                error_message="目标行为空行或注释，无法进行有效匹配"
            )
        
        # 在旧文件中查找相似行
        best_match = None
        best_score = 0
        exact_matches = []  # 可能有多个完全匹配
        
        for i, old_line in enumerate(old_lines):
            old_stripped = old_line.strip()
            if old_stripped == target_content:
                exact_matches.append(i + 1)
        
        # 如果有多个完全匹配，说明这行代码不够独特，匹配不可靠
        if len(exact_matches) == 1:
            return ToolAnalysisResult(
                tool_used="srcml",
                success=True,
                change_type="Move" if exact_matches[0] != target_line else "Unchanged",
                source_line=exact_matches[0],
                target_line=target_line,
                confidence=0.7,  # 降低置信度，因为只是简单文本匹配
                raw_output={"match_type": "exact", "warning": "基于文本匹配，非语义分析"},
                error_message=None
            )
        elif len(exact_matches) > 1:
            # 多个匹配，选择行号最接近的，但置信度很低
            closest = min(exact_matches, key=lambda x: abs(x - target_line))
            return ToolAnalysisResult(
                tool_used="srcml",
                success=True,
                change_type="Move" if closest != target_line else "Unchanged",
                source_line=closest,
                target_line=target_line,
                confidence=0.3,  # 多个匹配，置信度很低
                raw_output={"match_type": "multiple_exact", "all_matches": exact_matches, 
                           "warning": "存在多个相同行，结果不可靠"},
                error_message=None
            )
            
            # 计算相似度
            if old_stripped and target_content:
                # 简单的相似度：共同字符比例
                common = len(set(old_stripped) & set(target_content))
                total = len(set(old_stripped) | set(target_content))
                if total > 0:
                    score = common / total
                    if score > best_score and score > 0.6:
                        best_score = score
                        best_match = i + 1
        
        if best_match and best_score > 0.6:
            return ToolAnalysisResult(
                tool_used="srcml",
                success=True,
                change_type="Update",
                source_line=best_match,
                target_line=target_line,
                confidence=best_score * 0.5,  # 大幅降低，相似匹配不可靠
                raw_output={"match_type": "similar", "similarity": best_score,
                           "warning": "基于相似度匹配，可能不准确"},
                error_message=None
            )
        
        # 没有找到匹配，可能是新增（但也可能是匹配失败）
        return ToolAnalysisResult(
            tool_used="srcml",
            success=True,
            change_type="Insert",
            source_line=None,
            target_line=target_line,
            confidence=0.4,  # 低置信度，因为可能只是没匹配到
            raw_output={"match_type": "none", 
                       "warning": "未找到匹配行，可能是新增也可能是匹配失败"},
            error_message=None
        )


class CodeAnalyzerFactory:
    """
    代码分析器工厂
    根据文件类型选择合适的分析工具
    """
    
    def __init__(self, repo_path: str, repo_name: str, ast_map_path: str = None):
        """
        初始化工厂
        
        Args:
            repo_path: Git仓库路径
            repo_name: 仓库名称
            ast_map_path: AST工具路径
        """
        self.repo_path = repo_path
        self.repo_name = repo_name
        
        # 初始化分析器
        if ast_map_path:
            self.ast_analyzer = ASTAnalyzer(ast_map_path, repo_path, repo_name)
        else:
            self.ast_analyzer = None
        
        self.srcml_analyzer = SrcMLAnalyzer(repo_path)
    
    def analyze(self, commit_hash: str, file_path: str, 
                line_num: int, repo=None) -> CombinedToolResult:
        """
        综合分析代码变更
        
        设计原则：
        - Java 代码：同时使用 AST 和 srcml，综合两者结果
        - 非 Java 代码：使用 srcml
        - 所有结果都传给 LLM，LLM 是最终决策者
        
        Args:
            commit_hash: 提交哈希
            file_path: 文件路径
            line_num: 目标行号
            repo: Git仓库对象
            
        Returns:
            综合分析结果
        """
        ext = os.path.splitext(file_path)[1].lower()
        
        ast_result = None
        srcml_result = None
        
        # Java 文件：同时使用 AST 和 srcml
        if ext == '.java':
            # 1. AST 分析
            if self.ast_analyzer and self.ast_analyzer.is_available():
                ast_result = self.ast_analyzer.analyze(commit_hash, file_path, line_num)
            
            # 2. srcml 也分析一遍（Java 也支持）
            if self.srcml_analyzer.is_available():
                srcml_result = self.srcml_analyzer.analyze(commit_hash, file_path, line_num, repo)
        else:
            # 非 Java 文件：只用 srcml
            if self.srcml_analyzer.is_available():
                srcml_result = self.srcml_analyzer.analyze(commit_hash, file_path, line_num, repo)
        
        return CombinedToolResult(
            ast_result=ast_result,
            srcml_result=srcml_result,
            file_path=file_path,
            line_num=line_num
        )
    
    def get_status(self) -> Dict:
        """获取分析器状态"""
        return {
            'ast': {
                'available': self.ast_analyzer.is_available() if self.ast_analyzer else False,
                'java_available': self.ast_analyzer.java_available if self.ast_analyzer else False,
                'jar_available': self.ast_analyzer.jar_available if self.ast_analyzer else False,
                'for_languages': ['Java']
            },
            'srcml': {
                'available': self.srcml_analyzer.is_available(),
                'for_languages': ['Java', 'C', 'C++', 'C#', 'Objective-C']
            },
            'strategy': {
                'java': 'AST + srcml (综合使用)',
                'non_java': 'srcml',
                'final_decision': 'LLM (所有代码都由 LLM 最终决策)'
            }
        }
