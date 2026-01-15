#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
LLM 客户端封装
支持 OpenAI 和其他兼容 API
"""

import os
import json
import hashlib
from typing import Dict, Optional
from abc import ABC, abstractmethod


class BaseLLMClient(ABC):
    """LLM客户端基类"""
    
    @abstractmethod
    def chat(self, messages: list, temperature: float = 0.1, 
             response_format: str = "json") -> str:
        """发送聊天请求"""
        pass
    
    @abstractmethod
    def get_model_name(self) -> str:
        """获取模型名称"""
        pass


class OpenAIClient(BaseLLMClient):
    """OpenAI API 客户端（Chat Completions API）"""
    
    def __init__(self, api_key: str = None, model: str = "gpt-4", 
                 base_url: str = None):
        """
        初始化 OpenAI 客户端
        
        Args:
            api_key: API密钥，默认从环境变量获取
            model: 模型名称
            base_url: API基础URL，用于兼容其他API
        """
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError("请安装 openai: pip install openai")
        
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("未配置 OPENAI_API_KEY")
        
        self.model = model
        self.base_url = base_url
        
        if base_url:
            self.client = OpenAI(api_key=self.api_key, base_url=base_url)
        else:
            self.client = OpenAI(api_key=self.api_key)
    
    def chat(self, messages: list, temperature: float = 0.1,
             response_format: str = "json") -> str:
        """
        发送聊天请求
        
        Args:
            messages: 消息列表
            temperature: 温度参数
            response_format: 响应格式 ("json" 或 "text")
        """
        # 检查是否是 codex 模型，需要使用 Responses API
        if "codex" in self.model.lower():
            return self._chat_responses_api(messages, temperature, response_format)
        
        kwargs = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "timeout": 120,  # 添加超时设置
        }
        
        # GPT 模型支持 json_object 格式
        if response_format == "json" and "gpt" in self.model.lower():
            kwargs["response_format"] = {"type": "json_object"}
        
        try:
            response = self.client.chat.completions.create(**kwargs)
            return response.choices[0].message.content
        except Exception as e:
            # 如果 response_format 不支持，重试不带该参数
            if "response_format" in kwargs and "response_format" in str(e).lower():
                del kwargs["response_format"]
                response = self.client.chat.completions.create(**kwargs)
                return response.choices[0].message.content
            raise
    
    def _chat_responses_api(self, messages: list, temperature: float = 0.1,
                            response_format: str = "json") -> str:
        """
        使用 Responses API 发送请求（用于 codex 模型）
        
        Responses API 端点: POST /v1/responses
        """
        import requests
        
        # 构建请求
        url = self.base_url.rstrip('/') + '/responses' if self.base_url else 'https://api.openai.com/v1/responses'
        
        # 从 messages 提取 system 和 user 内容
        instructions = None
        input_content = []
        
        for msg in messages:
            role = msg.get('role', '')
            content = msg.get('content', '')
            
            if role == 'system':
                instructions = content
            elif role in ('user', 'assistant'):
                input_content.append({
                    "role": role,
                    "content": content
                })
        
        # 如果只有一条用户消息，可以简化为字符串
        if len(input_content) == 1 and input_content[0]['role'] == 'user':
            input_data = input_content[0]['content']
        else:
            input_data = input_content
        
        payload = {
            "model": self.model,
            "input": input_data,
            "temperature": temperature,
        }
        
        if instructions:
            payload["instructions"] = instructions
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=120)
            response.raise_for_status()
            
            data = response.json()
            
            # 从 Responses API 格式中提取文本
            # output 是一个数组，找到 type="message" 的项
            output = data.get('output', [])
            for item in output:
                if item.get('type') == 'message':
                    content = item.get('content', [])
                    for c in content:
                        if c.get('type') == 'output_text':
                            return c.get('text', '')
            
            # 尝试 output_text 快捷方式
            if 'output_text' in data:
                return data['output_text']
            
            return str(data)
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Responses API 请求失败: {e}")
    
    def get_model_name(self) -> str:
        return self.model


class LLMCache:
    """LLM响应缓存"""
    
    def __init__(self, cache_dir: str = None):
        """
        初始化缓存
        
        Args:
            cache_dir: 缓存目录
        """
        if cache_dir is None:
            cache_dir = os.path.join(os.path.dirname(__file__), '.llm_cache')
        
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)
    
    def _get_cache_key(self, messages: list, model: str) -> str:
        """生成缓存键"""
        content = json.dumps(messages, sort_keys=True) + model
        return hashlib.sha256(content.encode()).hexdigest()
    
    def get(self, messages: list, model: str) -> Optional[str]:
        """获取缓存"""
        key = self._get_cache_key(messages, model)
        cache_file = os.path.join(self.cache_dir, f"{key}.json")
        
        if os.path.exists(cache_file):
            with open(cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('response')
        return None
    
    def set(self, messages: list, model: str, response: str):
        """设置缓存"""
        key = self._get_cache_key(messages, model)
        cache_file = os.path.join(self.cache_dir, f"{key}.json")
        
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump({
                'messages': messages,
                'model': model,
                'response': response
            }, f, ensure_ascii=False, indent=2)
    
    def clear(self):
        """清除所有缓存"""
        import shutil
        if os.path.exists(self.cache_dir):
            shutil.rmtree(self.cache_dir)
            os.makedirs(self.cache_dir)


class CachedLLMClient:
    """带缓存的LLM客户端包装器"""
    
    def __init__(self, client: BaseLLMClient, enable_cache: bool = True):
        """
        初始化
        
        Args:
            client: LLM客户端
            enable_cache: 是否启用缓存
        """
        self.client = client
        self.enable_cache = enable_cache
        self.cache = LLMCache() if enable_cache else None
        
        # 统计信息
        self.stats = {
            'total_calls': 0,
            'cache_hits': 0,
            'api_calls': 0
        }
    
    def chat(self, messages: list, temperature: float = 0.1,
             response_format: str = "json", use_cache: bool = True) -> str:
        """
        发送聊天请求（带缓存）
        
        Args:
            messages: 消息列表
            temperature: 温度参数
            response_format: 响应格式
            use_cache: 是否使用缓存（对于此次请求）
        """
        self.stats['total_calls'] += 1
        
        # 尝试从缓存获取
        if self.enable_cache and use_cache and temperature == 0.1:
            cached = self.cache.get(messages, self.client.get_model_name())
            if cached:
                self.stats['cache_hits'] += 1
                return cached
        
        # 调用API
        self.stats['api_calls'] += 1
        response = self.client.chat(messages, temperature, response_format)
        
        # 存入缓存
        if self.enable_cache and use_cache and temperature == 0.1:
            self.cache.set(messages, self.client.get_model_name(), response)
        
        return response
    
    def get_model_name(self) -> str:
        return self.client.get_model_name()
    
    def get_stats(self) -> Dict:
        """获取统计信息"""
        return self.stats.copy()
    
    def print_stats(self):
        """打印统计信息"""
        print(f"\n📊 LLM调用统计:")
        print(f"   总调用: {self.stats['total_calls']}")
        print(f"   缓存命中: {self.stats['cache_hits']}")
        print(f"   实际API调用: {self.stats['api_calls']}")
        if self.stats['total_calls'] > 0:
            hit_rate = self.stats['cache_hits'] / self.stats['total_calls'] * 100
            print(f"   缓存命中率: {hit_rate:.1f}%")


def create_llm_client(model_type: str = "large", 
                      api_key: str = None,
                      base_url: str = None,
                      enable_cache: bool = True) -> CachedLLMClient:
    """
    创建LLM客户端的工厂函数
    
    Args:
        model_type: "large" (GPT-4级别) 或 "small" (GPT-3.5级别)
        api_key: API密钥
        base_url: API基础URL
        enable_cache: 是否启用缓存
    
    Returns:
        CachedLLMClient 实例
    """
    if model_type == "large":
        model = "gpt-4"  # 或 "gpt-4-turbo-preview"
    else:
        model = "gpt-3.5-turbo"
    
    client = OpenAIClient(api_key=api_key, model=model, base_url=base_url)
    return CachedLLMClient(client, enable_cache=enable_cache)
