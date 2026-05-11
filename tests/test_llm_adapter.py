import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from core.llm_adapter import create_llm, BaseLLM, OpenAILLM


class TestLLMAdapter:
    """LLM适配器测试"""

    def test_create_llm_openai(self):
        """测试创建OpenAI LLM"""
        config = {
            "name": "OpenAI",
            "api_base": "https://api.openai.com/v1",
            "api_key": "test-key",
            "default_model": "gpt-4o"
        }
        llm = create_llm(config)
        assert llm is not None
        assert isinstance(llm, OpenAILLM)

    def test_create_llm_with_dict(self):
        """测试使用字典创建LLM"""
        config = {
            "name": "OpenAI",
            "api_base": "https://api.openai.com/v1",
            "api_key": "test-key",
            "default_model": "gpt-4o"
        }
        llm = create_llm(config)
        assert llm is not None

    def test_base_llm_is_abstract(self):
        """测试BaseLLM是抽象类"""
        with pytest.raises(TypeError):
            BaseLLM()

    def test_llm_has_analyze_method(self):
        """测试LLM有analyze方法"""
        config = {
            "name": "OpenAI",
            "api_base": "https://api.openai.com/v1",
            "api_key": "test-key",
            "default_model": "gpt-4o"
        }
        llm = create_llm(config)
        assert hasattr(llm, 'analyze')
        assert callable(getattr(llm, 'analyze'))

    def test_llm_has_chat_method(self):
        """测试LLM有chat方法"""
        config = {
            "name": "OpenAI",
            "api_base": "https://api.openai.com/v1",
            "api_key": "test-key",
            "default_model": "gpt-4o"
        }
        llm = create_llm(config)
        assert hasattr(llm, 'chat')
        assert callable(getattr(llm, 'chat'))


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
