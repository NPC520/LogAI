import os
import json
import logging
from abc import ABC, abstractmethod
import openai
import httpx

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """你是一名资深网络安全分析师，擅长从网络流量日志中识别攻击行为。

【检测类型】SQL注入、XSS、命令注入、LFI、SSRF、任意文件上传、暴力破解/端口扫描。

【流量特征】
SQLi: URL参数含' OR、UNION SELECT、--+、sleep(
XSS: 请求体含<script>、onerror=、javascript:
RCE: 参数含;id、|whoami、$(cat、`ls`
LFI: URL含../、/etc/passwd、file://
SSRF: 参数值为内网IP或169.254.169.254
暴力破解: 同一IP短时间>10次登录请求

【绕过识别】大小写混写、双写、编码、${IFS}等。

【分析原则】区分探测/成功，结合响应码，不确定标记low。

【输出JSON格式】{"findings":[{"severity":"high|medium|low","type":"类型","src_ip":"","dst_ip":"","description":"","evidence":"","confidence":0-10,"bypass_technique":"","suggestion":""}]}，无威胁返回{"findings":[]}
"""

class BaseLLM(ABC):
    def __init__(self, config: dict):
        self.config = config

    @abstractmethod
    def test_connection(self) -> bool:
        pass

    @abstractmethod
    def analyze(self, log_chunk: str) -> dict:
        pass

    @abstractmethod
    def chat(self, system_prompt: str, user_prompt: str) -> str:
        """通用聊天接口"""
        pass

    def _parse_json_response(self, content: str) -> dict:
        import re
        try:
            return json.loads(content.strip())
        except json.JSONDecodeError:
            pass
        match = re.search(r'```json\s*(.*?)\s*```', content, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass
        match = re.search(r'\{.*\}', content, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass
        return {"findings": [], "error": "JSON解析失败"}


class OpenAILLM(BaseLLM):
    def __init__(self, config: dict):
        super().__init__(config)
        api_base = config.get('api_base', '')
        api_key = config.get('api_key', '') or os.environ.get('OPENAI_API_KEY', '')
        model = config.get('default_model', 'gpt-4o')
        self.client = openai.OpenAI(base_url=api_base if api_base else None, api_key=api_key)
        self.config['model'] = model

    def test_connection(self) -> bool:
        try:
            self.client.models.list()
            return True
        except Exception as e:
            logger.error(f"OpenAI 连接测试失败: {str(e)}")
            return False

    def analyze(self, log_chunk: str) -> dict:
        try:
            response = self.client.chat.completions.create(
                model=self.config['model'],
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": log_chunk}
                ],
                temperature=0.1
            )
            content = response.choices[0].message.content
            return self._parse_json_response(content)
        except Exception as e:
            logger.error(f"OpenAI 分析失败: {str(e)}")
            return {"findings": [], "error": str(e)}

    def chat(self, system_prompt: str, user_prompt: str) -> str:
        try:
            response = self.client.chat.completions.create(
                model=self.config['model'],
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"OpenAI 聊天失败: {str(e)}")
            return f"错误: {str(e)}"


class GroqLLM(BaseLLM):
    def __init__(self, config: dict):
        super().__init__(config)
        api_base = config.get('api_base', '') or "https://api.groq.com/openai/v1"
        api_key = config.get('api_key', '') or os.environ.get('GROQ_API_KEY', '')
        model = config.get('default_model', 'llama3-8b-8192')
        self.client = openai.OpenAI(base_url=api_base, api_key=api_key)
        self.config['model'] = model

    def test_connection(self) -> bool:
        try:
            self.client.models.list()
            return True
        except Exception as e:
            logger.error(f"Groq 连接测试失败: {str(e)}")
            return False

    def analyze(self, log_chunk: str) -> dict:
        try:
            response = self.client.chat.completions.create(
                model=self.config['model'],
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": log_chunk}
                ],
                temperature=0.1
            )
            content = response.choices[0].message.content
            return self._parse_json_response(content)
        except Exception as e:
            logger.error(f"Groq 分析失败: {str(e)}")
            return {"findings": [], "error": str(e)}

    def chat(self, system_prompt: str, user_prompt: str) -> str:
        try:
            response = self.client.chat.completions.create(
                model=self.config['model'],
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"Groq 聊天失败: {str(e)}")
            return f"错误: {str(e)}"


class OllamaLLM(BaseLLM):
    def __init__(self, config: dict):
        super().__init__(config)
        api_base = config.get('api_base', 'http://localhost:11434')
        model = config.get('default_model', 'llama3')
        self.client = httpx.Client(base_url=api_base, timeout=120)
        self.config['model'] = model

    def test_connection(self) -> bool:
        try:
            response = self.client.get("/api/tags")
            if response.status_code == 200:
                data = response.json()
                if 'models' in data and isinstance(data['models'], list):
                    return True
            return False
        except Exception as e:
            logger.error(f"Ollama 连接测试失败: {str(e)}")
            return False

    def analyze(self, log_chunk: str) -> dict:
        try:
            payload = {
                "model": self.config['model'],
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": log_chunk}
                ],
                "stream": False,
                "options": {"temperature": 0.1}
            }
            response = self.client.post("/api/chat", json=payload)
            response.raise_for_status()
            data = response.json()
            content = data.get('message', {}).get('content', '')
            return self._parse_json_response(content)
        except httpx.HTTPError as e:
            logger.error(f"Ollama 分析失败: {str(e)}")
            return {"findings": [], "error": str(e)}
        except Exception as e:
            logger.error(f"Ollama 分析失败: {str(e)}")
            return {"findings": [], "error": str(e)}

    def chat(self, system_prompt: str, user_prompt: str) -> str:
        try:
            payload = {
                "model": self.config['model'],
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "stream": False,
                "options": {"temperature": 0.1}
            }
            response = self.client.post("/api/chat", json=payload)
            response.raise_for_status()
            data = response.json()
            return data.get('message', {}).get('content', '')
        except httpx.HTTPError as e:
            logger.error(f"Ollama 聊天失败: {str(e)}")
            return f"错误: {str(e)}"
        except Exception as e:
            logger.error(f"Ollama 聊天失败: {str(e)}")
            return f"错误: {str(e)}"


def create_llm(config: dict) -> BaseLLM:
    name = config.get('name', '').lower()
    if name == 'ollama':
        return OllamaLLM(config)
    else:
        return OpenAILLM(config)
