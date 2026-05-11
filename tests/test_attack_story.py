import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import pandas as pd
from core.attack_story import AttackStoryBuilder


class TestAttackStoryBuilder:
    """AttackStoryBuilder 攻击链生成器测试"""

    @pytest.fixture
    def sample_logs(self):
        """测试数据"""
        return pd.DataFrame([
            {
                'timestamp': '2024-01-01 10:00:00',
                'src_ip': '192.168.1.100',
                'dst_ip': '192.168.1.1',
                'protocol': 'HTTP',
                'payload_summary': 'GET /admin/login.php HTTP/1.1'
            },
            {
                'timestamp': '2024-01-01 10:00:05',
                'src_ip': '192.168.1.100',
                'dst_ip': '192.168.1.1',
                'protocol': 'HTTP',
                'payload_summary': "admin' OR '1'='1"
            },
            {
                'timestamp': '2024-01-01 10:00:10',
                'src_ip': '192.168.1.100',
                'dst_ip': '192.168.1.1',
                'protocol': 'HTTP',
                'payload_summary': 'SELECT * FROM users WHERE id=1'
            },
            {
                'timestamp': '2024-01-01 10:05:00',
                'src_ip': '192.168.1.200',
                'dst_ip': '192.168.1.1',
                'protocol': 'HTTP',
                'payload_summary': 'GET /index.html HTTP/1.1'
            },
        ])

    def test_init(self):
        """测试初始化"""
        builder = AttackStoryBuilder()
        assert builder is not None

    def test_group_into_sessions(self, sample_logs):
        """测试会话分组"""
        sessions = AttackStoryBuilder._group_into_sessions(sample_logs)
        assert len(sessions) >= 1

    def test_build_log_context(self, sample_logs):
        """测试日志上下文构建"""
        context = AttackStoryBuilder._build_log_context([sample_logs.iloc[0]])
        assert '192.168.1.100' in context
        assert 'GET /admin/login.php' in context

    def test_build_story_with_empty_df(self):
        """测试空DataFrame"""
        result = AttackStoryBuilder.build_story(pd.DataFrame(), None)
        assert result == {"stages": []}

    def test_build_story_with_none(self):
        """测试None输入"""
        result = AttackStoryBuilder.build_story(None, None)
        assert result == {"stages": []}

    def test_parse_response_valid_json(self):
        """测试解析有效JSON"""
        json_str = '{"stages": [{"timestamp": "2024-01-01", "technique_id": "T1190"}]}'
        result = AttackStoryBuilder._parse_response(json_str)
        assert 'stages' in result

    def test_parse_response_with_code_block(self):
        """测试解析代码块中的JSON"""
        json_str = '```python\n{"stages": []}\n```'
        result = AttackStoryBuilder._parse_response(json_str)
        assert 'stages' in result

    def test_parse_response_invalid(self):
        """测试解析无效响应"""
        result = AttackStoryBuilder._parse_response('Invalid response')
        assert result == {"stages": []}


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
