import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import pandas as pd
from core.log_loader import LogLoader


class TestLogLoader:
    """LogLoader 日志加载器测试"""

    @pytest.fixture
    def sample_csv_content(self, tmp_path):
        """创建临时CSV文件"""
        csv_file = tmp_path / "test.csv"
        csv_file.write_text(
            "timestamp,src_ip,dst_ip,protocol,payload_summary\n"
            "2024-01-01 10:00:00,192.168.1.1,192.168.1.2,TCP,GET /index.html\n"
            "2024-01-01 10:00:01,192.168.1.2,192.168.1.3,UDP,DNS query\n"
        )
        return str(csv_file)

    @pytest.fixture
    def sample_txt_content(self, tmp_path):
        """创建临时TXT文件"""
        txt_file = tmp_path / "test.txt"
        txt_file.write_text(
            "2024-01-01 10:00:00 HTTP 192.168.1.1:12345 -> 192.168.1.2:80 GET /api/users?id=1\n"
            "2024-01-01 10:00:01 HTTP 192.168.1.1:12346 -> 192.168.1.2:80 POST /api/login\n"
        )
        return str(txt_file)

    def test_load_single_csv(self, sample_csv_content):
        """测试加载单个CSV文件"""
        result = LogLoader.load_single(sample_csv_content)
        assert result is not None
        assert isinstance(result, (list, pd.DataFrame))
        if isinstance(result, list):
            assert len(result) == 2
        elif isinstance(result, pd.DataFrame):
            assert len(result) == 2

    def test_load_single_txt(self, sample_txt_content):
        """测试加载单个TXT文件"""
        result = LogLoader.load_single(sample_txt_content)
        assert result is not None
        assert isinstance(result, (list, pd.DataFrame))

    def test_batch_load(self, sample_csv_content, sample_txt_content):
        """测试批量加载"""
        files = [sample_csv_content, sample_txt_content]
        result = LogLoader.batch_load(files)
        assert result is not None
        assert isinstance(result, pd.DataFrame)

    def test_load_nonexistent_file(self):
        """测试加载不存在的文件"""
        result = LogLoader.load_single('/nonexistent/file.csv')
        assert result is None or (isinstance(result, list) and len(result) == 0)

    def test_parse_csv(self, sample_csv_content):
        """测试CSV解析"""
        result = LogLoader._parse_csv(sample_csv_content)
        assert result is not None

    def test_parse_txt(self, sample_txt_content):
        """测试TXT解析"""
        result = LogLoader._parse_txt(sample_txt_content)
        assert result is not None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
