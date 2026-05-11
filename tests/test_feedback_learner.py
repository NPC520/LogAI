import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import tempfile
import shutil
from core.feedback_learner import FeedbackDB


class TestFeedbackDB:
    """FeedbackDB 误报反馈数据库测试"""

    @pytest.fixture
    def temp_db(self):
        """创建临时数据库"""
        temp_dir = tempfile.mkdtemp()
        db_path = os.path.join(temp_dir, 'test_feedback.db')
        db = FeedbackDB(db_path)
        yield db
        shutil.rmtree(temp_dir)

    def test_init(self, temp_db):
        """测试初始化"""
        assert temp_db is not None
        assert os.path.exists(temp_db.db_path)

    def test_add_feedback(self, temp_db):
        """测试添加反馈"""
        finding = {
            'timestamp': '2024-01-01 12:00:00',
            'src_ip': '192.168.1.1',
            'dst_ip': '192.168.1.2',
            'evidence': 'Normal GET request to /api/users',
            'payload_summary': 'Normal GET request to /api/users'
        }
        result = temp_db.add_feedback(finding)
        assert result is True

    def test_add_multiple_feedbacks(self, temp_db):
        """测试添加多条反馈"""
        findings = [
            {'timestamp': '2024-01-01 12:00:00', 'src_ip': '192.168.1.1', 'dst_ip': '192.168.1.2',
             'evidence': 'GET /api/users?id=1', 'payload_summary': 'GET /api/users?id=1'},
            {'timestamp': '2024-01-01 12:01:00', 'src_ip': '192.168.1.3', 'dst_ip': '192.168.1.4',
             'evidence': 'GET /api/products?id=2', 'payload_summary': 'GET /api/products?id=2'},
        ]
        for finding in findings:
            temp_db.add_feedback(finding)

        patterns = temp_db.get_all_false_positive_patterns()
        assert len(patterns) == 2

    def test_is_probable_false_positive(self, temp_db):
        """测试误报检测"""
        finding = {
            'timestamp': '2024-01-01 12:00:00',
            'src_ip': '192.168.1.1',
            'dst_ip': '192.168.1.2',
            'evidence': 'GET /api/users?id=1',
            'payload_summary': 'GET /api/users?id=1'
        }
        temp_db.add_feedback(finding)

        result = temp_db.is_probable_false_positive('GET /api/users?id=1')
        assert result is True

    def test_is_not_probable_false_positive(self, temp_db):
        """测试非误报检测"""
        result = temp_db.is_probable_false_positive('SELECT * FROM users')
        assert result is False

    def test_get_all_false_positive_patterns(self, temp_db):
        """测试获取所有误报模式"""
        findings = [
            {'timestamp': '2024-01-01 12:00:00', 'src_ip': '192.168.1.1', 'dst_ip': '192.168.1.2',
             'evidence': 'Pattern 1', 'payload_summary': 'Pattern 1'},
            {'timestamp': '2024-01-01 12:01:00', 'src_ip': '192.168.1.3', 'dst_ip': '192.168.1.4',
             'evidence': 'Pattern 2', 'payload_summary': 'Pattern 2'},
        ]
        for finding in findings:
            temp_db.add_feedback(finding)

        patterns = temp_db.get_all_false_positive_patterns()
        assert len(patterns) == 2
        assert 'Pattern 1' in patterns
        assert 'Pattern 2' in patterns

    def test_delete_feedback(self, temp_db):
        """测试删除反馈"""
        finding = {
            'timestamp': '2024-01-01 12:00:00',
            'src_ip': '192.168.1.1',
            'dst_ip': '192.168.1.2',
            'evidence': 'To be deleted',
            'payload_summary': 'To be deleted'
        }
        temp_db.add_feedback(finding)
        patterns_before = temp_db.get_all_false_positive_patterns()

        feedbacks = temp_db.get_all_feedbacks()
        if feedbacks:
            feedback_id = feedbacks[0]['id']
            result = temp_db.delete_feedback(feedback_id)
            assert result is True

    def test_get_all_feedbacks(self, temp_db):
        """测试获取所有反馈"""
        findings = [
            {'timestamp': '2024-01-01 12:00:00', 'src_ip': '192.168.1.1', 'dst_ip': '192.168.1.2',
             'evidence': 'Feedback 1', 'payload_summary': 'Feedback 1'},
        ]
        temp_db.add_feedback(findings[0])

        feedbacks = temp_db.get_all_feedbacks()
        assert len(feedbacks) == 1
        assert feedbacks[0]['src_ip'] == '192.168.1.1'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
