import sqlite3
import hashlib
import json
import os
from datetime import datetime


class FeedbackDB:
    """误报反馈数据库"""

    def __init__(self, db_path: str = "feedback.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """初始化数据库表"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS false_positives (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                log_summary TEXT,
                pattern_hash TEXT,
                created_at TEXT
            )
        ''')

        conn.commit()
        conn.close()

    def add_feedback(self, finding: dict) -> bool:
        """添加误报反馈"""
        try:
            timestamp = finding.get('timestamp', '')
            src_ip = finding.get('src_ip', '')
            dst_ip = finding.get('dst_ip', '')
            evidence = finding.get('evidence', '') or finding.get('payload_summary', '')

            pattern_hash = hashlib.md5(evidence.encode('utf-8')).hexdigest()
            created_at = datetime.now().isoformat()

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO false_positives 
                (timestamp, src_ip, dst_ip, log_summary, pattern_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (timestamp, src_ip, dst_ip, evidence, pattern_hash, created_at))

            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"添加反馈失败: {e}")
            return False

    def _compute_bigram_set(self, text: str) -> set:
        """计算文本的双字符集合"""
        text = text.lower().strip()
        if len(text) < 2:
            return set()
        return {text[i:i+2] for i in range(len(text)-1)}

    def is_probable_false_positive(self, log_text: str, threshold: float = 0.85) -> bool:
        """判断是否可能是误报"""
        if not log_text:
            return False

        log_bigrams = self._compute_bigram_set(log_text)
        if not log_bigrams:
            return False

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('SELECT log_summary FROM false_positives')
        rows = cursor.fetchall()
        conn.close()

        if not rows:
            return False

        max_similarity = 0.0
        for row in rows:
            stored_text = row[0]
            stored_bigrams = self._compute_bigram_set(stored_text)

            if not stored_bigrams:
                continue

            intersection = log_bigrams & stored_bigrams
            union = log_bigrams | stored_bigrams

            if not union:
                continue

            similarity = len(intersection) / len(union)
            max_similarity = max(max_similarity, similarity)

            if max_similarity >= threshold:
                return True

        return max_similarity >= threshold

    def get_all_false_positive_patterns(self) -> list:
        """获取所有误报模式"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('SELECT log_summary FROM false_positives')
        rows = cursor.fetchall()
        conn.close()

        return [row[0] for row in rows]

    def delete_feedback(self, feedback_id: int) -> bool:
        """删除指定误报记录"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('DELETE FROM false_positives WHERE id = ?', (feedback_id,))
            conn.commit()
            deleted = cursor.rowcount > 0
            conn.close()

            return deleted
        except Exception as e:
            print(f"删除反馈失败: {e}")
            return False

    def get_all_feedbacks(self) -> list:
        """获取所有反馈记录"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('SELECT id, timestamp, src_ip, dst_ip, log_summary, created_at FROM false_positives')
        rows = cursor.fetchall()
        conn.close()

        result = []
        for row in rows:
            result.append({
                'id': row[0],
                'timestamp': row[1],
                'src_ip': row[2],
                'dst_ip': row[3],
                'log_summary': row[4],
                'created_at': row[5]
            })

        return result

    def get_all_records(self) -> list:
        """获取所有记录（别名方法）"""
        return self.get_all_feedbacks()

    def clear_all(self) -> bool:
        """清除所有误报记录"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('DELETE FROM false_positives')
            conn.commit()
            conn.close()

            return True
        except Exception as e:
            print(f"清除所有反馈失败: {e}")
            return False
