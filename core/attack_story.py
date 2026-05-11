import json
import re
import pandas as pd
from datetime import timedelta


SYSTEM_PROMPT_STORY = """你是网络攻击分析专家。给定一组按时间排序的日志条目（同一源IP），请还原可能的攻击链，并使用 MITRE ATT&CK 框架标注。

输出严格 JSON：
{
  "stages": [
    {
      "timestamp": "攻击步骤发生时间",
      "technique_id": "MITRE ATT&CK 技术ID，如 T1190",
      "technique_name": "技术名称",
      "tactic": "战术阶段，如 Initial Access",
      "description": "中文描述该步骤的攻击操作和目的",
      "evidence": "支持该步骤的关键日志原文"
    }
  ]
}
如果日志无法形成攻击链，stages 置为空数组。不要杜撰不存在的攻击步骤。
"""


class AttackStoryBuilder:
    TIME_WINDOW_MINUTES = 5

    @staticmethod
    def build_story(suspicious_df: pd.DataFrame, llm) -> dict:
        if suspicious_df is None or suspicious_df.empty:
            return {"stages": []}

        if 'timestamp' not in suspicious_df.columns or 'src_ip' not in suspicious_df.columns:
            return {"stages": []}

        try:
            sessions = AttackStoryBuilder._group_into_sessions(suspicious_df)
        except Exception:
            return {"stages": []}

        all_stages = []

        for session_logs in sessions:
            if not session_logs:
                continue

            log_context = AttackStoryBuilder._build_log_context(session_logs)

            try:
                response = llm.chat(SYSTEM_PROMPT_STORY, log_context)
            except Exception:
                continue

            story = AttackStoryBuilder._parse_response(response)
            if story and 'stages' in story:
                all_stages.extend(story['stages'])

        return {"stages": all_stages}

    @staticmethod
    def _group_into_sessions(df: pd.DataFrame):
        sessions = []
        df = df.copy()

        if 'timestamp' not in df.columns:
            return sessions

        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df = df.dropna(subset=['timestamp'])
        df = df.sort_values('timestamp')

        for src_ip, group in df.groupby('src_ip'):
            group = group.sort_values('timestamp')
            current_session = []

            for _, row in group.iterrows():
                if not current_session:
                    current_session.append(row)
                else:
                    last_time = current_session[-1]['timestamp']
                    curr_time = row['timestamp']
                    time_diff = (curr_time - last_time).total_seconds()

                    if time_diff > AttackStoryBuilder.TIME_WINDOW_MINUTES * 60:
                        if len(current_session) >= 1:
                            sessions.append(current_session)
                        current_session = [row]
                    else:
                        current_session.append(row)

            if current_session:
                sessions.append(current_session)

        return sessions

    @staticmethod
    def _build_log_context(session_logs):
        lines = []
        for row in session_logs:
            timestamp = row.get('timestamp', '')
            src_ip = row.get('src_ip', '')
            dst_ip = row.get('dst_ip', '')
            payload = row.get('payload_summary', '')
            protocol = row.get('protocol', '')

            line = f"[{timestamp}] {protocol} {src_ip} -> {dst_ip}: {payload}"
            lines.append(line)

        return '\n'.join(lines)

    @staticmethod
    def _parse_response(response: str) -> dict:
        try:
            return json.loads(response.strip())
        except json.JSONDecodeError:
            pass

        patterns = [
            r'```json\s*(\{.*?\})\s*```',
            r'```\s*(\{.*?\})\s*```',
            r'(\{.*\})'
        ]

        for pattern in patterns:
            match = re.search(pattern, response, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(1))
                except json.JSONDecodeError:
                    continue

        return {"stages": []}
