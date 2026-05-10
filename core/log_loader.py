import os
import json
import csv
import io
import re
import logging

import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP, Raw
from scapy.utils import PcapReader

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class LogLoader:
    """日志文件加载器，支持多种格式"""

    @staticmethod
    def load_single(file_path: str) -> list[dict]:
        """
        加载单个日志文件
        
        Args:
            file_path: 文件路径
        
        Returns:
            解析后的日志条目列表，每个条目是包含 timestamp, src_ip, dst_ip, protocol, payload_summary, raw 的字典
        """
        if not os.path.exists(file_path):
            logger.error(f"文件不存在: {file_path}")
            return []

        ext = os.path.splitext(file_path)[1].lower()

        try:
            if ext in ('.pcap', '.pcapng'):
                return LogLoader._parse_pcap(file_path)
            elif ext == '.csv':
                return LogLoader._parse_csv(file_path)
            elif ext in ('.txt', '.log'):
                return LogLoader._parse_txt(file_path)
            else:
                return LogLoader._parse_text_generic(file_path)
        except Exception as e:
            logger.error(f"解析文件 {file_path} 失败: {str(e)}")
            return []

    @staticmethod
    def _parse_pcap(file_path: str) -> list[dict]:
        """解析PCAP文件"""
        results = []
        try:
            with PcapReader(file_path) as pcap_reader:
                for pkt in pcap_reader:
                    entry = {
                        'timestamp': '',
                        'src_ip': '',
                        'dst_ip': '',
                        'protocol': 'OTHER',
                        'payload_summary': '',
                        'raw': ''
                    }

                    # 时间戳
                    if pkt.time:
                        entry['timestamp'] = pd.to_datetime(pkt.time, unit='s').strftime('%Y-%m-%d %H:%M:%S')

                    # IP层
                    if IP in pkt:
                        entry['src_ip'] = pkt[IP].src
                        entry['dst_ip'] = pkt[IP].dst

                        # TCP层
                        if TCP in pkt:
                            entry['protocol'] = 'TCP'
                            src_port = pkt[TCP].sport
                            dst_port = pkt[TCP].dport
                            entry['raw'] = f"{entry['src_ip']}:{src_port} -> {entry['dst_ip']}:{dst_port} TCP len {len(pkt)}"
                            
                            if Raw in pkt:
                                payload = bytes(pkt[Raw]).decode('utf-8', errors='ignore')
                                entry['payload_summary'] = payload[:300]
                        
                        # UDP层
                        elif UDP in pkt:
                            entry['protocol'] = 'UDP'
                            src_port = pkt[UDP].sport
                            dst_port = pkt[UDP].dport
                            entry['raw'] = f"{entry['src_ip']}:{src_port} -> {entry['dst_ip']}:{dst_port} UDP len {len(pkt)}"
                            
                            if Raw in pkt:
                                payload = bytes(pkt[Raw]).decode('utf-8', errors='ignore')
                                entry['payload_summary'] = payload[:300]
                        
                        else:
                            entry['raw'] = f"{entry['src_ip']} -> {entry['dst_ip']} IP len {len(pkt)}"
                    
                    # 只有IP包才添加
                    if entry['src_ip']:
                        results.append(entry)

        except Exception as e:
            logger.error(f"解析PCAP失败: {str(e)}")

        return results

    @staticmethod
    def _parse_csv(file_path: str) -> list[dict]:
        """解析CSV文件"""
        results = []
        try:
            # 尝试自动识别分隔符
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                sample = f.read(1024)
            
            # 尝试不同分隔符
            delimiters = [',', ';', '\t', '|']
            detected_delimiter = ','
            
            for delim in delimiters:
                if sample.count(delim) > sample.count(detected_delimiter):
                    detected_delimiter = delim

            df = pd.read_csv(file_path, delimiter=detected_delimiter, encoding='utf-8', errors='ignore')
            
            # 列名映射
            timestamp_cols = ['timestamp', 'time', 'datetime', 'date', 'ts']
            src_cols = ['src', 'src_ip', 'source', 'source_ip', 'from']
            dst_cols = ['dst', 'dst_ip', 'destination', 'dest', 'to']
            payload_cols = ['payload', 'data', 'info', 'message', 'content', 'log']
            protocol_cols = ['protocol', 'proto']

            def find_col(cols):
                for col in cols:
                    for df_col in df.columns:
                        if df_col.lower() == col.lower():
                            return df_col
                return None

            ts_col = find_col(timestamp_cols)
            src_col = find_col(src_cols)
            dst_col = find_col(dst_cols)
            payload_col = find_col(payload_cols)
            proto_col = find_col(protocol_cols)

            for _, row in df.iterrows():
                entry = {
                    'timestamp': '',
                    'src_ip': '',
                    'dst_ip': '',
                    'protocol': 'OTHER',
                    'payload_summary': '',
                    'raw': ''
                }

                if ts_col and pd.notna(row[ts_col]):
                    entry['timestamp'] = str(row[ts_col])[:20]
                
                if src_col and pd.notna(row[src_col]):
                    entry['src_ip'] = str(row[src_col])
                
                if dst_col and pd.notna(row[dst_col]):
                    entry['dst_ip'] = str(row[dst_col])
                
                if proto_col and pd.notna(row[proto_col]):
                    proto = str(row[proto_col]).upper()
                    entry['protocol'] = proto if proto in ['TCP', 'UDP', 'HTTP'] else 'OTHER'
                
                if payload_col and pd.notna(row[payload_col]):
                    entry['payload_summary'] = str(row[payload_col])[:300]
                else:
                    # 如果没有payload列，合并所有列
                    entry['payload_summary'] = str(row.to_dict())[:300]
                
                entry['raw'] = str(row.to_dict())[:500]
                results.append(entry)

        except Exception as e:
            logger.error(f"解析CSV失败: {str(e)}")

        return results

    @staticmethod
    def _parse_txt(file_path: str) -> list[dict]:
        """解析TXT/LOG文件"""
        results = []
        
        # 常见日志格式正则
        # 格式1: 时间 协议 IP:端口 -> IP:端口 内容
        pattern1 = re.compile(
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(TCP|UDP)\s+([\d.]+):(\d+)\s*->?\s*([\d.]+):(\d+)\s+(.*)',
            re.IGNORECASE
        )
        # 格式2: [时间] IP -> IP 内容
        pattern2 = re.compile(
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+([\d.]+)\s*->?\s*([\d.]+)\s*(.*)',
            re.IGNORECASE
        )
        # 格式3: IP:端口 -> IP:端口 内容
        pattern3 = re.compile(
            r'([\d.]+):(\d+)\s*->?\s*([\d.]+):(\d+)\s*(.*)',
            re.IGNORECASE
        )
        # 格式4: 时间 IP 其他
        pattern4 = re.compile(
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+([\d.]+)\s+(.*)',
            re.IGNORECASE
        )

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    entry = {
                        'timestamp': '',
                        'src_ip': '',
                        'dst_ip': '',
                        'protocol': 'OTHER',
                        'payload_summary': '',
                        'raw': line[:500]
                    }

                    match = pattern1.match(line)
                    if match:
                        entry['timestamp'] = match.group(1)
                        entry['protocol'] = match.group(2).upper()
                        entry['src_ip'] = match.group(3)
                        entry['dst_ip'] = match.group(5)
                        entry['payload_summary'] = match.group(7)[:300]
                        results.append(entry)
                        continue

                    match = pattern2.match(line)
                    if match:
                        entry['timestamp'] = match.group(1)
                        entry['src_ip'] = match.group(2)
                        entry['dst_ip'] = match.group(3)
                        entry['payload_summary'] = match.group(4)[:300]
                        results.append(entry)
                        continue

                    match = pattern3.match(line)
                    if match:
                        entry['src_ip'] = match.group(1)
                        entry['dst_ip'] = match.group(3)
                        entry['payload_summary'] = match.group(5)[:300]
                        # 根据端口猜测协议
                        dst_port = int(match.group(4))
                        if dst_port in [80, 8080, 443]:
                            entry['protocol'] = 'HTTP'
                        elif dst_port in [21, 22, 23]:
                            entry['protocol'] = 'TCP'
                        results.append(entry)
                        continue

                    match = pattern4.match(line)
                    if match:
                        entry['timestamp'] = match.group(1)
                        entry['src_ip'] = match.group(2)
                        entry['payload_summary'] = match.group(3)[:300]
                        results.append(entry)
                        continue

                    # 无法匹配，整行作为payload
                    entry['payload_summary'] = line[:300]
                    results.append(entry)

        except Exception as e:
            logger.error(f"解析TXT失败: {str(e)}")

        return results

    @staticmethod
    def _parse_text_generic(file_path: str) -> list[dict]:
        """通用文本解析（其他格式）"""
        results = []
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entry = {
                            'timestamp': '',
                            'src_ip': '',
                            'dst_ip': '',
                            'protocol': 'OTHER',
                            'payload_summary': line[:300],
                            'raw': line[:500]
                        }
                        results.append(entry)
        except Exception as e:
            logger.error(f"解析文件失败: {str(e)}")
        return results

    @staticmethod
    def batch_load(file_paths: list[str]) -> pd.DataFrame:
        """
        批量加载多个日志文件并合并为DataFrame
        
        Args:
            file_paths: 文件路径列表
        
        Returns:
            合并后的DataFrame，列名: timestamp, src_ip, dst_ip, protocol, payload_summary, raw
        """
        all_entries = []

        for file_path in file_paths:
            entries = LogLoader.load_single(file_path)
            all_entries.extend(entries)

        df = pd.DataFrame(all_entries, columns=[
            'timestamp', 'src_ip', 'dst_ip', 'protocol', 'payload_summary', 'raw'
        ])

        return df

if __name__ == '__main__':
    # 测试
    import sys
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        entries = LogLoader.load_single(file_path)
        print(f"解析到 {len(entries)} 条记录")
        if entries:
            print(json.dumps(entries[:3], indent=2, ensure_ascii=False))
    else:
        print("用法: python log_loader.py <文件路径>")
