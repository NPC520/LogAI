#!/usr/bin/env python
"""验证误报学习功能 - 中文版"""

import sys
sys.path.insert(0, '.')

from core.log_loader import LogLoader
from core.filter_funnel import FilterFunnel
from core.feedback_learner import FeedbackDB

print("=" * 60)
print("  误报反馈闭环功能验证")
print("=" * 60)

# 步骤1: 加载日志
print("\n步骤1: 加载测试日志文件...")
log_df = LogLoader.load_single('tests/test.log')
print(f"   原始日志条数: {len(log_df)}")

# 步骤2: 创建带反馈学习的过滤器
print("\n步骤2: 创建带反馈学习的过滤器...")
db = FeedbackDB('feedback.db')
funnel = FilterFunnel('configs/rules.regex', db)

# 显示已学习的误报模式
patterns = db.get_all_false_positive_patterns()
print(f"   已学习的误报模式数量: {len(patterns)}")
for i, p in enumerate(patterns):
    print(f"     {i+1}. {p[:60]}...")

# 步骤3: 执行过滤
print("\n步骤3: 执行威胁过滤...")
filtered = funnel.filter(log_df)
print(f"   过滤后日志条数: {len(filtered)}")

# 步骤4: 验证误报过滤
print("\n步骤4: 验证误报过滤效果...")
marked_pattern = "<script>alert('XSS')</script>"
contains_marked = False
for idx, row in filtered.iterrows():
    summary = str(row.get('payload_summary', ''))
    if marked_pattern in summary:
        contains_marked = True
        break

print(f"   是否包含已标记的误报模式: {contains_marked}")
print(f"   预期结果: False (应该被过滤掉)")

# 步骤5: 结论
print("\n" + "=" * 60)
if contains_marked:
    print("   [失败] 误报模式未被过滤！")
    print("   请检查 FeedbackDB 和 FilterFunnel 配置")
else:
    print("   [成功] 误报模式已被自动过滤！")
    print("   系统已成功学习并应用误报模式")
print("=" * 60)

# 步骤6: 显示过滤后的日志
print("\n步骤5: 过滤后的日志摘要:")
print("-" * 60)
for idx, row in filtered.iterrows():
    timestamp = row.get('timestamp', '')[:19]
    summary = row.get('payload_summary', '')[:80]
    print(f"   [{idx+1}] {timestamp} - {summary}")
print("-" * 60)
