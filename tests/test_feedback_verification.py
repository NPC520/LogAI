#!/usr/bin/env python
"""验证误报学习功能"""

import sys
sys.path.insert(0, '.')

from core.log_loader import LogLoader
from core.filter_funnel import FilterFunnel
from core.feedback_learner import FeedbackDB

# 加载日志
print("步骤1: 加载日志...")
log_df = LogLoader.load_single('tests/test.log')
print(f"原始日志条数: {len(log_df)}")

# 创建带反馈学习的过滤器
print("\n步骤2: 创建带反馈学习的过滤器...")
db = FeedbackDB('feedback.db')
funnel = FilterFunnel('configs/rules.regex', db)

# 显示已学习的误报模式
patterns = db.get_all_false_positive_patterns()
print(f"已学习的误报模式数量: {len(patterns)}")
for i, p in enumerate(patterns):
    print(f"  {i+1}. {p[:60]}...")

# 过滤后
print("\n步骤3: 执行过滤...")
filtered = funnel.filter(log_df)
print(f"过滤后日志条数: {len(filtered)}")

# 检查是否包含被标记的误报
print("\n步骤4: 验证误报过滤...")
marked_pattern = "<script>alert('XSS')</script>"
contains_marked = False
for idx, row in filtered.iterrows():
    summary = str(row.get('payload_summary', ''))
    if marked_pattern in summary:
        contains_marked = True
        break

print(f"是否包含已标记的误报模式: {contains_marked}")
print(f"预期结果: False (应该被过滤掉)")

if contains_marked:
    print("\n❌ 警告: 误报模式未被过滤!")
else:
    print("\n✅ 成功: 误报模式已被自动过滤!")

# 打印过滤后的日志摘要
print("\n步骤5: 过滤后的日志摘要:")
for idx, row in filtered.iterrows():
    print(f"  [{idx}] {row.get('timestamp', '')[:19]} {row.get('payload_summary', '')[:80]}")
