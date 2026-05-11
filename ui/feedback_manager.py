from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QTableWidget,
                               QPushButton, QLabel, QMessageBox, QComboBox,
                               QTableWidgetItem, QHeaderView, QSpacerItem, QSizePolicy)
from PySide6.QtCore import Qt


class FeedbackManagerDialog(QDialog):
    """误报管理对话框"""

    def __init__(self, feedback_db, parent=None):
        super().__init__(parent)
        self.feedback_db = feedback_db
        self.setWindowTitle("误报管理")
        self.setMinimumSize(700, 450)
        self.resize(700, 450)

        self._init_ui()

    def _init_ui(self):
        """初始化界面"""
        layout = QVBoxLayout(self)

        # 阈值调整（可选功能）
        threshold_layout = QHBoxLayout()
        threshold_label = QLabel("匹配阈值:")
        threshold_layout.addWidget(threshold_label)

        self.threshold_combo = QComboBox()
        self.threshold_combo.addItems(["0.75", "0.80", "0.85", "0.90"])
        self.threshold_combo.setCurrentText("0.85")
        threshold_layout.addWidget(self.threshold_combo)

        threshold_hint = QLabel("(此功能即将实现)")
        threshold_hint.setStyleSheet("color: gray; font-size: 12px;")
        threshold_layout.addWidget(threshold_hint)

        threshold_layout.addSpacerItem(QSpacerItem(20, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))
        layout.addLayout(threshold_layout)

        # 表格
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["ID", "时间", "源IP", "目的IP", "摘要", "创建时间"])
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)

        layout.addWidget(self.table)

        # 按钮区
        button_layout = QHBoxLayout()

        self.delete_btn = QPushButton("删除选中")
        self.delete_btn.clicked.connect(self.on_delete_selected)
        button_layout.addWidget(self.delete_btn)

        self.detail_btn = QPushButton("查看详情")
        self.detail_btn.clicked.connect(self.on_view_detail)
        button_layout.addWidget(self.detail_btn)

        self.clear_btn = QPushButton("全部清除")
        self.clear_btn.clicked.connect(self.on_clear_all)
        button_layout.addWidget(self.clear_btn)

        button_layout.addSpacerItem(QSpacerItem(20, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))

        self.close_btn = QPushButton("关闭")
        self.close_btn.clicked.connect(self.close)
        button_layout.addWidget(self.close_btn)

        layout.addLayout(button_layout)

        # 状态栏
        self.status_label = QLabel("已学习 0 个误报模式")
        self.status_label.setStyleSheet("color: gray; font-size: 12px;")
        layout.addWidget(self.status_label)

        # 加载数据
        self._load_data()

    def _load_data(self):
        """从数据库加载数据并刷新表格"""
        self.table.setRowCount(0)

        records = self.feedback_db.get_all_records()

        for record in records:
            row = self.table.rowCount()
            self.table.insertRow(row)

            self.table.setItem(row, 0, QTableWidgetItem(str(record['id'])))
            self.table.setItem(row, 1, QTableWidgetItem(record['timestamp']))
            self.table.setItem(row, 2, QTableWidgetItem(record['src_ip']))
            self.table.setItem(row, 3, QTableWidgetItem(record['dst_ip']))

            summary = record['log_summary'][:100] + "..." if len(record['log_summary']) > 100 else record['log_summary']
            self.table.setItem(row, 4, QTableWidgetItem(summary))

            created_at = record['created_at'][:19] if record['created_at'] else ''
            self.table.setItem(row, 5, QTableWidgetItem(created_at))

        self.status_label.setText(f"已学习 {len(records)} 个误报模式")

    def on_delete_selected(self):
        """删除选中的误报记录"""
        selected_rows = self.table.selectedIndexes()
        if not selected_rows:
            QMessageBox.warning(self, "提示", "请先选择一条记录")
            return

        row = selected_rows[0].row()
        feedback_id = int(self.table.item(row, 0).text())

        reply = QMessageBox.question(
            self,
            "确认删除",
            f"确定要删除这条误报记录吗？\n\nID: {feedback_id}",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            success = self.feedback_db.delete_feedback(feedback_id)
            if success:
                self._load_data()
                QMessageBox.information(self, "成功", "已删除选中的误报记录")
            else:
                QMessageBox.warning(self, "失败", "删除失败，请重试")

    def on_view_detail(self):
        """查看选中记录的详情"""
        selected_rows = self.table.selectedIndexes()
        if not selected_rows:
            QMessageBox.warning(self, "提示", "请先选择一条记录")
            return

        row = selected_rows[0].row()

        feedback_id = self.table.item(row, 0).text()
        timestamp = self.table.item(row, 1).text()
        src_ip = self.table.item(row, 2).text()
        dst_ip = self.table.item(row, 3).text()
        log_summary = self.table.item(row, 4).text()

        records = self.feedback_db.get_all_records()
        full_summary = ""
        for record in records:
            if str(record['id']) == feedback_id:
                full_summary = record['log_summary']
                break

        detail_text = f"""ID: {feedback_id}
时间: {timestamp}
源IP: {src_ip}
目的IP: {dst_ip}
完整摘要:
{full_summary}"""

        QMessageBox.information(self, "详情", detail_text)

    def on_clear_all(self):
        """清除所有误报记录"""
        records = self.feedback_db.get_all_records()
        if not records:
            QMessageBox.information(self, "提示", "没有误报记录需要清除")
            return

        reply = QMessageBox.question(
            self,
            "确认清除",
            f"确定要清除所有 {len(records)} 条误报记录吗？\n\n此操作不可撤销！",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            success = self.feedback_db.clear_all()
            if success:
                self._load_data()
                QMessageBox.information(self, "成功", "已清除所有误报记录")
            else:
                QMessageBox.warning(self, "失败", "清除失败，请重试")
