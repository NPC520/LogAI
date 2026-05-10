import json
import os
from PySide6.QtWidgets import (QDialog, QHBoxLayout, QVBoxLayout, QListWidget,
                               QListWidgetItem, QPushButton, QGroupBox,
                               QFormLayout, QLineEdit, QScrollArea, QWidget,
                               QCheckBox, QTableWidget, QTableWidgetItem,
                               QInputDialog, QMessageBox, QHeaderView, QLabel)
from PySide6.QtCore import Signal

class SettingsDialog(QDialog):
    test_connection_requested = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("模型供应商配置")
        self.resize(750, 500)
        self.setModal(True)

        self.config_path = os.path.join(os.path.dirname(__file__), '..', 'configs', 'providers.json')
        self.providers = self._load_providers()
        self._ensure_custom_provider()

        self._init_ui()

    def _load_providers(self):
        """加载提供商配置，自动迁移旧格式"""
        default_providers = [
            {"name":"OpenAI","api_base":"https://api.openai.com/v1","api_key":"","default_model":"gpt-4o","proxy":"","headers":{},"options":{"thinking_mode":True}},
            {"name":"Groq","api_base":"https://api.groq.com/openai/v1","api_key":"","default_model":"mixtral-8x7b-32768","proxy":"","headers":{},"options":{"thinking_mode":True}},
            {"name":"Ollama","api_base":"http://localhost:11434","api_key":"","default_model":"llama3","proxy":"","headers":{},"options":{"thinking_mode":True}},
            {"name":"Custom","api_base":"","api_key":"","default_model":"","proxy":"","headers":{},"options":{"thinking_mode":True}}
        ]

        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return [self._migrate_provider(p) for p in data]
            return default_providers
        except Exception:
            return default_providers

    def _migrate_provider(self, provider):
        """迁移旧格式提供商数据，补全缺失字段"""
        defaults = {
            "proxy": "",
            "headers": {},
            "options": {"thinking_mode": True}
        }
        return {**defaults, **provider}

    def _ensure_custom_provider(self):
        """确保存在 Custom 提供商"""
        has_custom = any(p['name'] == 'Custom' for p in self.providers)
        if not has_custom:
            self.providers.append({
                "name": "Custom",
                "api_base": "",
                "api_key": "",
                "default_model": "",
                "proxy": "",
                "headers": {},
                "options": {"thinking_mode": True}
            })

    def _save_providers(self):
        """保存提供商配置"""
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(self.providers, f, indent=4, ensure_ascii=False)
            return True
        except Exception as e:
            QMessageBox.critical(self, "错误", f"保存配置失败: {e}")
            return False

    def _init_ui(self):
        """初始化主界面布局"""
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(8)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_panel.setMaximumWidth(220)

        self.provider_list = QListWidget()
        self.provider_list.setSelectionMode(QListWidget.SingleSelection)
        self.provider_list.currentRowChanged.connect(self._on_provider_selected)
        left_layout.addWidget(self.provider_list)

        btn_layout = QHBoxLayout()
        self.add_btn = QPushButton("+ 添加")
        self.add_btn.clicked.connect(self._on_add_provider)
        btn_layout.addWidget(self.add_btn)

        self.delete_btn = QPushButton("- 删除")
        self.delete_btn.clicked.connect(self._on_delete_provider)
        btn_layout.addWidget(self.delete_btn)

        left_layout.addLayout(btn_layout)
        main_layout.addWidget(left_panel)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setMinimumWidth(500)

        right_panel = QWidget()
        self.right_layout = QVBoxLayout(right_panel)
        self.right_layout.setContentsMargins(8, 8, 8, 8)
        self.right_layout.setSpacing(12)

        basic_group = QGroupBox("基本信息")
        basic_layout = QFormLayout(basic_group)
        basic_layout.setSpacing(10)

        self.name_label = QLabel("")
        basic_layout.addRow("提供商名称:", self.name_label)

        self.api_key_edit = QLineEdit()
        self.api_key_edit.setEchoMode(QLineEdit.Password)
        self.api_key_edit.setPlaceholderText("输入 API Key")
        basic_layout.addRow("API Key:", self.api_key_edit)

        self.base_url_edit = QLineEdit()
        self.base_url_edit.setPlaceholderText("https://api.openai.com/v1")
        basic_layout.addRow("API Base URL:", self.base_url_edit)

        self.model_edit = QLineEdit()
        self.model_edit.setPlaceholderText("gpt-4o")
        basic_layout.addRow("默认模型:", self.model_edit)

        self.right_layout.addWidget(basic_group)

        self.advanced_group = QGroupBox("高级设置")
        self.advanced_group.setCheckable(True)
        self.advanced_group.setChecked(False)
        advanced_layout = QFormLayout(self.advanced_group)
        advanced_layout.setSpacing(10)

        self.proxy_edit = QLineEdit()
        self.proxy_edit.setPlaceholderText("http://127.0.0.1:7890")
        advanced_layout.addRow("代理地址:", self.proxy_edit)

        self.headers_table = QTableWidget()
        self.headers_table.setColumnCount(2)
        self.headers_table.setHorizontalHeaderLabels(["Header名称", "Header值"])
        self.headers_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.headers_table.setRowCount(3)
        for i in range(3):
            self.headers_table.setItem(i, 0, QTableWidgetItem(""))
            self.headers_table.setItem(i, 1, QTableWidgetItem(""))
        advanced_layout.addRow("自定义请求头:", self.headers_table)

        self.thinking_mode_checkbox = QCheckBox("关闭思考模式")
        advanced_layout.addRow("", self.thinking_mode_checkbox)

        self.right_layout.addWidget(self.advanced_group)

        scroll_area.setWidget(right_panel)
        main_layout.addWidget(scroll_area)

        btn_panel = QWidget()
        btn_layout = QHBoxLayout(btn_panel)
        btn_layout.setContentsMargins(8, 8, 8, 8)
        btn_layout.setSpacing(8)
        btn_layout.addStretch()

        self.test_btn = QPushButton("测试连接")
        self.test_btn.clicked.connect(self._on_test_connection)
        btn_layout.addWidget(self.test_btn)

        self.save_btn = QPushButton("保存")
        self.save_btn.clicked.connect(self._on_save)
        btn_layout.addWidget(self.save_btn)

        self.cancel_btn = QPushButton("取消")
        self.cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(self.cancel_btn)

        outer_layout = QVBoxLayout(self)
        outer_layout.addLayout(main_layout)
        outer_layout.addWidget(btn_panel)

        self._refresh_provider_list()

    def _refresh_provider_list(self):
        """刷新提供商列表"""
        current_name = ""
        if self.provider_list.currentItem():
            current_name = self.provider_list.currentItem().text()

        self.provider_list.clear()
        for provider in self.providers:
            item = QListWidgetItem(provider['name'])
            self.provider_list.addItem(item)

        for i in range(self.provider_list.count()):
            if self.provider_list.item(i).text() == current_name:
                self.provider_list.setCurrentRow(i)
                break

    def _on_provider_selected(self, row):
        """选中提供商时更新右侧面板"""
        if 0 <= row < len(self.providers):
            provider = self.providers[row]
            self._fill_form(provider)
        else:
            self._clear_form()

    def _fill_form(self, provider):
        """用提供商数据填充表单"""
        self.name_label.setText(provider.get('name', ''))
        self.api_key_edit.setText(provider.get('api_key', ''))
        self.base_url_edit.setText(provider.get('api_base', ''))
        self.model_edit.setText(provider.get('default_model', ''))
        self.proxy_edit.setText(provider.get('proxy', ''))

        headers = provider.get('headers', {})
        self.headers_table.setRowCount(max(3, len(headers)))
        for i, (key, value) in enumerate(headers.items()):
            if i >= self.headers_table.rowCount():
                self.headers_table.insertRow(i)
            self.headers_table.setItem(i, 0, QTableWidgetItem(key))
            self.headers_table.setItem(i, 1, QTableWidgetItem(value))
        for i in range(len(headers), self.headers_table.rowCount()):
            self.headers_table.setItem(i, 0, QTableWidgetItem(""))
            self.headers_table.setItem(i, 1, QTableWidgetItem(""))

        thinking_mode = provider.get('options', {}).get('thinking_mode', True)
        self.thinking_mode_checkbox.setChecked(not thinking_mode)

    def _clear_form(self):
        """清空表单"""
        self.name_label.setText("")
        self.api_key_edit.clear()
        self.base_url_edit.clear()
        self.model_edit.clear()
        self.proxy_edit.clear()
        self.headers_table.setRowCount(3)
        for i in range(3):
            self.headers_table.setItem(i, 0, QTableWidgetItem(""))
            self.headers_table.setItem(i, 1, QTableWidgetItem(""))
        self.thinking_mode_checkbox.setChecked(False)

    def _collect_form_data(self):
        """收集表单数据"""
        headers = {}
        for i in range(self.headers_table.rowCount()):
            key_item = self.headers_table.item(i, 0)
            value_item = self.headers_table.item(i, 1)
            if key_item and value_item and key_item.text().strip():
                headers[key_item.text().strip()] = value_item.text().strip()

        return {
            "api_key": self.api_key_edit.text(),
            "api_base": self.base_url_edit.text(),
            "default_model": self.model_edit.text(),
            "proxy": self.proxy_edit.text(),
            "headers": headers,
            "options": {
                "thinking_mode": not self.thinking_mode_checkbox.isChecked()
            }
        }

    def _on_add_provider(self):
        """添加新提供商"""
        name, ok = QInputDialog.getText(self, "添加提供商", "输入提供商名称:")
        if ok and name.strip():
            new_provider = {
                "name": name.strip(),
                "api_base": "",
                "api_key": "",
                "default_model": "",
                "proxy": "",
                "headers": {},
                "options": {"thinking_mode": True}
            }
            self.providers.append(new_provider)
            self._save_providers()
            self._refresh_provider_list()

    def _on_delete_provider(self):
        """删除选中的提供商"""
        row = self.provider_list.currentRow()
        if row < 0:
            QMessageBox.warning(self, "提示", "请先选择要删除的提供商")
            return

        if len(self.providers) <= 1:
            QMessageBox.warning(self, "提示", "至少需要保留一个提供商")
            return

        provider_name = self.providers[row]['name']
        reply = QMessageBox.question(
            self, "确认删除", f"确定要删除提供商 \"{provider_name}\" 吗？",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            del self.providers[row]
            self._save_providers()
            self._refresh_provider_list()

    def _on_save(self):
        """保存配置"""
        row = self.provider_list.currentRow()
        if row < 0:
            QMessageBox.warning(self, "提示", "请先选择一个提供商")
            return

        form_data = self._collect_form_data()
        self.providers[row].update(form_data)

        if self._save_providers():
            QMessageBox.information(self, "成功", "配置已保存")
            self._refresh_provider_list()

    def _on_test_connection(self):
        """测试连接"""
        row = self.provider_list.currentRow()
        if row < 0:
            QMessageBox.warning(self, "提示", "请先选择一个提供商")
            return

        provider_name = self.providers[row]['name']
        self.test_connection_requested.emit(provider_name)
