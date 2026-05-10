import json
import os
from PySide6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                               QMenuBar, QMenu, QSplitter, QTabWidget,
                               QTableView, QLabel, QLineEdit, QComboBox,
                               QPushButton, QTextEdit, QStatusBar, QProgressBar,
                               QFileDialog, QListWidget, QListWidgetItem,
                               QHeaderView, QMessageBox, QSpacerItem, QSizePolicy)
from PySide6.QtGui import QAction, QStandardItemModel, QBrush
from PySide6.QtCore import Qt, QThread, Signal
from ui.settings_dialog import SettingsDialog
from core.llm_adapter import create_llm
from core.log_loader import LogLoader
from core.filter_funnel import FilterFunnel


class AnalysisWorker(QThread):
    """后台分析线程"""
    finished_with_findings = Signal(list)
    progress_update = Signal(int, int)
    error_occurred = Signal(str)
    stopped = Signal()

    def __init__(self, llm, df_chunks):
        super().__init__()
        self.llm = llm
        self.df_chunks = df_chunks

    def run(self):
        """执行分析任务"""
        total = len(self.df_chunks)
        for idx, chunk in enumerate(self.df_chunks):
            if self.isInterruptionRequested():
                self.stopped.emit()
                return

            try:
                result = self.llm.analyze(chunk)
                if result and 'findings' in result and result['findings']:
                    self.finished_with_findings.emit(result['findings'])
            except Exception as e:
                self.error_occurred.emit(str(e))

            self.progress_update.emit(idx + 1, total)


class ChatWorker(QThread):
    """聊天分析线程"""
    chat_result = Signal(str)
    chat_error = Signal(str)

    def __init__(self, llm, question, system_prompt):
        super().__init__()
        self.llm = llm
        self.question = question
        self.system_prompt = system_prompt

    def run(self):
        """执行聊天分析"""
        try:
            response = self.llm.chat(self.system_prompt, self.question)
            self.chat_result.emit(response)
        except Exception as e:
            self.chat_error.emit(str(e))


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LogAI - 流量日志智能分析平台")
        self.setMinimumSize(1400, 900)
        self.resize(1400, 900)

        self.selected_files = []
        self.log_df = None
        self.current_config = {}
        self.analysis_worker = None
        self.analysis_running = False

        self._init_menubar()
        self._init_statusbar()
        self._init_central_widget()

        self._refresh_model_selector()
        self.load_current_config()

    def _init_menubar(self):
        """初始化菜单栏"""
        menubar = self.menuBar()

        file_menu = menubar.addMenu("文件(&F)")
        self.export_action = file_menu.addAction("导出报告")
        self.export_action.triggered.connect(self.on_export_report)
        file_menu.addSeparator()
        self.exit_action = file_menu.addAction("退出")
        self.exit_action.triggered.connect(self.close)

        settings_menu = menubar.addMenu("设置(&S)")
        self.config_action = settings_menu.addAction("模型供应商配置")
        self.config_action.triggered.connect(self.on_configure_providers)
        self.rules_action = settings_menu.addAction("过滤规则编辑")
        self.rules_action.triggered.connect(self.on_edit_rules)

        view_menu = menubar.addMenu("视图(&V)")
        self.chat_visible_action = view_menu.addAction("显示聊天区")
        self.chat_visible_action.setCheckable(True)
        self.chat_visible_action.setChecked(True)
        self.chat_visible_action.triggered.connect(self.on_toggle_chat)

        help_menu = menubar.addMenu("帮助(&H)")
        self.about_action = help_menu.addAction("关于")
        self.about_action.triggered.connect(self.on_about)

    def _init_statusbar(self):
        """初始化状态栏"""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        self.status_label = QLabel("就绪")
        self.status_bar.addWidget(self.status_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedWidth(200)
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)

    def _init_central_widget(self):
        """初始化中央部件布局"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(6)

        import_bar = QHBoxLayout()
        import_bar.setContentsMargins(0, 0, 0, 0)

        self.import_btn = QPushButton("导入日志文件")
        self.import_btn.clicked.connect(self.on_import_logs)
        import_bar.addWidget(self.import_btn)

        self.file_list_edit = QLineEdit()
        self.file_list_edit.setReadOnly(True)
        self.file_list_edit.setPlaceholderText("未选择文件")
        import_bar.addWidget(self.file_list_edit)

        import_bar.addSpacerItem(QSpacerItem(20, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))

        self.model_selector = QComboBox()
        self.model_selector.currentIndexChanged.connect(self.on_model_changed)
        import_bar.addWidget(self.model_selector)

        self.start_btn = QPushButton("开始分析")
        self.start_btn.clicked.connect(self.on_start_analysis)
        import_bar.addWidget(self.start_btn)

        self.stop_btn = QPushButton("停止")
        self.stop_btn.clicked.connect(self.on_stop_analysis)
        self.stop_btn.setEnabled(False)
        import_bar.addWidget(self.stop_btn)

        main_layout.addLayout(import_bar)

        self.splitter = QSplitter(Qt.Orientation.Vertical)

        self.tab_widget = QTabWidget()
        self._init_analysis_tab()

        attack_chain_widget = QWidget()
        attack_chain_layout = QVBoxLayout(attack_chain_widget)
        attack_chain_layout.addWidget(QLabel("功能开发中…"), alignment=Qt.AlignCenter)
        self.tab_widget.addTab(attack_chain_widget, "攻击链")

        map_widget = QWidget()
        map_layout = QVBoxLayout(map_widget)
        map_layout.addWidget(QLabel("功能开发中…"), alignment=Qt.AlignCenter)
        self.tab_widget.addTab(map_widget, "攻击地图")

        self.splitter.addWidget(self.tab_widget)

        self.chat_panel = QWidget()
        chat_layout = QVBoxLayout(self.chat_panel)
        chat_layout.setContentsMargins(0, 0, 0, 0)

        self.chat_history = QTextEdit()
        self.chat_history.setReadOnly(True)
        self.chat_history.setPlaceholderText("智能对话分析区域...")
        chat_layout.addWidget(self.chat_history)

        input_layout = QHBoxLayout()
        self.chat_input = QLineEdit()
        self.chat_input.returnPressed.connect(self.on_send_chat)
        input_layout.addWidget(self.chat_input)

        self.send_btn = QPushButton("发送")
        self.send_btn.clicked.connect(self.on_send_chat)
        input_layout.addWidget(self.send_btn)

        chat_layout.addLayout(input_layout)

        self.splitter.addWidget(self.chat_panel)

        self.splitter.setStretchFactor(0, 3)
        self.splitter.setStretchFactor(1, 1)

        main_layout.addWidget(self.splitter)

    def _init_analysis_tab(self):
        """初始化分析结果标签页"""
        analysis_widget = QWidget()
        analysis_layout = QVBoxLayout(analysis_widget)

        self.table_view = QTableView()
        self.table_model = QStandardItemModel()

        headers = ["时间", "源IP", "目的IP", "威胁类型", "严重程度", "原始摘要"]
        self.table_model.setHorizontalHeaderLabels(headers)

        self.table_view.setModel(self.table_model)
        self.table_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table_view.customContextMenuRequested.connect(self.on_table_context_menu)

        self.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)

        analysis_layout.addWidget(self.table_view)
        self.tab_widget.addTab(analysis_widget, "分析结果")

    def load_current_config(self):
        """从配置文件加载当前模型配置"""
        config_path = os.path.join(os.path.dirname(__file__), '..', 'configs', 'providers.json')

        default_config = {
            "name": "OpenAI",
            "api_base": "https://api.openai.com/v1",
            "api_key": "",
            "default_model": "gpt-4o"
        }

        try:
            if os.path.exists(config_path):
                with open(config_path, 'r', encoding='utf-8') as f:
                    providers = json.load(f)
                    if providers and len(providers) > 0:
                        selected_index = self.model_selector.currentIndex()
                        
                        if selected_index >= 0 and selected_index < len(providers):
                            provider = providers[selected_index]
                        else:
                            provider = providers[0]
                        
                        self.current_config = {
                            "name": provider.get('name', 'OpenAI'),
                            "api_base": provider.get('api_base', ''),
                            "api_key": provider.get('api_key', ''),
                            "default_model": provider.get('default_model', '')
                        }
                    else:
                        self.current_config = default_config
            else:
                self.current_config = default_config
        except Exception:
            self.current_config = default_config

        self._update_statusbar()

    def _update_statusbar(self):
        """更新状态栏显示当前模型信息"""
        name = self.current_config.get('name', 'Unknown')
        model = self.current_config.get('default_model', 'Unknown')
        self.status_label.setText(f"就绪 | 当前模型：{name} - {model}")

    def _refresh_model_selector(self):
        """刷新模型选择器下拉框"""
        config_path = os.path.join(os.path.dirname(__file__), '..', 'configs', 'providers.json')
        
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r', encoding='utf-8') as f:
                    providers = json.load(f)
                
                self.model_selector.blockSignals(True)
                self.model_selector.clear()
                
                for provider in providers:
                    name = provider.get('name', '')
                    model = provider.get('default_model', '')
                    display_text = f"{name} - {model}"
                    self.model_selector.addItem(display_text)
                
                self.model_selector.blockSignals(False)
        except Exception:
            pass

    def on_model_changed(self, index):
        """模型选择器选中项改变时的处理"""
        if index < 0:
            return
        
        config_path = os.path.join(os.path.dirname(__file__), '..', 'configs', 'providers.json')
        
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r', encoding='utf-8') as f:
                    providers = json.load(f)
                
                if 0 <= index < len(providers):
                    provider = providers[index]
                    self.current_config = {
                        "name": provider.get('name', 'Unknown'),
                        "api_base": provider.get('api_base', ''),
                        "api_key": provider.get('api_key', ''),
                        "default_model": provider.get('default_model', '')
                    }
                    self._update_statusbar()
        except Exception:
            pass

    def on_import_logs(self):
        """导入日志文件"""
        files, _ = QFileDialog.getOpenFileNames(
            self, "选择日志文件", "", "日志文件 (*.pcap *.pcapng *.csv *.txt *.log);;所有文件 (*)"
        )
        if files:
            self.selected_files = files
            try:
                self.log_df = LogLoader.batch_load(self.selected_files)
                count = len(self.log_df)
                self.file_list_edit.setText(f"已选 {len(self.selected_files)} 个文件")
                self.status_label.setText(f"加载完成：共 {count} 条日志记录")
                
                # 填充表格
                self._populate_log_table()
            except Exception as e:
                QMessageBox.critical(self, "加载失败", f"日志文件加载失败：{str(e)}")
                self.file_list_edit.setText("未选择文件")
        else:
            self.file_list_edit.setText("未选择文件")

    def _populate_log_table(self):
        """将日志数据填充到表格"""
        # 清空现有数据
        self.table_model.clear()
        headers = ["时间", "源IP", "目的IP", "威胁类型", "严重程度", "分析结果", "原始摘要"]
        self.table_model.setHorizontalHeaderLabels(headers)
        
        if self.log_df is not None and not self.log_df.empty:
            from PySide6.QtGui import QStandardItem
            
            for _, row in self.log_df.iterrows():
                timestamp = QStandardItem(row.get('timestamp', ''))
                src_ip = QStandardItem(row.get('src_ip', ''))
                dst_ip = QStandardItem(row.get('dst_ip', ''))
                threat_type = QStandardItem('')  # 待分析
                severity = QStandardItem('')     # 待分析
                analysis = QStandardItem('')     # 分析结果
                summary = QStandardItem(row.get('payload_summary', '')[:150])
                
                self.table_model.appendRow([timestamp, src_ip, dst_ip, threat_type, severity, analysis, summary])

    def on_send_chat(self):
        """发送聊天消息"""
        message = self.chat_input.text().strip()
        if message:
            self.chat_history.append(f"用户: {message}")
            self.chat_input.clear()
            self.process_chat_query(message)

    def process_chat_query(self, question: str):
        """处理聊天查询"""
        # 检查日志是否已加载
        if self.log_df is None or self.log_df.empty:
            self.chat_history.append("助手: 请先导入日志文件。")
            return

        # 检查模型配置
        if not self.current_config:
            self.chat_history.append("助手: 请先配置模型。")
            return

        # 构建系统提示词
        system_prompt = """你是一个日志数据分析助手。用户会用中文提问，你需要通过操作一个已经存在的 pandas DataFrame 变量 df 来回答。
df 列名：timestamp, src_ip, dst_ip, protocol, payload_summary, raw
规则：
- 只能生成 Python 代码，不能包含 import、eval、exec、os、subprocess 等危险模块。
- 只能使用 df 变量，不能修改它，不能写入文件。
- 最后一行将结果赋值给 result 变量，并确保 result 可序列化（字典、列表、标量、DataFrame 转 dict）。
- 如果问题超出日志数据范围，请回复“超出范围”。
示例：
用户：“源IP为192.168.1.5的流量有多少条？”
你的回复：result = df[df['src_ip'] == '192.168.1.5'].shape[0]"""

        # 创建 LLM 实例
        try:
            llm = create_llm(self.current_config)
        except Exception as e:
            self.chat_history.append(f"助手: 模型创建失败: {str(e)}")
            return

        # 启动聊天线程
        self.chat_worker = ChatWorker(llm, question, system_prompt)
        self.chat_worker.chat_result.connect(self.on_chat_result)
        self.chat_worker.chat_error.connect(self.on_chat_error)
        self.chat_worker.start()

    def on_chat_result(self, response: str):
        """处理聊天结果"""
        import re
        import pandas as pd
        import json

        try:
            # 提取代码块
            code_patterns = [
                r'```python\s*(.*?)\s*```',
                r'```\s*(.*?)\s*```',
                r'([\s\S]*)'
            ]

            code = None
            for pattern in code_patterns:
                match = re.search(pattern, response, re.DOTALL)
                if match:
                    code = match.group(1).strip()
                    break

            if not code:
                self.chat_history.append(f"助手: {response}")
                return

            # 检查是否为"超出范围"
            if "超出范围" in code:
                self.chat_history.append("助手: 超出范围")
                return

            # 安全执行代码
            namespace = {'df': self.log_df, 'pd': pd, 'result': None}
            exec(code, namespace)
            result = namespace.get('result')

            # 格式化结果
            if result is None:
                answer = "未获取到结果"
            elif isinstance(result, pd.DataFrame):
                answer = result.to_string(max_rows=10, max_cols=6)
            elif isinstance(result, (list, dict)):
                answer = json.dumps(result, ensure_ascii=False, indent=2)
            else:
                answer = str(result)

            self.chat_history.append(f"助手: {answer}")
        except Exception as e:
            self.chat_history.append(f"助手: 执行失败: {str(e)}")

    def on_chat_error(self, error: str):
        """处理聊天错误"""
        self.chat_history.append(f"助手: 错误: {error}")

    def on_export_report(self):
        """导出报告"""
        pass

    def on_configure_providers(self):
        """打开模型供应商配置对话框"""
        dialog = SettingsDialog(self)
        dialog.test_connection_requested.connect(self.on_test_connection)
        dialog.exec()
        self._refresh_model_selector()
        if self.model_selector.count() > 0:
            self.model_selector.setCurrentIndex(0)
        self.load_current_config()

    def on_edit_rules(self):
        """编辑过滤规则"""
        pass

    def on_about(self):
        """关于对话框"""
        pass

    def on_toggle_chat(self, checked):
        """显示/隐藏聊天区"""
        self.chat_panel.setVisible(checked)

    def on_table_context_menu(self, pos):
        """表格右键菜单"""
        menu = QMenu()
        mark_action = menu.addAction("标记为误报")
        detail_action = menu.addAction("查看详情")

        action = menu.exec(self.table_view.mapToGlobal(pos))
        if action == mark_action:
            pass
        elif action == detail_action:
            pass

    def on_test_connection(self, provider_name):
        """测试连接"""
        config_path = os.path.join(os.path.dirname(__file__), '..', 'configs', 'providers.json')
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                providers = json.load(f)
            
            # 查找指定名称的提供商配置（精确匹配）
            provider_config = None
            for p in providers:
                if p.get('name') == provider_name:
                    provider_config = p
                    break
            
            if not provider_config:
                QMessageBox.warning(self, "连接失败", f"未找到提供商配置: {provider_name}")
                return
            
            # 创建 LLM 适配器并测试连接
            llm = create_llm(provider_config)
            self.status_label.setText("正在测试连接...")
            
            success = llm.test_connection()
            
            if success:
                model_name = provider_config.get('default_model', '未知')
                QMessageBox.information(self, "连接成功", 
                                       f"提供商：{provider_name}\n模型：{model_name} 连接正常！")
                self.load_current_config()  # 连接成功后更新状态栏
            else:
                QMessageBox.warning(self, "连接失败", 
                                   f"无法连接到 {provider_name}，请检查配置和网络。")
                
        except Exception as e:
            QMessageBox.critical(self, "错误", f"测试连接出错：{str(e)}")
        
        # 恢复状态显示
        self._update_statusbar()

    def on_start_analysis(self):
        """开始分析"""
        # 检查日志是否已加载
        if self.log_df is None or self.log_df.empty:
            QMessageBox.warning(self, "警告", "请先导入日志文件")
            return

        # 检查配置
        if not self.current_config:
            QMessageBox.warning(self, "警告", "请先配置模型供应商")
            return

        # 使用过滤器筛选可疑日志
        funnel = FilterFunnel()
        suspicious_df = funnel.filter(self.log_df)

        if suspicious_df.empty:
            QMessageBox.information(self, "提示", "未发现可疑流量，无需分析")
            return

        # 将可疑日志转换为文本块
        chunks = []
        chunk_size = 20  # 每20行一个块
        rows = []
        for _, row in suspicious_df.iterrows():
            row_text = f"{row.get('timestamp', '')} {row.get('protocol', '')} {row.get('src_ip', '')}: -> {row.get('dst_ip', '')}: {row.get('payload_summary', '')}"
            rows.append(row_text)
            
            if len(rows) >= chunk_size:
                chunks.append('\n'.join(rows))
                rows = []
        
        if rows:
            chunks.append('\n'.join(rows))

        # 创建LLM实例
        try:
            llm = create_llm(self.current_config)
        except Exception as e:
            QMessageBox.critical(self, "错误", f"创建LLM实例失败：{str(e)}")
            return

        # 创建并启动分析线程
        self.analysis_worker = AnalysisWorker(llm, chunks)
        self.analysis_worker.finished_with_findings.connect(self.on_new_findings)
        self.analysis_worker.progress_update.connect(self.on_progress_update)
        self.analysis_worker.error_occurred.connect(self.on_analysis_error)
        self.analysis_worker.stopped.connect(self.on_analysis_stopped)

        # 更新UI状态
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("分析中...")
        self.analysis_running = True

        # 保留原始日志数据，分析后更新威胁信息
        # 先清空之前的威胁标记
        for row in range(self.table_model.rowCount()):
            threat_item = self.table_model.item(row, 3)
            severity_item = self.table_model.item(row, 4)
            analysis_item = self.table_model.item(row, 5)
            if threat_item:
                threat_item.setText('')
                threat_item.setForeground(QBrush(Qt.black))
            if severity_item:
                severity_item.setText('')
                severity_item.setForeground(QBrush(Qt.black))
            if analysis_item:
                analysis_item.setText('')
                analysis_item.setForeground(QBrush(Qt.black))

        # 启动后台线程
        self.analysis_worker.start()

    def on_stop_analysis(self):
        """停止分析"""
        if self.analysis_worker and self.analysis_worker.isRunning():
            self.analysis_worker.requestInterruption()
        
        # 恢复按钮状态（实际恢复在on_analysis_stopped中）
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.status_label.setText("分析已停止")
        self.analysis_running = False

    def on_new_findings(self, findings_list):
        """处理新发现的威胁 - 更新现有行而不是添加新行"""
        from PySide6.QtGui import QBrush
        
        for finding in findings_list:
            src_ip = finding.get('src_ip', '')
            dst_ip = finding.get('dst_ip', '')
            threat_type = finding.get('type', '')
            severity = finding.get('severity', '')
            description = finding.get('description', '')[:150]

            # 根据源IP和目的IP查找匹配的行
            for row in range(self.table_model.rowCount()):
                row_src_ip = self.table_model.item(row, 1)
                row_dst_ip = self.table_model.item(row, 2)
                
                if row_src_ip and row_dst_ip:
                    if row_src_ip.text() == src_ip and row_dst_ip.text() == dst_ip:
                        # 更新威胁类型
                        threat_item = self.table_model.item(row, 3)
                        if threat_item:
                            threat_item.setText(threat_type)
                        else:
                            from PySide6.QtGui import QStandardItem
                            threat_item = QStandardItem(threat_type)
                            self.table_model.setItem(row, 3, threat_item)
                        
                        # 更新严重程度
                        severity_item = self.table_model.item(row, 4)
                        if severity_item:
                            severity_item.setText(severity)
                        else:
                            severity_item = QStandardItem(severity)
                            self.table_model.setItem(row, 4, severity_item)
                        
                        # 更新分析结果（第6列）
                        analysis_item = self.table_model.item(row, 5)
                        if analysis_item:
                            analysis_item.setText(description)
                        else:
                            analysis_item = QStandardItem(description)
                            self.table_model.setItem(row, 5, analysis_item)
                        
                        # 根据严重程度设置颜色（不影响原始摘要列）
                        if severity == 'high':
                            brush = QBrush(Qt.red)
                            for col in range(6):  # 只给前6列着色
                                item = self.table_model.item(row, col)
                                if item:
                                    item.setForeground(brush)
                        elif severity == 'medium':
                            brush = QBrush(Qt.darkYellow)
                            for col in range(6):  # 只给前6列着色
                                item = self.table_model.item(row, col)
                                if item:
                                    item.setForeground(brush)
                        
                        break  # 找到匹配行后退出循环

    def on_progress_update(self, cur, total):
        """更新进度"""
        if total > 0:
            self.progress_bar.setValue(int(cur / total * 100))

    def on_analysis_error(self, msg):
        """处理分析错误"""
        QMessageBox.warning(self, "分析错误", f"分析过程中发生错误：{msg}")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.status_label.setText("分析失败")
        self.analysis_running = False

    def on_analysis_stopped(self):
        """分析停止"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.status_label.setText("分析已停止")
        self.analysis_running = False
