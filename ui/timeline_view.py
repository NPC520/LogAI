from PySide6.QtWidgets import QWidget, QVBoxLayout
from PySide6.QtWebEngineWidgets import QWebEngineView


class TimelineView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
        self.init_timeline()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.web_view = QWebEngineView()
        layout.addWidget(self.web_view)

    def init_timeline(self):
        html = """<!DOCTYPE html>
<html>
<head>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis-timeline-graph2d.min.css" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis-timeline-graph2d.min.js"></script>
    <style>
        body { margin: 0; padding: 0; font-family: Arial, sans-serif; }
        #visualization { width: 100%; height: 100vh; }
        .vis-item.red { background-color: #ff4444; border-color: #cc0000; color: white; }
        .vis-item.yellow { background-color: #ffaa00; border-color: #cc8800; color: black; }
        .vis-item.blue { background-color: #4488ff; border-color: #2266cc; color: white; }
    </style>
</head>
<body>
    <div id="visualization"></div>
    <script>
        var container = document.getElementById('visualization');
        var items = new vis.DataSet([]);
        var options = {
            editable: false,
            start: '2024-01-01',
            end: '2024-12-31',
            zoomMin: 60000,
            zoomMax: 31536000000,
            height: '100%',
            width: '100%'
        };
        var timeline = new vis.Timeline(container, items, options);

        function updateItems(newItems) {
            items.clear();
            items.add(newItems);
            if (newItems.length > 0) {
                timeline.fit();
            }
        }

        function clearItems() {
            items.clear();
        }
    </script>
</body>
</html>"""
        self.web_view.setHtml(html)

    def update_timeline(self, stages: list):
        if not stages:
            self._clear_timeline()
            return

        items = []
        for idx, stage in enumerate(stages):
            tactic = stage.get('tactic', '').lower()
            if any(t in tactic for t in ['initial access', 'execution', 'persistence', 'privilege escalation', 'defense evasion', 'collection', 'exfiltration', 'impact']):
                class_name = 'red'
            elif any(t in tactic for t in ['reconnaissance', 'resource development', 'command and control', 'discovery', 'lateral movement']):
                class_name = 'yellow'
            else:
                class_name = 'blue'

            content = f"<b>{stage.get('technique_id', 'T0000')}</b><br>{stage.get('technique_name', '')}"
            title = f"Tactic: {stage.get('tactic', 'Unknown')}\n\nDescription: {stage.get('description', '')}\n\nEvidence: {stage.get('evidence', '')}"

            item = {
                'id': idx,
                'content': content,
                'start': stage.get('timestamp', '2024-01-01'),
                'className': class_name,
                'title': title.replace('\n', '<br>')
            }
            items.append(item)

        js_code = f"updateItems({items});"
        self.web_view.page().runJavaScript(js_code)

    def _clear_timeline(self):
        self.web_view.page().runJavaScript("clearItems();")
