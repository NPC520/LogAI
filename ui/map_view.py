from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QHBoxLayout, QComboBox
from PySide6.QtWebEngineWidgets import QWebEngineView


class MapView(QWidget):
    """攻击来源地图视图"""

    def __init__(self, min_zoom=2, max_zoom=4):
        super().__init__()
        self.min_zoom = min_zoom
        self.max_zoom = max_zoom
        self._init_ui()

    def _init_ui(self):
        """初始化界面"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # 顶部控制栏
        control_layout = QHBoxLayout()
        control_layout.setContentsMargins(4, 4, 4, 4)

        # 状态标签
        self.status_label = QLabel("加载地图中...")
        self.status_label.setStyleSheet("color: gray; font-size: 12px;")
        control_layout.addWidget(self.status_label)

        control_layout.addStretch()

        # 瓦片层级选择器
        self.zoom_label = QLabel("地图细节：")
        self.zoom_label.setStyleSheet("color: gray; font-size: 12px;")
        control_layout.addWidget(self.zoom_label)

        self.zoom_selector = QComboBox()
        for z in range(self.min_zoom, self.max_zoom + 1):
            if z == 2:
                desc = "世界"
            elif z == 3:
                desc = "大洲"
            elif z == 4:
                desc = "国家"
            elif z == 5:
                desc = "城市"
            elif z == 6:
                desc = "区县"
            else:
                desc = f"级别{z}"
            self.zoom_selector.addItem(f"{z}级（{desc}）", z)

        self.zoom_selector.setStyleSheet("""
            QComboBox {
                background: rgba(50, 50, 50, 0.8);
                color: white;
                border: 1px solid rgba(100, 100, 100, 0.5);
                border-radius: 4px;
                padding: 2px 6px;
                min-width: 80px;
            }
            QComboBox:hover {
                border: 1px solid rgba(100, 200, 140, 0.7);
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox QAbstractItemView {
                background: rgba(40, 40, 50, 0.95);
                color: white;
                selection-background-color: rgba(100, 200, 140, 0.5);
            }
        """)
        self.zoom_selector.currentIndexChanged.connect(self.on_zoom_level_changed)
        control_layout.addWidget(self.zoom_selector)

        layout.addLayout(control_layout)

        # Web 视图显示地图
        self.web_view = QWebEngineView()
        layout.addWidget(self.web_view)

        # 初始化地图
        self.init_map()

    def init_map(self):
        """初始化 Leaflet 地图"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>攻击来源地图</title>
            <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
            <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                html, body, #map { width: 100%; height: 100vh; }
            </style>
        </head>
        <body>
            <div id="map"></div>
            <script>
                var map = L.map('map', {
                    minZoom: 2,
                    maxZoom: 4,
                    zoomControl: true
                }).setView([20, 0], 3);

                L.tileLayer('https://webrd0{s}.is.autonavi.com/appmaptile?lang=zh_cn&size=1&scale=1&style=8&x={x}&y={y}&z={z}', {
                    maxZoom: 4,
                    minZoom: 2,
                    subdomains: ['1','2','3','4'],
                    attribution: '&copy; 高德地图'
                }).addTo(map);

                var markers = [];

                function updateMap(locations) {
                    markers.forEach(function(m) { map.removeLayer(m); });
                    markers = [];

                    if (!locations || locations.length === 0) return;

                    var bounds = [];
                    locations.forEach(function(loc) {
                        if (loc.lat === 0 && loc.lon === 0) return;

                        var radius = Math.min(loc.count * 3, 20);
                        var color = loc.count >= 5 ? '#ff0000' : '#ff9900';

                        var circle = L.circleMarker([loc.lat, loc.lon], {
                            radius: radius,
                            fillColor: color,
                            color: '#000',
                            weight: 1,
                            fillOpacity: 0.7
                        }).addTo(map);

                        circle.bindPopup(
                            '<b>' + (loc.city || '未知') + ', ' + (loc.country || '未知') + '</b><br>' +
                            'IP: ' + loc.ip + '<br>攻击次数: ' + loc.count
                        );

                        markers.push(circle);
                        bounds.push([loc.lat, loc.lon]);
                    });

                    if (bounds.length > 0) {
                        map.fitBounds(bounds, { padding: [50, 50] });
                    }
                }

                function setZoomLevel(level) {
                    map.setMinZoom(level);
                    map.setMaxZoom(level);
                    map.setZoom(level);
                }
            </script>
        </body>
        </html>
        """
        self.web_view.setHtml(html)

    def on_zoom_level_changed(self, index):
        """瓦片层级切换"""
        level = self.zoom_selector.itemData(index)
        js_code = f"setZoomLevel({level});"
        self.web_view.page().runJavaScript(js_code)

    def update_map(self, locations: list):
        """更新地图标记"""
        if not locations or len(locations) == 0:
            self.status_label.setText("暂无攻击来源")
            js_code = "updateMap([]);"
            self.web_view.page().runJavaScript(js_code)
            return

        self.status_label.setText(f"发现 {len(locations)} 个攻击来源")

        locations_json = []
        for loc in locations:
            locations_json.append({
                "ip": loc["ip"],
                "lat": loc["lat"],
                "lon": loc["lon"],
                "city": loc["city"],
                "country": loc["country"],
                "count": loc["count"]
            })

        import json
        js_code = f"updateMap({json.dumps(locations_json)});"
        self.web_view.page().runJavaScript(js_code)

    def clear_map(self):
        """清除地图标记"""
        self.status_label.setText("暂无攻击来源")
        js_code = "updateMap([]);"
        self.web_view.page().runJavaScript(js_code)