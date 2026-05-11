import os
import sys
import ipaddress
import pandas as pd

try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False


def _get_base_path():
    if getattr(sys, 'frozen', False):
        return sys._MEIPASS
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class GeoService:
    """GeoIP 查询服务"""

    def __init__(self, db_path: str = None):
        """
        初始化 GeoIP 服务
        
        Args:
            db_path: GeoLite2-City.mmdb 文件路径，默认为项目根目录
        """
        if db_path is None:
            db_path = os.path.join(_get_base_path(), 'GeoLite2-City.mmdb')
        
        self.db_path = os.path.abspath(db_path)
        self.reader = None
        
        if GEOIP_AVAILABLE and os.path.exists(self.db_path):
            try:
                self.reader = geoip2.database.Reader(self.db_path)
            except Exception as e:
                print(f"GeoIP 数据库打开失败: {e}")

    def is_private_ip(self, ip: str) -> bool:
        """判断是否为内网 IP"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return True

    def query(self, ip: str) -> dict:
        """
        查询单个 IP 的地理位置
        
        Args:
            ip: IP 地址字符串
            
        Returns:
            包含地理位置信息的字典
        """
        result = {
            "ip": ip,
            "is_private": False,
            "country": "未知",
            "city": "",
            "latitude": 0,
            "longitude": 0
        }

        # 检查是否为内网 IP
        if self.is_private_ip(ip):
            result["is_private"] = True
            result["country"] = "内网"
            return result

        # 如果没有数据库，返回未知
        if self.reader is None:
            return result

        try:
            response = self.reader.city(ip)
            
            if response.country.name:
                result["country"] = response.country.name
            
            if response.city.name:
                result["city"] = response.city.name
            
            if response.location.latitude:
                result["latitude"] = response.location.latitude
            
            if response.location.longitude:
                result["longitude"] = response.location.longitude

        except geoip2.errors.AddressNotFoundError:
            result["country"] = "未知"
        except Exception as e:
            print(f"GeoIP 查询失败 {ip}: {e}")

        return result

    def batch_query(self, ip_list: list) -> list:
        """
        批量查询 IP 地理位置
        
        Args:
            ip_list: IP 地址列表
            
        Returns:
            包含地理位置信息的列表，每个元素增加 count 字段
        """
        if not ip_list:
            return []

        # 统计每个 IP 出现次数
        ip_counts = {}
        for ip in ip_list:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

        # 去重后查询
        results = []
        for ip, count in ip_counts.items():
            info = self.query(ip)
            info["count"] = count
            results.append(info)

        return results

    def get_attack_locations(self, findings_df: pd.DataFrame) -> list:
        """
        从分析结果中提取攻击来源位置
        
        Args:
            findings_df: 包含 src_ip 列的 DataFrame
            
        Returns:
            攻击位置列表，格式:
            [{"ip": "x.x.x.x", "lat": 35.0, "lon": 139.0, "city": "Tokyo", "country": "Japan", "count": 5}, ...]
        """
        if findings_df is None or findings_df.empty:
            return []

        # 提取所有源 IP
        ip_list = findings_df['src_ip'].dropna().tolist()
        
        # 批量查询
        results = self.batch_query(ip_list)
        
        # 过滤内网 IP，只保留外网攻击来源
        locations = []
        for result in results:
            if not result['is_private'] and result['latitude'] != 0:
                locations.append({
                    "ip": result["ip"],
                    "lat": result["latitude"],
                    "lon": result["longitude"],
                    "city": result["city"],
                    "country": result["country"],
                    "count": result["count"]
                })

        return locations

    def close(self):
        """关闭数据库连接"""
        if self.reader is not None:
            self.reader.close()

    def __del__(self):
        """析构函数，确保关闭连接"""
        self.close()


if __name__ == "__main__":
    # 测试
    service = GeoService()
    print(f"GeoIP 数据库可用: {service.reader is not None}")
    
    test_ips = ["8.8.8.8", "192.168.1.1", "223.5.5.5"]
    for ip in test_ips:
        result = service.query(ip)
        print(f"{ip}: {result}")
    
    service.close()
