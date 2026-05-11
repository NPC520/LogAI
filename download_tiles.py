# download_tiles.py
import os
import requests
import math
import time

# ===== 配置区域 =====
MIN_ZOOM = 2           # 世界全览只需 2-4 级；到 7 级文件会很大
MAX_ZOOM = 4           # 推荐先用 4 级测试，速度快
TILE_DIR = "tiles"
# 高德地图瓦片源（国内极快），{s} 自动替换为 1-4
TILE_URL = "https://webrd0{s}.is.autonavi.com/appmaptile?lang=zh_cn&size=1&scale=1&style=8&x={x}&y={y}&z={z}"
# =====================


def download_tile(z, x, y, retries=3):
    """下载单个瓦片，支持重试"""
    # {s} 在 1-4 之间随机取，实现负载均衡
    s = (x + y) % 4 + 1
    url = TILE_URL.replace('{s}', str(s)).format(z=z, x=x, y=y)
    
    dir_path = os.path.join(TILE_DIR, str(z), str(x))
    os.makedirs(dir_path, exist_ok=True)
    filepath = os.path.join(dir_path, f"{y}.png")
    
    if os.path.exists(filepath):
        return  # 已存在则跳过
    
    for attempt in range(retries):
        try:
            resp = requests.get(url, timeout=15, headers={'User-Agent': 'LogAI/1.0'})
            if resp.status_code == 200:
                with open(filepath, 'wb') as f:
                    f.write(resp.content)
                return
            else:
                print(f"  HTTP {resp.status_code}: {url}")
        except Exception as e:
            print(f"  尝试 {attempt+1}/{retries} 出错: {e}")
            time.sleep(0.5)
    print(f"  下载彻底失败: {url}")


if __name__ == "__main__":
    print(f"开始下载世界地图瓦片 (级别 {MIN_ZOOM}-{MAX_ZOOM})...")
    total_tiles = sum(int(math.pow(2, z)) ** 2 for z in range(MIN_ZOOM, MAX_ZOOM + 1))
    downloaded = 0
    
    for z in range(MIN_ZOOM, MAX_ZOOM + 1):
        count = int(math.pow(2, z))
        print(f"下载第 {z} 级，共 {count}x{count} 张瓦片...")
        for x in range(count):
            for y in range(count):
                download_tile(z, x, y)
                downloaded += 1
                if downloaded % 50 == 0:
                    print(f"  已完成 {downloaded}/{total_tiles}")
    
    print(f"全部完成！瓦片已保存到 {TILE_DIR} 文件夹。")