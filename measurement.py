import requests

API_KEY = "这里替换成你在RIPE Atlas申请的API Key"
# 🚨 关键修改：直接使用域名，不要用IP！
TARGET_HOST = "walletapi.mobikwik.com"  

payload = {
    "definitions": [
        {
            "target": TARGET_HOST, 
            "af": 4,
            "type": "ping", 
            "packets": 5,
            "resolve_on_probe": True, # 让每个探针在当地真实解析DNS
            "description": "MobiKwik API - Ping"
        },
        {
            "target": TARGET_HOST, 
            "af": 4,
            "type": "traceroute", 
            "protocol": "TCP",
            "port": 443, 
            "max_hops": 32,
            "resolve_on_probe": True, # 同上
            "description": "MobiKwik API - Traceroute TCP/443"
        }
    ],
    "probes": [
        # 实验组：印度本土
        {"type": "country", "value": "IN", "requested": 5}, 
        # 对照组：海外节点（看看延迟会不会飙升）
        {"type": "country", "value": "SG", "requested": 2},
        {"type": "country", "value": "DE", "requested": 2},
        {"type": "country", "value": "US", "requested": 2}
    ],
    "is_oneoff": True
}

r = requests.post(
    "https://atlas.ripe.net/api/v2/measurements/",
    json=payload,
    headers={"Authorization": f"Key {API_KEY}", "Content-Type": "application/json"}
)

print(f"HTTP {r.status_code}: {r.text}")

data = r.json()
if "measurements" not in data:
    raise RuntimeError(f"API error: {data}")

msm_ids = data["measurements"]
print(f"🎉 任务创建成功！")
print(f"Ping 测试 ID: {msm_ids[0]}")
print(f"Traceroute 测试 ID: {msm_ids[1]}")
print(f"去浏览器查看结果(Ping): https://atlas.ripe.net/measurements/{msm_ids[0]}/")
print(f"去浏览器查看结果(Traceroute): https://atlas.ripe.net/measurements/{msm_ids[1]}/")