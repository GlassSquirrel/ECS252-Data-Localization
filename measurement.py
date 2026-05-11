import requests

API_KEY = "your_atlas_api_key"
TARGET_IP = "xx.xxx.xxx.xxx"   # 来自dig结果

payload = {
    "definitions": [
        {
            "target": TARGET_IP, "af": 4,
            "type": "ping", "packets": 5,
            "description": "your_provider_name api.glb - Ping"
        },
        {
            "target": TARGET_IP, "af": 4,
            "type": "traceroute", "protocol": "TCP",
            "port": 443, "max_hops": 32,
            "description": "your_provider_name api.glb - Traceroute TCP/443"
        }
    ],
    "probes": [
        {"type": "country", "value": "IN", "requested": 5},
        {"type": "country", "value": "SG", "requested": 2},
        {"type": "country", "value": "DE", "requested": 2},
        {"type": "country", "value": "US", "requested": 2}
    ],
    "is_oneoff": True
}

r = requests.post(
    "https://atlas.ripe.net/api/v2/measurements/",
    json=payload,
    headers={"Authorization": f"Key {API_KEY}"}
)

print(f"HTTP {r.status_code}: {r.text}")

data = r.json()
if "measurements" not in data:
    raise RuntimeError(f"API error: {data}")

msm_ids = data["measurements"]
print(f"Ping ID: {msm_ids[0]}, Traceroute ID: {msm_ids[1]}")