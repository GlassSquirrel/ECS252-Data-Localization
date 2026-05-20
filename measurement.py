import requests

API_KEY = "d65aa759-333c-49d8-ab48-7460d9406424"  # to be changed
# use the domain instead of IP address!
TARGET_HOST = "static.mobikwik.com"  # to be changed

payload = {
    "definitions": [
        {
            "target": TARGET_HOST, 
            "af": 4,
            "type": "ping", 
            "packets": 5,
            "resolve_on_probe": True, # let evert probe resolve DNS locally
            "description": "MobiKwik CDN - Ping"    # to be changed
        },
        {
            "target": TARGET_HOST, 
            "af": 4,
            "type": "traceroute", 
            "protocol": "TCP",
            "port": 443, 
            "max_hops": 32,
            "resolve_on_probe": True, 
            "description": "MobiKwik CDN - Traceroute TCP/443"   # to be changed
        }
    ],
    "probes": [
        # India
        {"type": "country", "value": "IN", "requested": 5}, 
        # Overseas
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
print(f"🎉 Successfully create the measurements！")
print(f"Ping testing ID: {msm_ids[0]}")
print(f"Traceroute testing ID: {msm_ids[1]}")
print(f"To view the results (Ping): https://atlas.ripe.net/measurements/{msm_ids[0]}/")
print(f"To view the results (Traceroute): https://atlas.ripe.net/measurements/{msm_ids[1]}/")