import requests

API_KEY = "Your_RIPE_Atlas_API_Key"  # to be changed
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
        # India — 10 candidate ASNs, RIPE Atlas picks whichever have
        # available probes; expect 5-8 actual probes returned
        {"type": "asn", "value": 24560,  "requested": 1},   # Airtel Broadband
        {"type": "asn", "value": 9498,   "requested": 1},   # Airtel (AS2)
        {"type": "asn", "value": 45609,  "requested": 1},   # Airtel Mobile
        {"type": "asn", "value": 55836,  "requested": 1},   # Reliance Jio
        {"type": "asn", "value": 9829,   "requested": 1},   # BSNL
        {"type": "asn", "value": 17813,  "requested": 1},   # Idea / Vodafone Vi
        {"type": "asn", "value": 18101,  "requested": 1},   # Reliance Communications
        {"type": "asn", "value": 24309,  "requested": 1},   # Atria Convergence (South India)
        {"type": "asn", "value": 38266,  "requested": 1},   # Excitel Broadband
        {"type": "asn", "value": 132780, "requested": 1},   # Tata Play Fiber
        # Overseas
        # Singapore — StarHub or Singtel retail
        {"type": "asn", "value": 9506,  "requested": 1},   # Singtel Fibre
        {"type": "asn", "value": 7473,  "requested": 1},   # Singtel Mobile / Enterprise
        {"type": "asn", "value": 24514, "requested": 1},   # ViewQwest
        # EU — three countries for broader European coverage
        # Germany (Frankfurt — DE-CIX, largest IX in Europe)
        {"type": "asn", "value": 3320,  "requested": 1},   # Deutsche Telekom
        # Netherlands (Amsterdam — AMS-IX, second largest IX in Europe)
        {"type": "asn", "value": 1101,  "requested": 1},   # SURFnet
        # France (Paris — France-IX)
        {"type": "asn", "value": 5410,  "requested": 1},   # Bouygues Telecom
        # US East
        {"type": "asn", "value": 7922,  "requested": 1},   # Comcast
        {"type": "asn", "value": 701,   "requested": 1},   # Verizon
        {"type": "asn", "value": 6167,  "requested": 1},   # Verizon Wireless
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