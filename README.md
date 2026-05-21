# Data Localization Project Instructions
## 0: 环境准备
Python 版本：3.11

环境配置：
```bash
pip install -r requirements.txt
```

## 1: 确定目标端点
以`api.paypal.com`为例：
先用 dig 或 nslookup 从印度解析这些域名，获取目标IP：

```bash
dig api.paypal.com @8.8.8.8
```

输出示例：

```
; <<>> DiG 9.10.6 <<>> api.paypal.com @8.8.8.8
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 63879
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;api.paypal.com.                        IN      A

;; ANSWER SECTION:
api.paypal.com.         64      IN      CNAME   api.glb.paypal.com.
api.glb.paypal.com.     60      IN      A       66.211.168.123

;; Query time: 194 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Sun May 10 11:05:36 PDT 2026
;; MSG SIZE  rcvd: 81```
```

可得到以下信息：

```
api.paypal.com.      CNAME     api.glb.paypal.com. 
api.glb.paypal.com.  A         66.211.168.123
```

可知 **Target IP** 为`66.211.168.123`。

关键信号：`glb = Global Load Balancer`，高度疑似 **Anycast** 部署。 意味着不同地区的探针可能命中不同的物理服务器。

（非必要）可以用 GEOIP 进行初判：

```bash
curl https://ipinfo.io/66.211.168.123/json
```

输出示例：

```
{
  "ip": "66.211.168.123",
  "city": "San Jose",
  "region": "California",
  "country": "US",
  "loc": "37.3864,-121.8800",
  "org": "AS54113 Fastly, Inc.",
  "postal": "95131",
  "timezone": "America/Los_Angeles",
  "readme": "https://ipinfo.io/missingauth",
  "anycast": true
}
```

显示 US → 强烈暗示未本地化。

## 2: 在RIPE Atlas选择探针
|位置|作用|建议探针数|优先ASN|
|---|---|---|---|
|🇮🇳 India (Mumbai/Delhi)|验证本地路由|5个|Jio, Airtel, BSNL|
|🇸🇬 Singapore|东南亚参照点|2个|任意|
|🇩🇪 Frankfurt|欧洲参照点|2个|任意|
|🇺🇸 US-East|美国参照点|2个|任意|

⚠️ 印度探针选择多个不同ISP（Jio/Airtel/BSNL），避免单一运营商路由偏差影响结论

*以上选择仅供参考，可根据具体情况进行调整*
（这一步不用进行实际操作，只是说明探针的选择方式）

## 3: 提交测量任务 (Atlas API)
去 RIPE Atlas 的 dashboard 里面找到 My API Keys，创建你自己的 API Key，permission 一定要选择添加 **Schedule a new measurement** 进行授权。如果后续跑代码出现授权问题大概率是这里出错了。

进入`measurement.py`，根据实际情况修改以下位置的代码: 

```python
API_KEY = "your_atlas_api_key" 
TARGET_IP = "xxx" # 二编：直接写域名！！
```

运行`measurement.py`: 

```bash
python measurement.py
```

输出示例：

```
HTTP 201: {"measurements":[170170717,170170718]}
Ping ID: 170170717, Traceroute ID: 170170718
```

现在去 RIPE Atlas 的 dashboard 里面找到 My Measurements，可以看到有两个任务（Ping 和 Traceroute），ID分别为 170170717 和 170170718（这里仅为示例），点进去有详情。记下这两个任务 ID，后面会用到。

*任务跑完之后测量就结束了，这是必须跑通的基础测量流程，可以得到所有 raw data。记得去 My Measurements 面板里确认一下：理想的情况是大部分 probes 都 reached their target，如果出现大批量的 did not reach target 或者 did not report (yet)，那肯定有问题。*

## 4: Data Analysis
The analysis script (`result.py`) is organized into seven sequential sections. Each section has a single responsibility and passes its output directly to the next.

**Configuration**
Before running, edit the six variables at the top of the CONFIG block: `API_KEY`, `PING_ID`, `TRACE_ID`, `PROVIDER`, `ENDPOINT`, and `TARGET_HOST`. Everything else is fully reusable across providers and endpoints.
```python
# ─────────────────────────────────────────────────────────────
# CONFIG — edit these before running
# ─────────────────────────────────────────────────────────────
API_KEY   = "Your_RIPE_API_Key"  # to be changed
PING_ID   = 171964292   # to be changed
TRACE_ID  = 171964294   # to be changed

# Provider label used in report output
PROVIDER  = "Payment Service Provider"  # to be changed
ENDPOINT  = "CND: static.mobikwik.com"   # to be changed
TARGET_HOST = "static.mobikwik.com"   # to be changed
```

**Section 0 — Output Utilities**
Two helper functions used throughout the script. `capture_output()` redirects stdout into a string buffer, allowing any function's printed output to be captured and later written to the report file without duplicating print calls. `save_report()` writes a structured text file with a header block and named sections, one per analysis stage.

**Section 1 — Atlas Helpers**
Low-level functions for communicating with the RIPE Atlas REST API. `atlas_get()` handles authenticated GET requests. `fetch_results()` downloads all probe results for a given measurement ID. `fetch_probe_countries()` resolves each probe ID to a country code by querying probe metadata directly, which is more reliable than reading the `probes_scheduled` field from the measurement object.

**Section 2 — Geometry and GeoIP Helpers**
The physical constraint formula `d ≤ (RTT × 200 km/ms) / 2` is implemented in `rtt_to_max_dist()`. `haversine()` computes great-circle distances between two coordinate pairs. `get_ip_info()` queries ipinfo.io for a given IP's claimed location and organization, and is reused across both the ping and traceroute sections. `fetch_probe_location()` retrieves each probe's coordinates from RIPE Atlas metadata, noting that RIPE Atlas GeoJSON stores coordinates as `[longitude, latitude]` rather than the more common reverse order.

**Section 3 — Ping Analysis**
`analyze_ping()` processes ping results probe by probe. For each probe it computes the RTT-derived distance upper bound, fetches the probe's coordinates and the destination IP's GeoIP-claimed location, then compares the two distances. If the GeoIP-claimed location falls within the RTT bound the result is marked CONSISTENT; otherwise CONTRADICTED. These per-probe verdicts feed directly into Section 4. 

**Section 4 — Anycast Detection**
`anycast_verdict()` is called at the end of this section and combines three independent signals to determine whether the endpoint uses Anycast. 
- Signal A checks whether different regions resolve to different destination IPs. 
- Signal B looks at the pattern of CONSISTENT and CONTRADICTED results across all regions, distinguishing Cloudflare-style deployments (IP registered far away, local PoPs serve traffic everywhere) from Akamai-style deployments (accurate GeoIP per region). 
- Signal C compares each probe's actual RTT against the expected RTT derived from the GeoIP distance. At least two of the three signals must point to Anycast for the verdict to be confirmed.

At least two of the three signals must point to Anycast for the verdict to be confirmed. 

**Section 5 — Traceroute Analysis**
`parse_traceroute()` classifies each hop on Indian probe paths into one of four categories: confirmed egress (RTT cliff and foreign IP coincide at the same hop), egress inconclusive (RTT cliff but IPinfo still shows a domestic location), foreign without cliff (foreign IP but no RTT spike, suggesting a low-latency international link or an inaccurate IPinfo label), or no anomaly. RTT cliff detection compares consecutive visible hops; any delta above 20 ms is flagged. Egress classification is only performed for Indian probes; overseas probe paths record cliffs for Anycast cross-validation only. Progress is printed to the terminal during processing but not written to the report.

**Section 6 — WHOIS and rDNS Enrichment**

`enrich_rdns()` performs reverse DNS lookups on inconclusive and foreign-no-cliff hops, using router hostnames as independent geographic hints (e.g. `cr1.mum01.airtel.net` suggests Mumbai). Confirmed egress hops are skipped because cliff and foreign IP together already constitute sufficient evidence. 

`enrich_whois()` queries RDAP via the `ipwhois` library for all egress-related IPs, retrieving ASN, ASN description, network name, and registration country from authoritative RIR records (APNIC, ARIN, RIPE). Unlike ipinfo.io, RIR data reflects the legal and administrative ownership of an IP block, which is more relevant for policy-level compliance judgments.

**Section 7 — Traceroute Annotation**
`annotate_paths()` assembles the final per-hop output without issuing any new network requests. All data is read from `rec['ipinfo']` populated in Section 5, `rec['rdns']` populated by `enrich_rdns()`, and `whois_cache` returned by `enrich_whois()`. Every visible hop is printed with its IPinfo summary. Confirmed egress hops additionally show the WHOIS result. Inconclusive and foreign-no-cliff hops show both WHOIS and rDNS. A per-path summary at the end of each probe's output lists all egress-related hops with their ASN and, where available, rDNS hostname. The captured output from this function is written into the structured report alongside the ping analysis.

### Command
To view the report, run:
```bash
python result.py
```
Each time will generate two files:
- `"mobikwik_static_mobikwik_com.json"` contains all the raw data of Ping and Traceroute measurement;
- `"mobikwik_static_mobikwik_com_report.txt"` contains the report for analysis.