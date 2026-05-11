# Data Localization Project Instructions
## 0: 环境准备
Python 版本：3.11
环境配置：
```bash
pip install requests
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

可知 **Target IP** 为`66.211.168.123`
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
TARGET_IP = "xx.xxx.xxx.xxx" # 来自第2步里的dig结果
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

## 4: 数据分析
data analysis 暂时见仁见智，我写的仅供参考。

脚本分为六个独立的部分，逻辑是线性串联的：
**Section 1 — Atlas Helpers**：所有和RIPE API通信的底层函数，包括轮询状态、下载结果、解析探针国家。
**Section 2 — RTT Logic**：核心公式 `d ≤ (RTT × 200) / 2` 和 Anycast 判断，把距离阈值统一定义在 `THRESHOLDS` 列表里，方便你们之后换其他国家时修改。
**Section 3 & 4 — Ping / Traceroute**：分析阶段，Traceroute 解析时会把所有出现过的 hop IP 加入 `whois_queue`，自动为后续 WHOIS 做准备，不需要手动维护 IP 列表。
**Section 5 — WHOIS / GeoIP**：批量查询 `ipinfo.io`，然后 `annotate_paths()` 把 WHOIS 结果叠加回每条 traceroute 路径上，让你直接看到每个 hop 属于哪个 AS、在哪个城市。
**Section 6 — Summary**：根据 IN/US RTT 比值和印度路径的最后几跳，自动生成一段面向 RBI mandate 的 policy implication 文字，可以直接引用进报告。

运行前只需要改最顶部的几个变量，其余逻辑完全复用。

```python
# ─────────────────────────────────────────────────────────────
# CONFIG — edit these before running
# ─────────────────────────────────────────────────────────────
API_KEY = "your_atlas_api_key"
PING_ID = 170170717  # 来自第3步里的测量结果
TRACE_ID = 170170718  # 来自第3步里的测量结果

# Provider label used in report output
# 用于输出报告
PROVIDER = "PayPal"
ENDPOINT = "api.paypal.com → 66.211.168.123"
```

运行`result.py`:

```bash
python result.py
```

最终会把所有原始数据保存成 `atlas_paypal_170170717.json`，方便后续做跨服务商的横向对比。