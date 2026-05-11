"""
RIPE Atlas Measurement Analysis — India Payment Data Localization Study
ECS 252 Project | Muyang Zheng, Jintian Xu, Yan Liang, Sijia Fan

Usage:
    python analyze_atlas.py

Requires:
    pip install requests
"""

import requests
import time
import json
from datetime import datetime

# ─────────────────────────────────────────────────────────────
# CONFIG — edit these before running
# ─────────────────────────────────────────────────────────────
API_KEY   = "your_atlas_api_key"
PING_ID   = 170170717
TRACE_ID  = 170170718

# Provider label used in report output
PROVIDER  = "PayPal"
ENDPOINT  = "api.paypal.com → 66.211.168.123"


# ─────────────────────────────────────────────────────────────
# SECTION 1 — ATLAS HELPERS
# ─────────────────────────────────────────────────────────────

def atlas_get(path):
    """Authenticated GET against the RIPE Atlas REST API."""
    r = requests.get(
        f"https://atlas.ripe.net/api/v2/{path}",
        headers={"Authorization": f"Key {API_KEY}"}
    )
    r.raise_for_status()
    return r.json()


def wait_for_measurement(msm_id, max_wait=360, interval=15):
    """Poll until the measurement reaches a terminal state."""
    print(f"\n[*] Waiting for measurement {msm_id} to finish...")
    for elapsed in range(0, max_wait, interval):
        data   = atlas_get(f"measurements/{msm_id}/")
        status = data.get("status", {}).get("name", "unknown")
        print(f"    [{elapsed:>3}s] status: {status}")
        if status in ("Stopped", "Failed"):
            print(f"    → Measurement {msm_id} finished with status: {status}")
            return status
        time.sleep(interval)
    print(f"    → Timed out after {max_wait}s — fetching whatever results exist")
    return "timeout"


def fetch_results(msm_id):
    """Download all result objects for a measurement."""
    return atlas_get(f"measurements/{msm_id}/results/")


def fetch_probe_countries(msm_id):
    """
    Build {probe_id: country_code} by inspecting result objects,
    then querying each probe's metadata.  Avoids relying on the
    fragile 'probes_scheduled' measurement field.
    """
    print("\n[*] Resolving probe countries...")
    results   = fetch_results(msm_id)
    probe_ids = list({r.get("prb_id") for r in results if r.get("prb_id")})
    print(f"    Found {len(probe_ids)} probes: {probe_ids}")

    mapping = {}
    for pid in probe_ids:
        probe = atlas_get(f"probes/{pid}/")
        cc    = probe.get("country_code", "??")
        mapping[pid] = cc
        print(f"    Probe {pid} → {cc}")
        time.sleep(0.25)   # stay well under Atlas rate limits

    return mapping


# ─────────────────────────────────────────────────────────────
# SECTION 2 — RTT / LOCALIZATION LOGIC
# ─────────────────────────────────────────────────────────────

# Speed of light in fiber ≈ 200 km/ms
FIBER_KM_PER_MS = 200

# Geographic thresholds (km) for classification
THRESHOLDS = [
    (3_000,  "IN",  "✅ Likely within India"),
    (3_500,  "SG",  "⚠️  India or Singapore region"),
    (8_000,  "EU",  "❌ European / Middle-East range"),
    (99_999, "US",  "❌ Americas or further"),
]


def rtt_to_max_dist(rtt_ms):
    """Upper bound on server distance given an RTT (one-way light budget)."""
    return (rtt_ms * FIBER_KM_PER_MS) / 2


def classify_distance(km):
    for threshold, region, label in THRESHOLDS:
        if km <= threshold:
            return region, label
    return "??", "❓ Unknown"


def anycast_verdict(rtt_by_country):
    """
    Compare RTT ratios across vantage points to infer Anycast vs.
    single-origin deployment.

    Returns a string verdict.
    """
    def min_rtt(cc):
        vals = [r for c, r in rtt_by_country if c == cc]
        return min(vals) if vals else None

    rtt_in = min_rtt("IN")
    rtt_us = min_rtt("US")
    rtt_de = min_rtt("DE")
    rtt_sg = min_rtt("SG")

    lines = [
        f"  India   min RTT : {rtt_in:.2f} ms" if rtt_in else "  India   min RTT : N/A",
        f"  US      min RTT : {rtt_us:.2f} ms" if rtt_us else "  US      min RTT : N/A",
        f"  Germany min RTT : {rtt_de:.2f} ms" if rtt_de else "  Germany min RTT : N/A",
        f"  Singapore min RTT: {rtt_sg:.2f} ms" if rtt_sg else "  Singapore min RTT: N/A",
    ]

    verdict = "❓ Insufficient data"
    if rtt_in and rtt_us:
        ratio = rtt_in / rtt_us
        if ratio > 3:
            verdict = (f"❌ IN/US ratio = {ratio:.1f}x — strong evidence of a "
                       f"single US-based origin; Indian traffic NOT locally served")
        elif ratio > 1.5:
            verdict = (f"⚠️  IN/US ratio = {ratio:.1f}x — partial Anycast likely; "
                       f"corroborate with traceroute hop analysis")
        else:
            verdict = (f"⚠️  IN/US ratio = {ratio:.1f}x — globally uniform RTTs; "
                       f"classic Anycast / CDN deployment confirmed")

    return lines, verdict


# ─────────────────────────────────────────────────────────────
# SECTION 3 — PING ANALYSIS
# ─────────────────────────────────────────────────────────────

def analyze_ping(results, probe_map):
    print("\n" + "═" * 60)
    print("PING RESULTS")
    print("═" * 60)

    rtt_by_country = []

    for r in results:
        pid     = r.get("prb_id")
        avg_rtt = r.get("avg", -1)
        src     = r.get("from", "unknown")
        cc      = probe_map.get(pid, "??")

        if avg_rtt < 0:
            print(f"  Probe {pid:>8} ({cc}) | src={src}")
            print(f"    avg RTT = TIMEOUT — likely WAF / firewall drop")
            continue

        dist_km       = rtt_to_max_dist(avg_rtt)
        region, label = classify_distance(dist_km)
        rtt_by_country.append((cc, avg_rtt))

        print(f"\n  Probe {pid:>8} ({cc}) | src={src}")
        print(f"    avg RTT      = {avg_rtt:.2f} ms")
        print(f"    max distance = {dist_km:,.0f} km  →  {label}")

    # Anycast / single-origin verdict
    print("\n" + "─" * 60)
    print("ANYCAST DETECTION")
    print("─" * 60)
    lines, verdict = anycast_verdict(rtt_by_country)
    for l in lines:
        print(l)
    print(f"\n  Verdict: {verdict}")

    return rtt_by_country


# ─────────────────────────────────────────────────────────────
# SECTION 4 — TRACEROUTE ANALYSIS
# ─────────────────────────────────────────────────────────────

# Hostname substrings that hint at a known data-center / carrier location
DC_HINTS = {
    # PayPal / eBay backbone identifiers
    "paypal"  : "PayPal backbone",
    "ebay"    : "eBay / PayPal network",
    # US data-center city codes
    "ash"     : "🇺🇸 Ashburn, VA (USA) — PayPal primary DC",
    "sjc"     : "🇺🇸 San Jose, CA (USA)",
    "ord"     : "🇺🇸 Chicago, IL (USA)",
    "lax"     : "🇺🇸 Los Angeles, CA (USA)",
    # India
    "bom"     : "🇮🇳 Mumbai, India",
    "del"     : "🇮🇳 Delhi, India",
    "ccu"     : "🇮🇳 Kolkata, India",
    # Asia-Pacific
    "sin"     : "🇸🇬 Singapore",
    "nrt"     : "🇯🇵 Tokyo, Japan",
    "hkg"     : "🇭🇰 Hong Kong",
    # Carriers seen in this measurement
    "zayo"    : "Zayo Group (US backbone)",
    "ntt"     : "NTT Communications",
    "airtel"  : "Bharti Airtel (India)",
    "hetzner" : "Hetzner (Germany)",
}

# IPs we specifically want to WHOIS — populated during traceroute parsing
whois_queue = set()


def parse_traceroute(results, probe_map):
    print("\n" + "═" * 60)
    print("TRACEROUTE RESULTS")
    print("═" * 60)

    # Collect (probe_id, country, list_of_(hop, ip, rtt)) for later WHOIS
    all_paths = []

    for r in results:
        pid  = r.get("prb_id")
        cc   = probe_map.get(pid, "??")
        hops = r.get("result", [])

        print(f"\n  Probe {pid:>8} ({cc}) — {len(hops)} hops toward {ENDPOINT}")

        path_hops = []
        for hop in hops:
            idx = hop.get("hop")
            for pkt in hop.get("result", []):
                rtt      = pkt.get("rtt")
                hop_addr = pkt.get("from", "*")
                if not rtt or hop_addr == "*":
                    continue

                # Check for DC / carrier hint
                hint = ""
                for kw, loc in DC_HINTS.items():
                    if kw in hop_addr.lower():
                        hint = f"  ← {loc}"
                        break

                print(f"    hop {idx:>3}: {hop_addr:<45} {rtt:>7.1f} ms{hint}")

                # Queue last 3 meaningful hops for WHOIS
                path_hops.append((idx, hop_addr, rtt))
                whois_queue.add(hop_addr)
                break  # one packet per hop is enough

        all_paths.append((pid, cc, path_hops))

    return all_paths


# ─────────────────────────────────────────────────────────────
# SECTION 5 — WHOIS / GEOIP ENRICHMENT
# ─────────────────────────────────────────────────────────────

def geoip_lookup(ip):
    """
    Query ipinfo.io for org, country, city.
    Returns a dict; falls back gracefully on errors.
    """
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if r.ok:
            return r.json()
    except Exception:
        pass
    return {}


def enrich_hops(whois_ips):
    """
    Run GeoIP lookups for every IP in whois_ips.
    Returns {ip: {org, country, city}} dict.
    """
    print("\n" + "═" * 60)
    print("WHOIS / GEOIP ENRICHMENT")
    print("═" * 60)
    print(f"  Querying {len(whois_ips)} unique IPs via ipinfo.io...\n")

    enriched = {}
    for ip in sorted(whois_ips):
        d = geoip_lookup(ip)
        enriched[ip] = {
            "org"     : d.get("org",     "N/A"),
            "country" : d.get("country", "??"),
            "city"    : d.get("city",    "N/A"),
            "region"  : d.get("region",  "N/A"),
        }
        org  = enriched[ip]["org"]
        city = enriched[ip]["city"]
        cc   = enriched[ip]["country"]
        print(f"  {ip:<45} {cc}  {city:<20} {org}")
        time.sleep(0.3)   # respect ipinfo free-tier rate limit

    return enriched


def annotate_paths(all_paths, enriched):
    """
    Re-print each traceroute path, now with WHOIS context on every hop.
    Highlights the last hop before 66.211.168.123 as the 'handoff' point.
    """
    print("\n" + "═" * 60)
    print("ANNOTATED TRACEROUTE PATHS  (with WHOIS)")
    print("═" * 60)

    for pid, cc, hops in all_paths:
        print(f"\n  Probe {pid:>8} ({cc})")
        for idx, ip, rtt in hops:
            info = enriched.get(ip, {})
            org  = info.get("org",     "")
            city = info.get("city",    "")
            c    = info.get("country", "")
            note = f"{city}, {c}  |  {org}" if city != "N/A" else org
            print(f"    hop {idx:>3}: {ip:<42} {rtt:>6.1f} ms  [{note}]")


# ─────────────────────────────────────────────────────────────
# SECTION 6 — SUMMARY REPORT
# ─────────────────────────────────────────────────────────────

def print_summary(rtt_by_country, all_paths, enriched):
    print("\n" + "═" * 60)
    print("SUMMARY — DATA LOCALIZATION ASSESSMENT")
    print(f"Provider : {PROVIDER}")
    print(f"Endpoint : {ENDPOINT}")
    print(f"Run at   : {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    print("═" * 60)

    # RTT table
    print("\n  RTT by vantage point:")
    header = f"  {'Probe':>10}  {'Country':>7}  {'Avg RTT':>10}  {'Max Dist (km)':>15}  Verdict"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for cc, rtt in sorted(rtt_by_country, key=lambda x: x[1]):
        dist          = rtt_to_max_dist(rtt)
        _, label      = classify_distance(dist)
        print(f"  {'':>10}  {cc:>7}  {rtt:>10.2f}  {dist:>15,.0f}  {label}")

    # Anycast verdict
    _, verdict = anycast_verdict(rtt_by_country)
    print(f"\n  Anycast / Origin verdict:\n    {verdict}")

    # Key hops in India paths
    india_pids = [pid for pid, cc, _ in all_paths if cc == "IN"]
    print(f"\n  India probe handoff IPs (last hops before destination):")
    for pid, cc, hops in all_paths:
        if cc != "IN":
            continue
        # Last 2 hops before the target
        for idx, ip, rtt in hops[-3:-1]:
            info = enriched.get(ip, {})
            org  = info.get("org", "N/A")
            c    = info.get("country", "??")
            print(f"    Probe {pid}  hop {idx}: {ip}  [{c}]  {org}")

    # Policy implication
    print("\n  Policy implication for RBI localization mandate:")
    india_rtts = [r for c, r in rtt_by_country if c == "IN"]
    us_rtts    = [r for c, r in rtt_by_country if c == "US"]
    if india_rtts and us_rtts:
        ratio = min(india_rtts) / min(us_rtts)
        if ratio < 1.5:
            print("    Anycast confirmed — connection terminates at geographically")
            print("    distributed nodes. Network-layer evidence CANNOT confirm that")
            print("    payment data is stored within India; proxy / internal routing")
            print("    to overseas backends cannot be ruled out (Proposal §Biggest Risk).")
        else:
            print("    Single-origin server outside India detected.")
            print("    Strong network-layer evidence of NON-COMPLIANCE with RBI mandate.")

    print("\n" + "═" * 60)


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print(f" RIPE Atlas Analysis — {PROVIDER}")
    print(f" Ping MSM : {PING_ID}")
    print(f" Trace MSM: {TRACE_ID}")
    print("=" * 60)

    # 1. Resolve probe → country mapping from ping results
    probe_map = fetch_probe_countries(PING_ID)

    # 2. Wait for both measurements to finish
    wait_for_measurement(PING_ID)
    wait_for_measurement(TRACE_ID)

    # 3. Download results
    ping_results  = fetch_results(PING_ID)
    trace_results = fetch_results(TRACE_ID)

    # 4. Analyze ping (RTT + Anycast detection)
    rtt_by_country = analyze_ping(ping_results, probe_map)

    # 5. Parse traceroute paths; populate whois_queue
    all_paths = parse_traceroute(trace_results, probe_map)

    # 6. WHOIS / GeoIP enrichment for every hop IP seen
    enriched = enrich_hops(whois_queue)

    # 7. Re-print paths with WHOIS annotations
    annotate_paths(all_paths, enriched)

    # 8. Print consolidated summary
    print_summary(rtt_by_country, all_paths, enriched)

    # 9. Save raw results to JSON for further processing
    output = {
        "provider"       : PROVIDER,
        "endpoint"       : ENDPOINT,
        "ping_msm_id"    : PING_ID,
        "trace_msm_id"   : TRACE_ID,
        "probe_map"      : {str(k): v for k, v in probe_map.items()},
        "ping_results"   : ping_results,
        "trace_results"  : trace_results,
        "whois_enriched" : enriched,
        "rtt_by_country" : rtt_by_country,
    }
    fname = f"atlas_{PROVIDER.lower()}_{PING_ID}.json"
    with open(fname, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n[*] Raw results saved to {fname}")


if __name__ == "__main__":
    main()