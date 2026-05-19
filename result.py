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
from datetime import datetime, timezone
import math
import io
import sys

# ─────────────────────────────────────────────────────────────
# CONFIG — edit these before running
# ─────────────────────────────────────────────────────────────
API_KEY   = "Your_RIPE_Atlas_API"  # to be changed
PING_ID   = 171964292   # to be changed
TRACE_ID  = 171964294   # to be changed

# Provider label used in report output
PROVIDER  = "MobiKwik"  # to be changed
ENDPOINT  = "CND: static.mobikwik.com"   # to be changed

# ─────────────────────────────────────────────────────────────
# SECTION 0 — OUTPUT UTILITIES
# ─────────────────────────────────────────────────────────────
def capture_output(func, *args, **kwargs):
    """
    Run any function and capture everything it prints.
    Returns (return_value, printed_string).
    Usage:
        result, text = capture_output(analyze_ping, ping_results, probe_map)
    """
    old_stdout = sys.stdout
    sys.stdout = buffer = io.StringIO()
    try:
        retval = func(*args, **kwargs)
    finally:
        sys.stdout = old_stdout
    return retval, buffer.getvalue()


def save_report(fname, sections: dict):
    """
    Write a structured text report.
    
    sections: OrderedDict or regular dict (Python 3.7+) of
              {section_title: content_string}
    
    Example:
        save_report("report.txt", {
            "PING ANALYSIS":      ping_text,
            "TRACEROUTE ANALYSIS": trace_text,   # add later
            "WHOIS ENRICHMENT":   whois_text,    # add later
        })
    """
    with open(fname, "w", encoding="utf-8") as f:
        # Header
        f.write("=" * 70 + "\n")
        f.write(f"  RIPE Atlas Analysis Report\n")
        f.write(f"  Provider  : {PROVIDER}\n")
        f.write(f"  Endpoint  : {ENDPOINT}\n")
        f.write(f"  Ping MSM  : {PING_ID}\n")
        f.write(f"  Trace MSM : {TRACE_ID}\n")
        f.write(f"  Run at    : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n")
        f.write("=" * 70 + "\n\n")

        # Each section
        for title, content in sections.items():
            if content and content.strip():
                f.write("─" * 70 + "\n")
                f.write(f"  {title}\n")
                f.write("─" * 70 + "\n")
                f.write(content)
                f.write("\n")

    print(f"[*] Report saved to {fname}")

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
# SECTION 2 — GEOMETRY & GEOIP HELPERS
# ─────────────────────────────────────────────────────────────

# Speed of light in fiber ≈ 200 km/ms
FIBER_KM_PER_MS = 200

def haversine(lat1, lon1, lat2, lon2):
    """Great-circle distance between two lat/lon points (km)."""
    R = 6371
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi       = math.radians(lat2 - lat1)
    dlambda    = math.radians(lon2 - lon1)
    a = (math.sin(dphi / 2) ** 2 +
         math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2)
    return R * 2 * math.asin(math.sqrt(a))


def rtt_to_max_dist(rtt_ms):
    """
    Upper bound on one-way physical distance from RTT.
    Formula from proposal: d ≤ (RTT × 200 km/ms) / 2
    """
    return (rtt_ms * FIBER_KM_PER_MS) / 2


def get_ip_info(ip):
    """
    Query ipinfo.io for an IP's claimed location and org.
    Returns dict with keys: lat, lon, city, country, org
    Returns None on failure.
    """
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if r.ok:
            data = r.json()
            loc  = data.get("loc", "")
            if loc:
                lat, lon = map(float, loc.split(","))
                return {
                    "lat"     : lat,
                    "lon"     : lon,
                    "city"    : data.get("city",    "?"),
                    "country" : data.get("country", "?"),
                    "org"     : data.get("org",     "?"),
                }
    except Exception:
        pass
    return None


def fetch_probe_location(pid):
    """
    Fetch probe lat/lon from RIPE Atlas metadata.
    Returns (lat, lon) or None.
    Note: RIPE Atlas GeoJSON coordinates are [longitude, latitude].
    """
    try:
        probe    = atlas_get(f"probes/{pid}/")
        geometry = probe.get("geometry", {})
        if geometry and geometry.get("coordinates"):
            lon, lat = geometry["coordinates"]   # GeoJSON: [lon, lat]
            return lat, lon
    except Exception:
        pass
    return None


# ─────────────────────────────────────────────────────────────
# SECTION 3 — PING ANALYSIS
# ─────────────────────────────────────────────────────────────

def analyze_ping(results, probe_map):
    """
    For each probe:
      1. Compute RTT-based physical distance upper bound.
      2. Fetch probe coordinates from RIPE Atlas metadata.
      3. Fetch destination IP's GeoIP-claimed coordinates via ipinfo.io.
      4. Compute actual distance: probe → GeoIP-claimed location.
      5. Cross-validate:
           - If (probe → GeoIP location) ≤ max_dist_km  → CONSISTENT
             (GeoIP claim is physically plausible given the RTT)
           - If (probe → GeoIP location) > max_dist_km  → CONTRADICTED
             (server CANNOT be where GeoIP says; Anycast PoP is closer)
 
    Returns:
        rtt_by_country : list of (country_code, min_rtt_ms)
        probe_records  : list of per-probe result dicts (for Anycast analysis)
    """
    print("\n" + "═" * 70)
    print("PING RESULTS — RTT-to-Distance + GeoIP Cross-Validation")
    print("═" * 70)
    print()
    print("  Logic: probe draws a circle of radius = RTT × 200/2 km.")
    print("         If GeoIP-claimed server location falls OUTSIDE this")
    print("         circle, the GeoIP label is physically impossible —")
    print("         the server must be closer (Anycast PoP effect).")
    print()
 
    rtt_by_country = []   # [(cc, min_rtt_ms), ...]
    probe_records  = []   # one dict per probe, used by anycast_verdict()
 
    for r in results:
        pid     = r.get("prb_id")
        min_rtt = r.get("min", -1)
        dst_ip  = r.get("dst_addr") or r.get("dst_name", "?")
        src_ip  = r.get("from", "?")
        cc      = probe_map.get(pid, "??")
 
        print(f"  {'─' * 62}")
        print(f"  Probe {pid} ({cc}) | src={src_ip} → dst={dst_ip}")
 
        if min_rtt < 0:
            print(f"    ⚠️  No RTT returned — likely blocked by WAF/firewall")
            probe_records.append({
                "pid": pid, "cc": cc, "dst_ip": dst_ip,
                "min_rtt": None, "verdict": "NO_DATA",
            })
            continue
 
        # ── Step 1: RTT → distance upper bound ───────────────
        max_dist_km = rtt_to_max_dist(min_rtt)
        rtt_by_country.append((cc, min_rtt))
 
        print(f"    Min RTT        = {min_rtt:.3f} ms")
        print(f"    Max distance   = {max_dist_km:,.1f} km"
              f"  (d ≤ {min_rtt:.3f} ms × {FIBER_KM_PER_MS} / 2)")
 
        # ── Step 2: probe coordinates ─────────────────────────
        probe_loc = fetch_probe_location(pid)
        if not probe_loc:
            print(f"    ⚠️  Probe coordinates unavailable — skipping geometry check")
            probe_records.append({
                "pid": pid, "cc": cc, "dst_ip": dst_ip,
                "min_rtt": min_rtt, "verdict": "NO_PROBE_COORDS",
            })
            time.sleep(0.3)
            continue
 
        probe_lat, probe_lon = probe_loc
        print(f"    Probe coords   = ({probe_lat:.4f}, {probe_lon:.4f})")
 
        # ── Step 3: destination IP GeoIP ──────────────────────
        dst_info = get_ip_info(dst_ip)
        if not dst_info:
            print(f"    ⚠️  GeoIP lookup failed for {dst_ip}")
            probe_records.append({
                "pid": pid, "cc": cc, "dst_ip": dst_ip,
                "min_rtt": min_rtt, "verdict": "NO_GEOIP",
            })
            time.sleep(0.3)
            continue
 
        dst_lat     = dst_info["lat"]
        dst_lon     = dst_info["lon"]
        dst_city    = dst_info["city"]
        dst_country = dst_info["country"]
        dst_org     = dst_info["org"]
 
        print(f"    GeoIP claims   = {dst_city}, {dst_country}"
              f" ({dst_lat:.4f}, {dst_lon:.4f}) | {dst_org}")
 
        # ── Step 4: actual distance probe → GeoIP location ───
        dist_probe_to_geoip = haversine(probe_lat, probe_lon,
                                        dst_lat,   dst_lon)
        print(f"    Probe → GeoIP  = {dist_probe_to_geoip:,.1f} km")
        print(f"    RTT circle r   = {max_dist_km:,.1f} km")
 
        # ── Step 5: cross-validation verdict ─────────────────
        if dist_probe_to_geoip <= max_dist_km:
            verdict = "CONSISTENT"
            print(f"    ✅ CONSISTENT  — {dist_probe_to_geoip:,.1f} km"
                  f" ≤ {max_dist_km:,.1f} km")
            print(f"       GeoIP-claimed location ({dst_city}, {dst_country})"
                  f" is physically plausible given the RTT.")
        else:
            verdict = "CONTRADICTED"
            print(f"    ❌ CONTRADICTED — {dist_probe_to_geoip:,.1f} km"
                  f" > {max_dist_km:,.1f} km")
            print(f"       Server CANNOT be in {dst_city}, {dst_country}.")
            print(f"       GeoIP label is stale/wrong (typical Anycast:"
                  f" a local PoP is serving this probe, not the registered location).")
 
        probe_records.append({
            "pid"               : pid,
            "cc"                : cc,
            "dst_ip"            : dst_ip,
            "dst_city"          : dst_city,
            "dst_country"       : dst_country,
            "dst_org"           : dst_org,
            "min_rtt"           : min_rtt,
            "max_dist_km"       : max_dist_km,
            "dist_probe_to_geoip": dist_probe_to_geoip,
            "verdict"           : verdict,
        })
 
        time.sleep(0.3)   # respect ipinfo free-tier rate limit
 
    # ── Anycast detection using all regions ──────────────────
    anycast_text = anycast_verdict(rtt_by_country, probe_records)
    print(anycast_text)
 
    return rtt_by_country, probe_records


# ─────────────────────────────────────────────────────────────
# SECTION 4 — ANYCAST DETECTION
# ─────────────────────────────────────────────────────────────
 
def anycast_verdict(rtt_by_country, probe_records):
    """
    Three complementary signals, all regions used:
 
    Signal A — IP diversity across regions
        Different destination IPs per region  →  GeoDNS/Anycast
        Same IP everywhere                    →  single origin (or pure Anycast with stable IP)
 
    Signal B — GeoIP cross-validation pattern
        All CONSISTENT   →  each region's local PoP is real and GeoIP is accurate
        All CONTRADICTED →  IP registered far away, but local PoPs serve traffic (classic Cloudflare)
        Mixed            →  partial deployment or measurement noise
 
    Signal C — RTT symmetry check
        For each non-IN region R: does RTT(R) roughly match the
        expected travel time from R to the GeoIP-claimed location?
        If yes  →  single origin near GeoIP location
        If no   →  local PoP is closer than GeoIP claims (Anycast)
 
    Final verdict combines all three signals.
    """
    sep  = "\n" + "─" * 70
    out  = [sep, "ANYCAST DETECTION — MULTI-REGION ANALYSIS", "─" * 70]
 
    # ── Signal A: IP diversity ────────────────────────────────
    ips_by_cc = {}
    for rec in probe_records:
        if rec["verdict"] == "NO_DATA":
            continue
        cc = rec["cc"]
        ip = rec["dst_ip"]
        ips_by_cc.setdefault(cc, set()).add(ip)
 
    all_ips = set(ip for ips in ips_by_cc.values() for ip in ips)
 
    out.append("\n  [Signal A] Destination IP diversity across regions:")
    for cc, ips in sorted(ips_by_cc.items()):
        out.append(f"    {cc:>4} → {', '.join(sorted(ips))}")
    if len(all_ips) > 1:
        out.append(f"  → {len(all_ips)} distinct IPs observed across regions.")
        out.append(f"    Different IPs per region = strong GeoDNS / Anycast evidence.")
        signal_a = "ANYCAST"
    else:
        out.append(f"  → Single IP {list(all_ips)[0]} seen from all regions.")
        out.append(f"    Cannot distinguish Anycast from single-origin via IP diversity alone.")
        signal_a = "UNCLEAR"
 
    # ── Signal B: GeoIP cross-validation pattern ─────────────
    consistent_ccs    = set()
    contradicted_ccs  = set()
    for rec in probe_records:
        if rec["verdict"] == "CONSISTENT":
            consistent_ccs.add(rec["cc"])
        elif rec["verdict"] == "CONTRADICTED":
            contradicted_ccs.add(rec["cc"])
 
    out.append("\n  [Signal B] GeoIP cross-validation pattern:")
    out.append(f"    CONSISTENT    regions : {sorted(consistent_ccs)   or 'none'}")
    out.append(f"    CONTRADICTED  regions : {sorted(contradicted_ccs) or 'none'}")
 
    if contradicted_ccs and not consistent_ccs:
        out.append("  → All regions CONTRADICTED: IP registered far away but")
        out.append("    local PoPs serve traffic everywhere (classic Cloudflare-style Anycast).")
        signal_b = "ANYCAST_STALE_GEOIP"
    elif consistent_ccs and not contradicted_ccs:
        out.append("  → All regions CONSISTENT: GeoIP accurate, each region")
        out.append("    resolves to a local node (GeoDNS-based Anycast like Akamai).")
        signal_b = "ANYCAST_ACCURATE_GEOIP"
    elif consistent_ccs and contradicted_ccs:
        out.append("  → Mixed results: some regions have local PoPs with accurate")
        out.append("    GeoIP; others are served by a distant node. Partial deployment.")
        signal_b = "PARTIAL"
    else:
        signal_b = "UNCLEAR"
 
    # ── Signal C: RTT symmetry (does RTT match GeoIP distance?) ──
    out.append("\n  [Signal C] RTT vs. expected travel time to GeoIP location:")
    out.append(f"    (Expected RTT = 2 × distance_to_GeoIP / {FIBER_KM_PER_MS} km/ms)")
 
    signal_c_votes = {"LOCAL_POP": 0, "MATCHES_GEOIP": 0}
    for rec in probe_records:
        if rec["verdict"] not in ("CONSISTENT", "CONTRADICTED"):
            continue
        expected_rtt = (rec["dist_probe_to_geoip"] / FIBER_KM_PER_MS) * 2
        actual_rtt   = rec["min_rtt"]
        ratio        = actual_rtt / expected_rtt if expected_rtt > 0 else float("inf")
 
        if ratio < 0.5:
            # actual RTT much smaller than expected → local PoP closer than GeoIP
            label = "LOCAL_POP (RTT << expected)"
            signal_c_votes["LOCAL_POP"] += 1
        elif ratio <= 2.0:
            # actual RTT roughly matches expected → server near GeoIP location
            label = "MATCHES_GEOIP (RTT ≈ expected)"
            signal_c_votes["MATCHES_GEOIP"] += 1
        else:
            label = f"ANOMALY (ratio={ratio:.1f}x)"
 
        out.append(f"    Probe {rec['pid']:>8} ({rec['cc']}) | "
                   f"actual={actual_rtt:.2f}ms  expected={expected_rtt:.1f}ms  → {label}")
 
    if signal_c_votes["LOCAL_POP"] > signal_c_votes["MATCHES_GEOIP"]:
        signal_c = "LOCAL_POPS"
        out.append("  → Majority of probes show RTT << expected: "
                   "local PoPs serve traffic, not the GeoIP-registered location.")
    elif signal_c_votes["MATCHES_GEOIP"] >= signal_c_votes["LOCAL_POP"]:
        signal_c = "MATCHES_GEOIP"
        out.append("  → Majority of probes show RTT ≈ expected: "
                   "server is near its GeoIP-claimed location.")
    else:
        signal_c = "UNCLEAR"
 
    # ── Final verdict ─────────────────────────────────────────
    out.append("\n" + "─" * 70)
    out.append("  FINAL ANYCAST VERDICT")
    out.append("─" * 70)
    out.append(f"  Signal A (IP diversity)         : {signal_a}")
    out.append(f"  Signal B (GeoIP pattern)        : {signal_b}")
    out.append(f"  Signal C (RTT vs expected)      : {signal_c}")
 
    anycast_signals = sum([
        signal_a == "ANYCAST",
        signal_b in ("ANYCAST_STALE_GEOIP", "ANYCAST_ACCURATE_GEOIP"),
        signal_c == "LOCAL_POPS",
    ])
 
    if anycast_signals >= 2:
        if signal_b == "ANYCAST_ACCURATE_GEOIP":
            final = (
                "✅ Anycast/GeoDNS CONFIRMED (Akamai-style)\n"
                "   Each region resolves to a dedicated local PoP.\n"
                "   GeoIP labels are accurate. Indian users are served\n"
                "   from India-based infrastructure."
            )
        else:
            final = (
                "✅ Anycast CONFIRMED (Cloudflare-style)\n"
                "   Local PoPs serve traffic but IP registration is\n"
                "   centralized (e.g., in the US). GeoIP databases\n"
                "   misreport the actual serving location."
            )
    elif signal_b == "PARTIAL":
        final = (
            "⚠️  PARTIAL Anycast deployment detected.\n"
            "   Some regions have local PoPs; others are served\n"
            "   by a distant node. Traceroute analysis recommended."
        )
    else:
        final = (
            "❌ Single-origin server likely.\n"
            "   No evidence of Anycast. All traffic routed to\n"
            "   one physical location. Check traceroute for confirmation."
        )
 
    out.append(f"\n  → {final}")
 
    # ── Per-region RTT summary ────────────────────────────────
    out.append("\n" + "─" * 70)
    out.append("  RTT SUMMARY BY REGION")
    out.append("─" * 70)
 
    regions_order = ["IN", "SG", "DE", "US"]
    for cc in regions_order:
        vals = [r for c, r in rtt_by_country if c == cc]
        if vals:
            out.append(f"    {cc:>4}  min={min(vals):.3f} ms  "
                       f"max={max(vals):.3f} ms  "
                       f"n={len(vals)}")
        else:
            out.append(f"    {cc:>4}  N/A")
 
    return "\n".join(out) + "\n"
 
 
# ─────────────────────────────────────────────────────────────
# SECTION 4 — TRACEROUTE ANALYSIS
# ─────────────────────────────────────────────────────────────

# Hostname substrings that hint at a known data-center / carrier location
# DC_HINTS = {
#     # PayPal / eBay backbone identifiers
#     "paypal"  : "PayPal backbone",
#     "ebay"    : "eBay / PayPal network",
#     # US data-center city codes
#     "ash"     : "🇺🇸 Ashburn, VA (USA) — PayPal primary DC",
#     "sjc"     : "🇺🇸 San Jose, CA (USA)",
#     "ord"     : "🇺🇸 Chicago, IL (USA)",
#     "lax"     : "🇺🇸 Los Angeles, CA (USA)",
#     # India
#     "bom"     : "🇮🇳 Mumbai, India",
#     "del"     : "🇮🇳 Delhi, India",
#     "ccu"     : "🇮🇳 Kolkata, India",
#     # Asia-Pacific
#     "sin"     : "🇸🇬 Singapore",
#     "nrt"     : "🇯🇵 Tokyo, Japan",
#     "hkg"     : "🇭🇰 Hong Kong",
#     # Carriers seen in this measurement
#     "zayo"    : "Zayo Group (US backbone)",
#     "ntt"     : "NTT Communications",
#     "airtel"  : "Bharti Airtel (India)",
#     "hetzner" : "Hetzner (Germany)",
# }

# # IPs we specifically want to WHOIS — populated during traceroute parsing
# whois_queue = set()


# def parse_traceroute(results, probe_map):
#     print("\n" + "═" * 60)
#     print("TRACEROUTE RESULTS")
#     print("═" * 60)

#     # Collect (probe_id, country, list_of_(hop, ip, rtt)) for later WHOIS
#     all_paths = []

#     for r in results:
#         pid  = r.get("prb_id")
#         cc   = probe_map.get(pid, "??")
#         hops = r.get("result", [])

#         print(f"\n  Probe {pid:>8} ({cc}) — {len(hops)} hops toward {ENDPOINT}")

#         path_hops = []
#         for hop in hops:
#             idx = hop.get("hop")
#             for pkt in hop.get("result", []):
#                 rtt      = pkt.get("rtt")
#                 hop_addr = pkt.get("from", "*")
#                 if not rtt or hop_addr == "*":
#                     continue

#                 # Check for DC / carrier hint
#                 hint = ""
#                 for kw, loc in DC_HINTS.items():
#                     if kw in hop_addr.lower():
#                         hint = f"  ← {loc}"
#                         break

#                 print(f"    hop {idx:>3}: {hop_addr:<45} {rtt:>7.1f} ms{hint}")

#                 # Queue last 3 meaningful hops for WHOIS
#                 path_hops.append((idx, hop_addr, rtt))
#                 whois_queue.add(hop_addr)
#                 break  # one packet per hop is enough

#         all_paths.append((pid, cc, path_hops))

#     return all_paths


# # ─────────────────────────────────────────────────────────────
# # SECTION 5 — WHOIS / GEOIP ENRICHMENT
# # ─────────────────────────────────────────────────────────────

# def geoip_lookup(ip):
#     """
#     Query ipinfo.io for org, country, city.
#     Returns a dict; falls back gracefully on errors.
#     """
#     try:
#         r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
#         if r.ok:
#             return r.json()
#     except Exception:
#         pass
#     return {}


# def enrich_hops(whois_ips):
#     """
#     Run GeoIP lookups for every IP in whois_ips.
#     Returns {ip: {org, country, city}} dict.
#     """
#     print("\n" + "═" * 60)
#     print("WHOIS / GEOIP ENRICHMENT")
#     print("═" * 60)
#     print(f"  Querying {len(whois_ips)} unique IPs via ipinfo.io...\n")

#     enriched = {}
#     for ip in sorted(whois_ips):
#         d = geoip_lookup(ip)
#         enriched[ip] = {
#             "org"     : d.get("org",     "N/A"),
#             "country" : d.get("country", "??"),
#             "city"    : d.get("city",    "N/A"),
#             "region"  : d.get("region",  "N/A"),
#         }
#         org  = enriched[ip]["org"]
#         city = enriched[ip]["city"]
#         cc   = enriched[ip]["country"]
#         print(f"  {ip:<45} {cc}  {city:<20} {org}")
#         time.sleep(0.3)   # respect ipinfo free-tier rate limit

#     return enriched


# def annotate_paths(all_paths, enriched):
#     """
#     Re-print each traceroute path, now with WHOIS context on every hop.
#     Highlights the last hop before 66.211.168.123 as the 'handoff' point.
#     """
#     print("\n" + "═" * 60)
#     print("ANNOTATED TRACEROUTE PATHS  (with WHOIS)")
#     print("═" * 60)

#     for pid, cc, hops in all_paths:
#         print(f"\n  Probe {pid:>8} ({cc})")
#         for idx, ip, rtt in hops:
#             info = enriched.get(ip, {})
#             org  = info.get("org",     "")
#             city = info.get("city",    "")
#             c    = info.get("country", "")
#             note = f"{city}, {c}  |  {org}" if city != "N/A" else org
#             print(f"    hop {idx:>3}: {ip:<42} {rtt:>6.1f} ms  [{note}]")


# # ─────────────────────────────────────────────────────────────
# # SECTION 6 — SUMMARY REPORT
# # ─────────────────────────────────────────────────────────────

# def print_summary(rtt_by_country, all_paths, enriched):
#     print("\n" + "═" * 60)
#     print("SUMMARY — DATA LOCALIZATION ASSESSMENT")
#     print(f"Provider : {PROVIDER}")
#     print(f"Endpoint : {ENDPOINT}")
#     print(f"Run at   : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
#     print("═" * 60)

#     # RTT table
#     print("\n  RTT by vantage point:")
#     header = f"  {'Probe':>10}  {'Country':>7}  {'Avg RTT':>10}  {'Max Dist (km)':>15}  Verdict"
#     print(header)
#     print("  " + "-" * (len(header) - 2))
#     for cc, rtt in sorted(rtt_by_country, key=lambda x: x[1]):
#         dist          = rtt_to_max_dist(rtt)
#         _, label      = classify_distance(dist)
#         print(f"  {'':>10}  {cc:>7}  {rtt:>10.2f}  {dist:>15,.0f}  {label}")

#     # Anycast verdict
#     _, verdict = anycast_verdict(rtt_by_country)
#     print(f"\n  Anycast / Origin verdict:\n    {verdict}")

#     # Key hops in India paths
#     india_pids = [pid for pid, cc, _ in all_paths if cc == "IN"]
#     print(f"\n  India probe handoff IPs (last hops before destination):")
#     for pid, cc, hops in all_paths:
#         if cc != "IN":
#             continue
#         # Last 2 hops before the target
#         for idx, ip, rtt in hops[-3:-1]:
#             info = enriched.get(ip, {})
#             org  = info.get("org", "N/A")
#             c    = info.get("country", "??")
#             print(f"    Probe {pid}  hop {idx}: {ip}  [{c}]  {org}")

#     # Policy implication
#     print("\n  Policy implication for RBI localization mandate:")
#     india_rtts = [r for c, r in rtt_by_country if c == "IN"]
#     us_rtts    = [r for c, r in rtt_by_country if c == "US"]
#     if india_rtts and us_rtts:
#         ratio = min(india_rtts) / min(us_rtts)
#         if ratio < 1.5:
#             print("    Anycast confirmed — connection terminates at geographically")
#             print("    distributed nodes. Network-layer evidence CANNOT confirm that")
#             print("    payment data is stored within India; proxy / internal routing")
#             print("    to overseas backends cannot be ruled out (Proposal §Biggest Risk).")
#         else:
#             print("    Single-origin server outside India detected.")
#             print("    Strong network-layer evidence of NON-COMPLIANCE with RBI mandate.")

#     print("\n" + "═" * 60)


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print(f" RIPE Atlas Analysis — {PROVIDER}")
    print(f" Endpoint : {ENDPOINT}")
    print(f" Ping MSM : {PING_ID}")
    print(f" Trace MSM: {TRACE_ID}")
    print(f" Run at   : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print("=" * 60)

    # 1. Wait for both measurements to finish FIRST
    wait_for_measurement(PING_ID)
    wait_for_measurement(TRACE_ID)

    # 2. Resolve probe → country mapping (after results are ready)
    probe_map = fetch_probe_countries(PING_ID)

    # 3. Download results
    ping_results  = fetch_results(PING_ID)
    trace_results = fetch_results(TRACE_ID)

    # 4. Ping analysis — capture output for both terminal and report
    (rtt_by_country, probe_records), ping_text = capture_output(
        analyze_ping, ping_results, probe_map
    )
    print(ping_text)

    # # 5. Parse traceroute paths; populate whois_queue
    # all_paths = parse_traceroute(trace_results, probe_map)
    # ── placeholder: traceroute (add later) ──────────────────
    # all_paths, trace_text = capture_output(
    #     parse_traceroute, trace_results, probe_map
    # )
    # print(trace_text)
    trace_text = ""  # remove this line when traceroute is ready

    # # 6. WHOIS / GeoIP enrichment for every hop IP seen
    # enriched = enrich_hops(whois_queue)
    # ── placeholder: WHOIS enrichment (add later) ────────────
    # enriched, whois_text = capture_output(
    #     enrich_hops, whois_queue
    # )
    # print(whois_text)
    whois_text = ""  # remove this line when WHOIS is ready

    # # 7. Re-print paths with WHOIS annotations
    # annotate_paths(all_paths, enriched)

    # # 8. Print consolidated summary
    # print_summary(rtt_by_country, all_paths, enriched)

    # 9. Save structured report
    report_fname = (f"atlas_{PROVIDER.lower().replace(' ', '_')}"
                    f"_{PING_ID}_report.txt")
    save_report(report_fname, {
        "PING ANALYSIS"        : ping_text,
        "TRACEROUTE ANALYSIS"  : trace_text,   # populated in future step
        "WHOIS ENRICHMENT"     : whois_text,   # populated in future step
    })

    # 10. Save raw results to JSON for further processing
    output = {
        "provider"      : PROVIDER,
        "endpoint"      : ENDPOINT,
        "ping_msm_id"   : PING_ID,
        "trace_msm_id"  : TRACE_ID,
        "run_at"        : datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
        "probe_map"     : {str(k): v for k, v in probe_map.items()},
        "ping_results"  : ping_results,
        "trace_results" : trace_results,
        "rtt_by_country": [{"country": c, "min_rtt_ms": r}
                           for c, r in rtt_by_country],
        "probe_records" : probe_records,   # per-probe analysis results
    }
    json_fname = (f"atlas_{PROVIDER.lower().replace(' ', '_')}"
                  f"_{PING_ID}.json")
    with open(json_fname, "w") as f:
        json.dump(output, f, indent=2)
    print(f"[*] Raw data saved to {json_fname}")
 
 
if __name__ == "__main__":
    main()