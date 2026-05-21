"""
RIPE Atlas Measurement Analysis — India Payment Data Localization Study
ECS 252 Project | Muyang Zheng, Jintian Xu, Yan Liang, Sijia Fan

Usage:
    python analyze_atlas.py

Requires:
    pip install requests
    pip install ipwhois
"""

import requests
import time
import json
from datetime import datetime, timezone
import math
import io
import sys
from ipwhois import IPWhois
import socket

# ─────────────────────────────────────────────────────────────
# CONFIG — edit these before running
# ─────────────────────────────────────────────────────────────
API_KEY   = "Your_RIPE_Atlas_API_Key"  # to be changed
PING_ID   = 173126494   # to be changed
TRACE_ID  = 173126495   # to be changed

# Provider label used in report output
PROVIDER  = "MobiKwik"  # to be changed
ENDPOINT  = "CDN: static.mobikwik.com"   # to be changed
TARGET_HOST = "static.mobikwik.com"   # 纯domain，用于文件命名, to be changed

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
        Different destination IPs per region  →  Anycast (GeoDNS: Different IPs per region)
        Same IP everywhere                    →  Unclear, could still be pure Anycast with stable IP
 
    Signal B — GeoIP vs RTT cross-validation pattern (Section 3)
        All CONTRADICTED →  Anycast (Cloudflare-style, IP registered far away, local PoPs serve everywhere)
        All CONSISTENT   →  Anycast (Akamai-style, each region has a local PoP, GeoIP correctly reports it)
        PARTIAL          →  Some regions local, others served remotely
        UNCLEAR          →  No data
 
    Signal C — actual RTT vs expected RTT
        For each non-IN region R: does RTT(R) roughly match the expected travel time from R to the GeoIP-claimed location?
            Expected RTT = 2 × dist_probe_to_geoip / 200 km/ms ratio = expected
        ratio < 0.5        →  actual << expected, Served by a nearby PoP, not the GeoIP location, Anycast
        0.5 <= ratio <= 2  →  actual ≈ expected, Server is likely near its GeoIP-claimed location
        ratio > 2          →  actual >> expected, anomaly, doesn't count
 
    Final verdict combines all three signals: 
        - 2+ signals: CONFIRMED Anycast 
        - Signal B = PARTIAL: Partial Anycast
        - < 2 signals: No anycast evidence; confirm with traceroute
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
# SECTION 5 — TRACEROUTE ANALYSIS
# ─────────────────────────────────────────────────────────────

CLIFF_THRESHOLD_MS = 20   # RTT cliff threshold, any diff larger than this will be seen as a cliff-like spike

def _best_rtt_for_hop(hop):
    """
    get the minimum RTT for one hop
    Returns: (min_rtt, corresponding_addr)
    if *, return (None, '*')
    """
    best_rtt  = None
    best_addr = "*"
    for pkt in hop.get("result", []):
        addr = pkt.get("from", "*")
        rtt  = pkt.get("rtt")
        if addr == "*" or rtt is None:
            continue
        if best_rtt is None or rtt < best_rtt:
            best_rtt  = rtt
            best_addr = addr
    return best_rtt, best_addr

def _is_foreign(info, probe_cc="IN"):
    """
    Return True if the IPinfo record places this IP outside the probe's
    home country. Returns False when info is None (cannot determine).
    """
    if not info:
        return False
    return info.get("country", "") != probe_cc

# rDNS
def rdns_lookup(ip):
    """
    Perform a reverse DNS lookup for a single IP address.
    Returns the hostname string, or None if the lookup fails or
    returns no PTR record.
    Used to extract geographic hints from router hostnames
    (e.g. 'cr1.mum01.airtel.net' hints at Mumbai).
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except Exception:
        return None



def parse_traceroute(results, probe_map):
    """
    For each traceroute path:
      1. Record per-hop: IP address, minimum RTT, IPinfo (ASN / org / country / city)
      2. Compute RTT diff between consecutive visible hops; flag cliff-like spikes
         (diff >= CLIFF_THRESHOLD_MS)
      3. Classify each hop into one of four egress categories (IN probes only):
           - egress             : cliff + foreign IP (confirmed cross-border egress)
           - egress_inconclusive: cliff but IPinfo still domestic
           - foreign_no_cliff   : foreign IP but no RTT spike
           - (none)             : domestic hop, no anomaly
      4. After a run of silent (*) hops, if the next visible hop is foreign,
         emit an 'egress boundary obscured' warning

    rDNS lookups are performed separately in enrich_rdns().
    WHOIS lookups are performed separately in enrich_whois().

    Returns:
        all_paths   : list of per-probe dicts for downstream enrichment
        whois_queue : set of every hop IP seen across all paths
    """
    print("\n" + "═" * 70)
    print("TRACEROUTE RESULTS — hop-by-hop IPinfo + RTT cliff detection")
    print("═" * 70)

    all_paths   = []
    whois_queue = set()

    for r in results:
        pid  = r.get("prb_id")
        cc   = probe_map.get(pid, "??")
        hops = r.get("result", [])

        print(f"\n  {'─' * 62}")
        print(f"  Probe {pid} ({cc}) — {len(hops)} hops toward {ENDPOINT}")

        # ── Pass 1: collect minimum RTT and address for each hop ─
        hop_records = []
        for hop in hops:
            idx = hop.get("hop")
            if idx is None:
                continue   # skip malformed hop entries with no hop index
            rtt, addr = _best_rtt_for_hop(hop)
            hop_records.append({
                "hop"                : idx,
                "addr"               : addr,
                "rtt"                : rtt,
                "ipinfo"             : None,
                "cliff"              : False,
                "egress"             : False,
                "egress_inconclusive": False,
                "foreign_no_cliff"   : False,
                "delta"              : None,
                "skipped_hops"       : 0, 
                "rdns"               : None,   # filled by enrich_rdns()
            })

        # ── Pass 2: query IPinfo for every hop that returned an IP ─
        for rec in hop_records:
            if rec["addr"] == "*":
                continue
            info = get_ip_info(rec["addr"])
            rec["ipinfo"] = info
            whois_queue.add(rec["addr"])
            time.sleep(0.2)

        # ── Pass 3: RTT cliff detection and egress classification ─
        # egress classification is only meaningful for IN probes;
        # for overseas probes, cliffs are recorded only for Anycast cross-validation
        visible = [rec for rec in hop_records if rec["rtt"] is not None and rec["hop"] != 255]
        for i in range(1, len(visible)):
            prev  = visible[i - 1]
            curr  = visible[i]
            delta = curr["rtt"] - prev["rtt"]
            skipped = curr["hop"] - prev["hop"] - 1
            if delta >= CLIFF_THRESHOLD_MS:
                curr["cliff"] = True
                curr["delta"] = delta
                curr["skipped_hops"] = skipped
                if cc == "IN":
                    if _is_foreign(curr["ipinfo"], probe_cc=cc):
                        curr["egress"] = True
                    else:
                        curr["egress_inconclusive"] = True

        # foreign-without-cliff classification: IN probes only
        if cc == "IN":
            for rec in hop_records:
                if (rec["hop"] == 255):
                    continue   # skip destination IP, not an intermediate routing hop
                if (not rec["cliff"]
                        and rec["addr"] != "*"
                        and _is_foreign(rec["ipinfo"], probe_cc=cc)):
                    rec["foreign_no_cliff"] = True

        # ── Pass 4: print progress to terminal only ───────────────
        for rec in hop_records:
            hop_idx = rec["hop"]
            addr    = rec["addr"]
            print(f"    hop {hop_idx:>3}: {addr}", flush=True)

        # ── per-path summary ──────────────────────────────────────
        egress_hops       = [rec for rec in hop_records if rec["egress"]]
        cliff_hops        = [rec for rec in hop_records if rec["cliff"]]
        inconclusive_hops = [rec for rec in hop_records if rec["egress_inconclusive"]]
        foreign_nc_hops   = [rec for rec in hop_records if rec["foreign_no_cliff"]]

        obscured = False
        for i, rec in enumerate(hop_records):
            if rec["addr"] != "*":
                continue
            for nxt in hop_records[i + 1 : i + 3]:
                if nxt["hop"] == 255:
                    continue   # destination IP is not an egress indicator
                if _is_foreign(nxt.get("ipinfo"), probe_cc=cc):
                    obscured = True
                    break

        # build summary string instead of printing directly
        summary_lines = [
            f"\n    Summary for probe {pid} ({cc}):",
            f"      RTT cliffs detected        : {len(cliff_hops)}"
            f"  at hops {[rec['hop'] for rec in cliff_hops]}",
            f"      Confirmed egress hops      : {len(egress_hops)}"
            f"  at hops {[rec['hop'] for rec in egress_hops]}",
            f"      Inconclusive (cliff only)  : {len(inconclusive_hops)}"
            f"  at hops {[rec['hop'] for rec in inconclusive_hops]}",
            f"      Foreign no-cliff           : {len(foreign_nc_hops)}"
            f"  at hops {[rec['hop'] for rec in foreign_nc_hops]}",
        ]
        if obscured:
            summary_lines.append(
                f"      ⚠️  Some egress boundaries may be obscured"
                f" by silent (*) hops"
            )
        probe_summary = "\n".join(summary_lines)

        # still print to terminal for progress monitoring
        print(probe_summary, flush=True)

        all_paths.append({
            "pid"        : pid,
            "cc"         : cc,
            "hop_records": hop_records,
            "egress_hops": egress_hops,
            "cliff_hops" : cliff_hops,
            "summary"    : probe_summary,   # store for annotate_paths
        })

    return all_paths, whois_queue


# ─────────────────────────────────────────────────────────────
# SECTION 6 — WHOIS & rDNS ENRICHMENT
# ─────────────────────────────────────────────────────────────
def whois_lookup(ip):
    """
    Query RDAP via ipwhois for a single IP address.
    Returns a dict with ASN, ASN description, network name, and country
    drawn from RIR registration data (APNIC / ARIN / RIPE etc.).
    Returns an empty dict on any failure.
    """
    try:
        result = IPWhois(ip).lookup_rdap(depth=1)
        network = result.get("network", {})
        return {
            "asn"          : result.get("asn",              "N/A"),
            "asn_desc"     : result.get("asn_description",  "N/A"),
            "network_name" : network.get("name",            "N/A"),
            "country"      : network.get("country",         "??"),
        }
    except Exception:
        return {}


def enrich_rdns(all_paths):
    """
    Perform rDNS lookups for egress_inconclusive and foreign_no_cliff hops
    on IN probes only. Results are written back into rec['rdns'] in-place.
    Confirmed egress hops are skipped because cliff + foreign IP already
    provides sufficient evidence without needing hostname hints.
    """
    for path in all_paths:
        if path["cc"] != "IN":
            continue
        for rec in path["hop_records"]:
            if (rec.get("egress_inconclusive")
                    or rec.get("foreign_no_cliff")):
                rec["rdns"] = rdns_lookup(rec["addr"])
                time.sleep(0.1)


def enrich_whois(all_paths):
    """
    Query RDAP for all egress-related hop IPs found in all_paths:
      - confirmed egress (cliff + foreign IP)
      - inconclusive egress (cliff but IPinfo still domestic)
      - foreign without cliff (foreign ASN but no RTT spike)
    Deduplicates IPs across probes so each address is queried only once.
    Returns {ip: whois_dict} without printing anything.
    """
    egress_ips = set()
    for path in all_paths:
        for rec in path["hop_records"]:
            if rec["addr"] == "*":
                continue
            if (rec.get("egress")
                    or rec.get("egress_inconclusive")
                    or rec.get("foreign_no_cliff")):
                egress_ips.add(rec["addr"])

    whois_cache = {}
    for ip in sorted(egress_ips):
        whois_cache[ip] = whois_lookup(ip)
        time.sleep(0.3)

    return whois_cache


# ─────────────────────────────────────────────────────────────
# SECTION 7 — TRACEROUTE ANNOTATION
# ─────────────────────────────────────────────────────────────

def annotate_paths(all_paths: list, whois_cache: dict):
    """
    Print every traceroute path with full per-hop annotations.
    No new network requests are issued here; all data comes from
    rec['ipinfo'] (Section 5), rec['rdns'] (enrich_rdns), and
    whois_cache (enrich_egress_hops).

    Per-hop output format:
      All visible hops    : 2 lines (IP/RTT/flags + IPinfo)
      Confirmed egress    : 3 lines (+ WHOIS)
      Inconclusive        : 4 lines (+ WHOIS + rDNS)
      Foreign no-cliff    : 4 lines (+ WHOIS + rDNS)
    """
    print("\n" + "═" * 70)
    print("ANNOTATED TRACEROUTE PATHS")
    print("═" * 70)

    for path in all_paths:
        pid  = path["pid"]
        cc   = path["cc"]
        hops = path["hop_records"]

        confirmed_count    = sum(1 for r in hops if r.get("egress"))
        inconclusive_count = sum(1 for r in hops if r.get("egress_inconclusive"))
        foreign_nc_count   = sum(1 for r in hops if r.get("foreign_no_cliff"))
        cliff_count        = sum(1 for r in hops if r.get("cliff"))

        print(f"\n  {'─' * 62}")
        print(f"  Probe {pid} ({cc})"
              f"  |  cliffs: {cliff_count}"
              f"  |  confirmed egress: {confirmed_count}"
              f"  |  inconclusive: {inconclusive_count}"
              f"  |  foreign no-cliff: {foreign_nc_count}")

        in_star_run = False

        for rec in hops:
            hop_idx  = rec["hop"]
            addr     = rec["addr"]
            rtt      = rec["rtt"]
            info     = rec.get("ipinfo")
            is_cliff = rec.get("cliff", False)
            delta    = rec.get("delta")

            # silent hop: one line only
            if addr == "*":
                print(f"    hop {hop_idx:>3}: {'*':<45}    (no response)")
                in_star_run = True
                continue

            # first visible hop after a silent run: warn if already foreign
            # only relevant for IN probes
            if in_star_run and cc == "IN" and _is_foreign(info, probe_cc=cc):
                print(f"          ⚠️  Egress boundary obscured"
                      f" by preceding silent hops")
            in_star_run = False

            # ── Line 2: IPinfo summary ────────────────────────────
            if info:
                geo_tag = (f"{info.get('country', '?')} / "
                           f"{info.get('city',    '?')} / "
                           f"{info.get('org',     '?')}")
            else:
                geo_tag = "(IPinfo unavailable)"

            # ── Line 1: flags ─────────────────────────────────────
            # cliff flag is independent and stacks with any egress flag
            flags = ""
            if is_cliff:
                skipped = rec.get("skipped_hops", 0)
                if skipped > 0:
                    flags += f"  ⚡ RTT +{delta:.0f} ms (across {skipped} silent hops)"
                else:
                    flags += f"  ⚡ RTT +{delta:.0f} ms"
            if rec.get("egress"):
                flags += "  🚨 CONFIRMED EGRESS"
            elif rec.get("egress_inconclusive"):
                flags += "  ⚠️  RTT spike, IPinfo domestic"
            elif rec.get("foreign_no_cliff"):
                flags += "  ⚠️  foreign ASN without RTT spike"

            # print line 1 and line 2
            print(f"    hop {hop_idx:>3}: {addr:<45} {rtt:>7.1f} ms{flags}")
            print(f"           IPinfo : {geo_tag}")

            # ── Line 3: WHOIS ─────────────────────────────────────
            # all three egress cases get WHOIS
            if (rec.get("egress") or rec.get("egress_inconclusive")
                    or rec.get("foreign_no_cliff")):
                if addr in whois_cache:
                    w = whois_cache[addr]
                    print(f"           WHOIS  : "
                          f"ASN {w.get('asn', 'N/A')} "
                          f"({w.get('asn_desc', 'N/A')}) | "
                          f"net={w.get('network_name', 'N/A')} | "
                          f"cc={w.get('country', '??')}")

            # ── Line 4: rDNS ──────────────────────────────────────
            # inconclusive and foreign-no-cliff only
            # rDNS hostname may reveal geographic hints that corroborate
            # or contradict the IPinfo country label
            if rec.get("egress_inconclusive") or rec.get("foreign_no_cliff"):
                rdns = rec.get("rdns")
                if rdns:
                    print(f"           rDNS   : {rdns}")
                else:
                    print(f"           rDNS   : (no PTR record)")

        # ── per-path egress summary ───────────────────────────────
        confirmed    = [r for r in hops if r.get("egress")]
        inconclusive = [r for r in hops if r.get("egress_inconclusive")]
        foreign_nc   = [r for r in hops if r.get("foreign_no_cliff")]

        if confirmed:
            print(f"\n    Confirmed egress hops for probe {pid} ({cc}):")
            for rec in confirmed:
                w = whois_cache.get(rec["addr"], {})
                print(f"      hop {rec['hop']:>3}: {rec['addr']:<45}"
                      f" RTT={rec['rtt']:.1f} ms"
                      f"  ASN={w.get('asn_desc', 'N/A')}")

        if inconclusive:
            print(f"\n    Inconclusive hops (RTT spike, IPinfo still domestic):")
            for rec in inconclusive:
                w    = whois_cache.get(rec["addr"], {})
                rdns = rec.get("rdns") or "no PTR record"
                print(f"      hop {rec['hop']:>3}: {rec['addr']:<45}"
                      f" RTT={rec['rtt']:.1f} ms"
                      f"  ASN={w.get('asn_desc', 'N/A')}"
                      f"  rDNS={rdns}")

        if foreign_nc:
            print(f"\n    Foreign ASN without RTT spike:")
            for rec in foreign_nc:
                w    = whois_cache.get(rec["addr"], {})
                rdns = rec.get("rdns") or "no PTR record"
                print(f"      hop {rec['hop']:>3}: {rec['addr']:<45}"
                      f" RTT={rec['rtt']:.1f} ms"
                      f"  ASN={w.get('asn_desc', 'N/A')}"
                      f"  rDNS={rdns}")

        if not confirmed and not inconclusive and not foreign_nc:
            print(f"\n    No egress evidence detected for probe {pid} ({cc}).")

        # print classification summary from parse_traceroute for all probes
        summary = path.get("summary", "")
        if summary:
            print(summary)

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

    # 1. Resolve probe → country mapping
    probe_map = fetch_probe_countries(PING_ID)

    # 2. Download results
    ping_results  = fetch_results(PING_ID)
    trace_results = fetch_results(TRACE_ID)

    # 3. Ping analysis — capture output for terminal and report
    (rtt_by_country, probe_records), ping_text = capture_output(
        analyze_ping, ping_results, probe_map
    )
    print(ping_text)

    # 4. Parse traceroute paths — prints progress to terminal only,
    #    not captured, not written to report
    all_paths, _ = parse_traceroute(trace_results, probe_map)

    # 5. rDNS enrichment for inconclusive and foreign-no-cliff hops (silent)
    enrich_rdns(all_paths)

    # 6. WHOIS enrichment for egress-related hops (silent)
    whois_cache = enrich_whois(all_paths)

    # 7. Annotated paths — capture output for terminal and report
    _, annotate_text = capture_output(
        annotate_paths, all_paths, whois_cache
    )
    print(annotate_text)

    # 8. Save structured report
    _domain_slug   = TARGET_HOST.lower().replace(".", "_")
    _provider_slug = PROVIDER.lower().replace(" ", "_")
    report_fname   = f"{_provider_slug}_{_domain_slug}_report.txt"
    save_report(report_fname, {
        "PING ANALYSIS"  : ping_text,
        "ANNOTATED PATHS": annotate_text,
    })

    # 9. Save raw results to JSON
    json_fname = f"{_provider_slug}_{_domain_slug}.json"
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
        "probe_records" : probe_records,
        "all_paths"     : [
            {
                "pid"                 : p["pid"],
                "cc"                  : p["cc"],
                "confirmed_egress"    : [
                    {"hop": r["hop"], "addr": r["addr"], "rtt": r["rtt"]}
                    for r in p["hop_records"] if r.get("egress")
                ],
                "inconclusive_egress" : [
                    {"hop": r["hop"], "addr": r["addr"], "rtt": r["rtt"],
                     "rdns": r.get("rdns")}
                    for r in p["hop_records"] if r.get("egress_inconclusive")
                ],
                "foreign_no_cliff"    : [
                    {"hop": r["hop"], "addr": r["addr"], "rtt": r["rtt"],
                     "rdns": r.get("rdns")}
                    for r in p["hop_records"] if r.get("foreign_no_cliff")
                ],
                "cliff_hops"          : [
                    r["hop"] for r in p["hop_records"] if r.get("cliff")
                ],
            }
            for p in all_paths
        ],
        "whois_cache"   : whois_cache,
    }
    with open(json_fname, "w") as f:
        json.dump(output, f, indent=2)
    print(f"[*] Raw data saved to {json_fname}")
 
if __name__ == "__main__":
    main()