"""
Quick utility to check ISP diversity of probes used in a measurement.
Run once after submitting measurements to verify probe coverage.

Usage:
    python check_probes.py
"""

import requests
import time

API_KEY = "Your_RIPE_Atlas_API_Key"   # same as analyze_atlas.py
PING_ID = 173124378                    # to be changed

def atlas_get(path):
    r = requests.get(
        f"https://atlas.ripe.net/api/v2/{path}",
        headers={"Authorization": f"Key {API_KEY}"}
    )
    r.raise_for_status()
    return r.json()


def check_probe_isp_diversity(msm_id):
    print(f"\nChecking probe ISP diversity for measurement {msm_id}...")

    # fetch results to get probe IDs that actually participated
    results   = atlas_get(f"measurements/{msm_id}/results/")
    probe_ids = list({r.get("prb_id") for r in results if r.get("prb_id")})
    print(f"Found {len(probe_ids)} probes: {probe_ids}\n")

    india_probes = []

    for pid in probe_ids:
        probe   = atlas_get(f"probes/{pid}/")
        cc      = probe.get("country_code", "??")
        asn_v4  = probe.get("asn_v4")
        status  = probe.get("status", {}).get("name", "?")

        # fetch ASN description from RIPE Stat
        asn_desc = "unknown"
        if asn_v4:
            try:
                stat = requests.get(
                    f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn_v4}",
                    timeout=5
                ).json()
                asn_desc = stat.get("data", {}).get("holder", "unknown")
            except Exception:
                pass

        row = {
            "pid"     : pid,
            "cc"      : cc,
            "asn"     : asn_v4,
            "isp"     : asn_desc,
            "status"  : status,
        }

        print(f"  Probe {pid:>8} | cc={cc} | ASN={asn_v4} | {asn_desc} | status={status}")

        if cc == "IN":
            india_probes.append(row)

        time.sleep(0.3)

    # summary for Indian probes
    print(f"\n  Indian probes ({len(india_probes)} total):")
    asns_seen = set()
    for p in india_probes:
        duplicate = " ⚠️  DUPLICATE ISP" if p["asn"] in asns_seen else ""
        print(f"    Probe {p['pid']:>8} | ASN {p['asn']} | {p['isp']}{duplicate}")
        asns_seen.add(p["asn"])

    if len(asns_seen) == len(india_probes):
        print(f"\n  ✅ All {len(india_probes)} Indian probes are on different ISPs.")
    else:
        print(f"\n  ⚠️  Only {len(asns_seen)} distinct ISPs across {len(india_probes)} Indian probes.")
        print(f"     Consider specifying probes by ASN in your next measurement.")
        print(f"\n  Suggested measurement.py probe config:")
        for asn in asns_seen:
            print(f'    {{"type": "asn", "value": {asn}, "requested": 1}},')
        print(f"\n  Additional major Indian ISP ASNs to consider:")
        suggestions = {
            9498 : "Bharti Airtel",
            55836: "Reliance Jio",
            9829 : "BSNL",
            17813: "Idea / Vodafone (Vi)",
            24560: "Airtel Mobile",
            45609: "Bharti Airtel (mobile)",
        }
        for asn, name in suggestions.items():
            if asn not in asns_seen:
                print(f"    ASN {asn:>6} — {name}")


if __name__ == "__main__":
    check_probe_isp_diversity(PING_ID)