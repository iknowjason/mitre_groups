"""
feeds_stable.py  —  Lab 1.4, "after" script (the durable approach)

Same goal: get the latest CISA alerts, programmatically.

The difference is NOT a better set of headers -- it is a better SOURCE.
Instead of scraping HTML/RSS from behind Akamai, we consume CISA's own
machine-readable data product: the Known Exploited Vulnerabilities (KEV)
catalog, which CISA publishes as JSON to a public GitHub repository.

Why this is the superior automation solution:
  * No CDN gate. GitHub's raw endpoint serves the file to ANY client --
    notice we send NO custom headers at all (not even a User-Agent trick).
  * Stable data CONTRACT. It is documented JSON with a fixed schema, so we
    parse fields directly. No HTML scraping, no LLM needed to "read" a page.
  * Licensed for reuse. The catalog is released under CC0 (public domain).
  * Fresh. The GitHub mirror updates within minutes of cisa.gov.

Same `requests` library as feeds.py -- we changed the DESTINATION,
not our disguise. That is the whole point.
"""

import sys
import requests

# CISA's official KEV catalog, mirrored to GitHub and served ungated.
KEV_JSON = (
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
    "known_exploited_vulnerabilities.json"
)

# How many of the most recently added alerts to display.
LATEST_N = 10

print(f"[*] Requesting {KEV_JSON}")
print("[*] Sending NO custom headers -- no browser impersonation required.")

# Plain GET. No headers dict. This is deliberate: prove the point that we
# are not smuggling ourselves past anything.
response = requests.get(KEV_JSON, timeout=30)
response.raise_for_status()  # a real error here is a real error, not a gate

catalog = response.json()

print(f"[+] HTTP status: {response.status_code}")
print(f"[+] Catalog: {catalog['title']}")
print(f"[+] Version: {catalog['catalogVersion']}  "
      f"Released: {catalog['dateReleased']}")
print(f"[+] Total known-exploited vulnerabilities: {catalog['count']}")
print()

# The file is not stored in date order, so sort by dateAdded (newest first)
# to get the "latest alerts" view.
vulns = sorted(
    catalog["vulnerabilities"],
    key=lambda v: v["dateAdded"],
    reverse=True,
)

print(f"=== {LATEST_N} most recently added CISA KEV alerts ===\n")
for v in vulns[:LATEST_N]:
    ransomware = v.get("knownRansomwareCampaignUse", "Unknown")
    print(f"[{v['dateAdded']}] {v['cveID']} — {v['vendorProject']} {v['product']}")
    print(f"    {v['vulnerabilityName']}")
    print(f"    Ransomware campaign use: {ransomware}")
    print(f"    Required action: {v['requiredAction']} (due {v['dueDate']})")
    print()

sys.exit(0)
