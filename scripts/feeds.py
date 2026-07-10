import logging
import sys
from datetime import datetime
import feedparser
import requests

# Configure logging
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logging.getLogger().addHandler(logging.StreamHandler(stream=sys.stdout))

cisa_all_alerts = "https://www.cisa.gov/cybersecurity-advisories/all.xml"

# Fetch with browser User-Agent to bypass Akamai 403
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
response = requests.get(cisa_all_alerts, headers=headers)

print(f"[DEBUG] HTTP status: {response.status_code}")

# Graceful handling if the CISA CDN (Akamai) gates this automated request.
# On a non-200 (typically 403), there is no RSS feed to parse -- exit with a
# clear message instead of silently reporting 0 entries.
if response.status_code != 200:
    print(f"[!] Expected HTTP 200 but received {response.status_code}.")
    print("[!] The CISA site is behind the Akamai CDN, which can block automated")
    print("    requests (typically HTTP 403 Forbidden). No RSS data was returned,")
    print("    so there is nothing to parse. Try again later or from another network.")
    sys.exit(1)

print(f"[DEBUG] Content length: {len(response.text)} chars")
print(f"[DEBUG] First 300 chars:\n{response.text[:300]}\n---")

feed = feedparser.parse(response.text)

print(f"[DEBUG] Feed entries: {len(feed.entries)}")

count = 0
for entry in feed.entries:
    count += 1
    print("Entry Title:", entry.title)
    print("Entry Link:", entry.link)
    print("Entry Published Date:", entry.published)
    print()
    # Skip summary for now
    #print("Entry Summary:", entry.summary)
    print("\n")
