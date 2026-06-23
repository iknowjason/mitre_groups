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
