import logging
import sys
from datetime import datetime
import feedparser

# Configure logging
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logging.getLogger().addHandler(logging.StreamHandler(stream=sys.stdout))

cisa_all_alerts = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
feed = feedparser.parse(cisa_all_alerts)

count = 0
for entry in feed.entries:
    count += 1
    print("Entry Title:", entry.title)
    print("Entry Link:", entry.link)
    print("Entry Published Date:", entry.published)
    # Skip summary for now
    #print("Entry Summary:", entry.summary)
    print("\n")
