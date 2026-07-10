"""
cisa_alert_summarize_stable.py  —  Lab 1.4, "after" script (the durable approach)

Same goal: summarize a CISA alert with an LLM.

The difference is NOT a better set of headers -- it is a better SOURCE.
Instead of scraping advisory HTML from behind Akamai, we pull a structured
record from CISA's own machine-readable Known Exploited Vulnerabilities (KEV)
catalog, which CISA publishes as JSON to a public GitHub repository, and hand
that clean data to the same LLM summarizer.

Why this is the superior automation solution:
  * No CDN gate. GitHub's raw endpoint serves the file to ANY client -- we
    send NO custom headers at all (not even a User-Agent trick).
  * The LLM gets high-quality, structured input (documented JSON fields),
    not messy scraped page text full of nav bars and boilerplate.
  * Licensed for reuse (CC0) and fresh (updates within minutes of cisa.gov).

Usage:
    python3 cisa_alert_summarize_stable.py            # newest KEV entry
    python3 cisa_alert_summarize_stable.py CVE-2026-48282   # a specific CVE
"""

import sys
import logging
import requests
from llama_index.core import SummaryIndex
from llama_index.core import Document

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logging.getLogger().addHandler(logging.StreamHandler(stream=sys.stdout))

# CISA's official KEV catalog, mirrored to GitHub and served ungated.
KEV_JSON = (
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
    "known_exploited_vulnerabilities.json"
)

# Optional CVE id argument; otherwise summarize the most recently added alert.
wanted_cve = sys.argv[1].upper() if len(sys.argv) > 1 else None

print(f"[*] Requesting {KEV_JSON}")
print("[*] Sending NO custom headers -- no browser impersonation required.")

# Plain GET. No headers dict. The point is that we are not smuggling past anything.
response = requests.get(KEV_JSON, timeout=30)
response.raise_for_status()
catalog = response.json()
print(f"[+] HTTP status: {response.status_code}  ({catalog['count']} entries)")

# Select the record to summarize.
if wanted_cve:
    record = next((v for v in catalog["vulnerabilities"]
                   if v["cveID"].upper() == wanted_cve), None)
    if record is None:
        print(f"[X] {wanted_cve} not found in the KEV catalog.")
        sys.exit(1)
else:
    record = max(catalog["vulnerabilities"], key=lambda v: v["dateAdded"])

print(f"[+] Summarizing {record['cveID']} ({record['dateAdded']})")

# Build a clean, human-readable block from the STRUCTURED fields. No scraping,
# no HTML parsing -- the LLM receives exactly the data that matters.
alert_text = "\n".join([
    f"Source: {KEV_JSON}",
    f"CVE ID: {record['cveID']}",
    f"Vendor/Project: {record['vendorProject']}",
    f"Product: {record['product']}",
    f"Vulnerability Name: {record['vulnerabilityName']}",
    f"Date Added to KEV: {record['dateAdded']}",
    f"Short Description: {record['shortDescription']}",
    f"Required Action: {record['requiredAction']}",
    f"Due Date: {record['dueDate']}",
    f"Known Ransomware Campaign Use: {record.get('knownRansomwareCampaignUse', 'Unknown')}",
    f"CWEs: {', '.join(record.get('cwes', [])) or 'N/A'}",
    f"Notes: {record.get('notes', '')}",
])

documents = [Document(text=alert_text)]

# Index the record and summarize with the SAME LLM pipeline the scrape version
# used -- tree_summarize avoids the refine chain some models echo back as
# "Repeat the original answer."
index = SummaryIndex.from_documents(documents)
query_engine = index.as_query_engine(response_mode="tree_summarize")

text_summary = query_engine.query(
    "Output this summary as text. Include all fields from the CISA KEV record. "
    "Put the CVE ID and the source URL as the first fields at the top. "
    "Call out whether it is known to be used in ransomware campaigns."
)

print(text_summary)
summary = str(text_summary)

# Output text file named after the CVE.
file_name = record["cveID"] + ".txt"
print("[+] Output to file: " + file_name)
with open(file_name, "w") as file:
    file.write(summary)
