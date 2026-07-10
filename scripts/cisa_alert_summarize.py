"""
cisa_alert_summarize.py  —  Lab 1.4, "before" script (the fragile approach)

Goal: summarize a single CISA cybersecurity advisory with an LLM.

To feed the LLM, this script first has to GET the advisory's web page from
www.cisa.gov. That site is fronted by the Akamai CDN, which fingerprints HTTP
clients and blocks ones that look automated. The `requests` library sends a
default User-Agent of "python-requests/x.y.z", so Akamai answers with
HTTP 403 Forbidden -- and the summarization pipeline never even starts,
because we never got the text.

Notice the failure happens at the FETCH step, before any AI is involved.
The tempting "fix" is to paste in a fake browser User-Agent (and, when that
stops working, a fuller set of browser headers). That is a brittle
cat-and-mouse game with the CDN. See cisa_alert_summarize_stable.py for the
durable approach: feed the same LLM clean, structured data from an ungated
official source instead of scraping gated HTML.
"""

import sys
import requests

# A single CISA "AA-series" joint advisory (narrative HTML, behind Akamai).
url = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-022a"

print(f"[*] Requesting {url}")
print("[*] Using the requests library's DEFAULT headers (no spoofing).")

# No custom headers. requests sends User-Agent: python-requests/x.y.z,
# which is exactly what Akamai gates on.
response = requests.get(url, timeout=30)

print(f"[*] Default User-Agent sent: python-requests/{requests.__version__}")
print(f"[*] HTTP status: {response.status_code}")

if response.status_code != 200:
    print()
    print("[X] DENIED. Akamai returned a non-200 response (typically 403).")
    print("    We never obtained the advisory text, so there is nothing to")
    print("    summarize. The AI half of the pipeline never runs.")
    print("    'Fixing' this with a fake browser User-Agent is a fragile bypass.")
    print("    Run cisa_alert_summarize_stable.py for the stable alternative.")
    sys.exit(1)

# Depending on your source IP and Akamai's mood, you may occasionally get a
# 200 -- which is itself the lesson: a pipeline that only works "sometimes"
# is not a pipeline. We deliberately stop here rather than build on a coin flip.
print("[!] Got 200 this time -- but this is INCONSISTENT. Akamai gates by")
print("    IP/reputation/fingerprint, so this will fail elsewhere or later.")
print("    Do not build an LLM summarization pipeline on top of a coin flip.")
print("    Run cisa_alert_summarize_stable.py for the stable alternative.")
sys.exit(0)
