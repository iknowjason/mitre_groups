import logging
import sys
import requests
from llama_index.core import SummaryIndex
from llama_index.core import Document
from llama_index.core import Settings
from llama_index.llms.openai import OpenAI
import os

# Pin the LLM to an allowed model. LlamaIndex's default LLM is gpt-3.5-turbo,
# which is deprecated and returns HTTP 404 on the SANS LiteLLM proxy. The API key
# and base URL still come from the environment (OPENAI_API_KEY / OPENAI_API_BASE);
# only the model needs to change. gpt-4o is on the SANS allow-list.
Settings.llm = OpenAI(model="gpt-4o")

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logging.getLogger().addHandler(logging.StreamHandler(stream=sys.stdout))

# Set the url for this CISA alert
url = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-022a"

# Load the data from webpage with browser-like headers to bypass Akamai 403
headers = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/126.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}
response = requests.get(url, headers=headers)

# The CISA site is behind the Akamai CDN, which gates automated clients
# inconsistently. Only summarize when we actually received the page (HTTP 200).
# On a block (e.g. 403), exit gracefully with an explanation rather than
# crashing on a raise_for_status() traceback -- and write no text file.
if response.status_code != 200:
    print(f"[!] HTTP {response.status_code} from {url}")
    print("[!] Akamai (CISA's CDN) blocked this automated request. This gate is")
    print("    inconsistent -- it may succeed from another network or on a later run.")
    print("    Nothing was summarized and no text file was written. See")
    print("    cisa_alert_summarize_stable.py for a durable approach that reads")
    print("    CISA's machine-readable KEV feed instead of scraping the gated site.")
    sys.exit(1)

print("[+] HTTP 200 OK -- advisory fetched. Summarizing with the LLM...")

from html.parser import HTMLParser
from io import StringIO

class HTMLTextExtractor(HTMLParser):
    # Tags whose text content is not human-readable page content
    _SKIP_TAGS = {"script", "style", "noscript", "template", "head"}

    def __init__(self):
        super().__init__()
        self._output = StringIO()
        self._skip_depth = 0
    def handle_starttag(self, tag, attrs):
        if tag in self._SKIP_TAGS:
            self._skip_depth += 1
    def handle_endtag(self, tag):
        if tag in self._SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1
    def handle_data(self, data):
        if self._skip_depth == 0:
            self._output.write(data)
    def get_text(self):
        return self._output.getvalue()

extractor = HTMLTextExtractor()
extractor.feed(response.text)
documents = [Document(text=extractor.get_text())]

# Index the page
index = SummaryIndex.from_documents(documents)

# Set the query engine to the index.
# tree_summarize summarizes each chunk then combines them, avoiding the
# refine chain whose "return the original answer" step some models echo
# back literally (e.g. "Repeat the original answer.").
query_engine = index.as_query_engine(response_mode="tree_summarize")

# Call to OpenAI to summarize with prompt
text_summary = query_engine.query('Output this summary as text.  Include all fields in the security advisory webpage.  Include the URL that was fetched as the first field at top of text.  Include the IOCs as a field if you can parse them from the section that shows IOCs')

# Print the summary
print(text_summary)

# Extract the text
summary = str(text_summary)

# Create an advisory ID
advisory_id = url.split('/')[-1]

# Create a file name based on advisory
file_name = advisory_id + '.txt'

# Output text file
print("[+] Output to file: " + file_name)
with open(file_name, "w") as file:
    file.write(summary)
