import logging
import sys
import requests
from llama_index.core import SummaryIndex
from llama_index.core import Document
import os

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logging.getLogger().addHandler(logging.StreamHandler(stream=sys.stdout))

# Set the url for this CISA alert
url = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-022a"

# Load the data from webpage with User-Agent to bypass Akamai 403
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
response = requests.get(url, headers=headers)
response.raise_for_status()

from html.parser import HTMLParser
from io import StringIO

class HTMLTextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self._output = StringIO()
    def handle_data(self, data):
        self._output.write(data)
    def get_text(self):
        return self._output.getvalue()

extractor = HTMLTextExtractor()
extractor.feed(response.text)
documents = [Document(text=extractor.get_text())]

# Index the page
index = SummaryIndex.from_documents(documents)

# Set the query engine to the index
query_engine = index.as_query_engine()

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
