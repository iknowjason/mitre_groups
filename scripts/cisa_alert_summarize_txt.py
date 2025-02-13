import logging
import sys
from llama_index.core import SummaryIndex
from llama_index.readers.web import SimpleWebPageReader
import os

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logging.getLogger().addHandler(logging.StreamHandler(stream=sys.stdout))

# Set the url for this CISA alert
url = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-022a"

# Load the data from webpage
documents = SimpleWebPageReader(html_to_text=True).load_data([url])

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
