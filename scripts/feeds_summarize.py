import logging
import sys
from datetime import datetime
from llama_index.core import SummaryIndex
from llama_index.core import Document
from bs4 import BeautifulSoup
import feedparser
import requests

# Configure logging
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logging.getLogger().addHandler(logging.StreamHandler(stream=sys.stdout))

def llm_summarize(url):
    """
    Fetches the advisory from the given URL, generates a summary using LlamaIndex,
    and writes the summary to a text file named after the advisory ID.
    :param url: The URL of the cybersecurity advisory.
    """
    try:
        print(f"[+] Processing URL: {url}")

        # Extract the advisory ID from the URL
        advisory_id = url.split('/')[-1]
        file_name = f"{advisory_id}.txt"

        # Load webpage content with User-Agent to bypass Akamai 403
        ua_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        response = requests.get(url, headers=ua_headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        page_text = soup.get_text(separator="\n", strip=True)
        documents = [Document(text=page_text)]

        # Generate summary using LlamaIndex
        index = SummaryIndex.from_documents(documents)
        query_engine = index.as_query_engine()

        text_summary = query_engine.query(
            'Output this summary as text. Include all fields in the security advisory webpage. '
            'Include the URL that was fetched as the first field at the top of the text. '
            'Include the IOCs as a field if you can parse them from the section that shows IOCs.'
        )

        # Convert response to string
        summary = str(text_summary)

        # Write summary to file
        with open(file_name, "w") as file:
            file.write(summary)

        print(f"[+] Successfully written summary to {file_name}")

    except Exception as e:
        print(f"[!] Error processing {url}: {str(e)}")

cisa_all_alerts = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
ua_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
response = requests.get(cisa_all_alerts, headers=ua_headers)
feed = feedparser.parse(response.text)

for entry in feed.entries:
    print("Entry Title:", entry.title)
    print("Entry Link:", entry.link)
    # Call the summarize function
    llm_summarize(entry.link)
    print("Entry Published Date:", entry.published)
    # Skip summary for now
    #print("Entry Summary:", entry.summary)
    print("\n")

sys.exit()

# Below code is if you want to filter on a specific time range
# Get right now
now = datetime.now().astimezone()
time_range = timedelta(days=1)

for entry in feed.entries:
    date_parts = entry.published.split(" ")

    if len(date_parts[3]) == 2:
        year = "20" + date_parts[3]
        date_parts[3] = year
        fixed_date = " ".join(date_parts)
    else:
        fixed_date = entry.published

    entry_date = datetime.strptime(fixed_date, "%a, %d %b %Y %H:%M:%S %z")

    if now - entry_date <= time_range:
        print("Entry Title:", entry.title)
        print("Entry Link:", entry.link)
        print("Entry Published Date:", entry.published)
        print("Entry Summary:", entry.summary)
        print("\n")
