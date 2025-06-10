import glob
import tiktoken
from langchain_community.document_loaders import UnstructuredMarkdownLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.embeddings import SentenceTransformerEmbeddings
from langchain_community.vectorstores import Chroma
from langchain_openai import OpenAIEmbeddings
import openai
import os

current_directory = os.path.dirname(__file__)
documents_directory = os.path.join(current_directory, "documents")
contrib_directory = os.path.join(current_directory, "contrib")
embeddings_directory = os.path.join(current_directory, "embeddings")
templates_directory = os.path.join(current_directory, "templates")
group_template = os.path.join(templates_directory, "group.md")

# Index Source Knowlege by Loading Documents
group_files = glob.glob(os.path.join(documents_directory, "*.md"))

# Loading Markdown files
md_docs = []
print("[+] Loading Group markdown files..")
for group in group_files:
    print(f' [*] Loading {os.path.basename(group)}')
    loader = UnstructuredMarkdownLoader(group)
    md_docs.extend(loader.load())

print(f'[+] Number of .md documents processed: {len(md_docs)}')

# Tokenizer
tokenizer = tiktoken.get_encoding('cl100k_base')
token_integers = tokenizer.encode(md_docs[0].page_content, disallowed_special=())
num_tokens = len(token_integers)
token_bytes = [tokenizer.decode_single_token_bytes(token) for token in token_integers]
print(f"token count: {num_tokens} tokens")

def tiktoken_len(text):
    tokens = tokenizer.encode(
        text,
        disallowed_special=() #To disable this check for all special tokens
    )
    return len(tokens)

# Get token counts
token_counts = [tiktoken_len(doc.page_content) for doc in md_docs]

print(f"""[+] Token Counts:
Min: {min(token_counts)}
Avg: {int(sum(token_counts) / len(token_counts))}
Max: {max(token_counts)}""")

# Chunking Text
print('[+] Initializing RecursiveCharacterTextSplitter')
text_splitter = RecursiveCharacterTextSplitter(
    chunk_size=500,
    chunk_overlap=50,
    length_function=tiktoken_len,
    separators=['\n\n', '\n', ' ', '']
)

print('[+] Splitting documents in chunks')
#chunks = text_splitter.split_documents(md_docs)
# Note:  Changing this so that only 300000 tokens or less are used, as exceeding causes error
MAX_TOKENS = 300_000
current_token_sum = 0
safe_chunks = []

for chunk in text_splitter.split_documents(md_docs):
    chunk_tokens = tiktoken_len(chunk.page_content)
    if current_token_sum + chunk_tokens > MAX_TOKENS:
        break
    safe_chunks.append(chunk)
    current_token_sum += chunk_tokens

print(f'[+] Using {len(safe_chunks)} chunks (total {current_token_sum} tokens) for embedding')

print(f'[+] Number of documents: {len(md_docs)}')
#print(f'[+] Number of chunks: {len(chunks)}')

embed_model = OpenAIEmbeddings(
    model="text-embedding-3-large",
    dimensions=768
)

print("[+] Load embeddings into Chroma and save it to disk")
db = Chroma.from_documents(safe_chunks, embed_model, collection_name="groups_collection", persist_directory="./chroma_db")
#db = Chroma.from_documents(chunks, embed_model, collection_name="groups_collection", persist_directory="./chroma_db")

## An example question
"""
query = "What threat actors send text messages to their targets?"
print("[+] Asking question:")
print(query)
relevant_docs = db.similarity_search(query)
print("[+] Print relevant docs search from query")
print(relevant_docs[0].page_content)
"""
print("[+] Script complete")
