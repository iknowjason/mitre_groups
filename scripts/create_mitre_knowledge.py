import glob
import tiktoken
from langchain_community.document_loaders import UnstructuredMarkdownLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores import Chroma
import os
import shutil
import time

current_directory = os.path.dirname(__file__)
documents_directory = os.path.join(current_directory, "documents")
chroma_db_path = os.path.join(current_directory, "chroma_db")

# Index Source Knowledge by Loading Documents
group_files = glob.glob(os.path.join(documents_directory, "*.md"))

# Loading Markdown files
md_docs = []
print("[+] Loading Group markdown files")
for group in group_files:
    print(f' [*] Loading {os.path.basename(group)}')
    loader = UnstructuredMarkdownLoader(group)
    md_docs.extend(loader.load())
print(f'[+] Number of .md documents processed: {len(md_docs)}')

# Tokenizer
tokenizer = tiktoken.get_encoding('cl100k_base')

def tiktoken_len(text):
    tokens = tokenizer.encode(
        text,
        disallowed_special=()
    )
    return len(tokens)

# Get token counts for original documents
token_counts = [tiktoken_len(doc.page_content) for doc in md_docs]
print(f"""[+] Original Document Token Counts:
Min: {min(token_counts)}
Avg: {int(sum(token_counts) / len(token_counts))}
Max: {max(token_counts)}""")

# Chunking Text with Markdown-aware separators
print('[+] Initializing RecursiveCharacterTextSplitter')
text_splitter = RecursiveCharacterTextSplitter(
    chunk_size=500,
    chunk_overlap=100,  # 20% overlap
    length_function=tiktoken_len,
    separators=[
        '\n## ',      # Major markdown headers
        '\n### ',     # Sub-headers
        '\n#### ',    # Technique headers
        '\n\n',       # Paragraphs
        '\n',         # Lines
        '. ',         # Sentences
        ' ',          # Words
        ''            # Characters
    ]
)

print('[+] Splitting documents in chunks')
all_chunks = text_splitter.split_documents(md_docs)

# Calculate chunk statistics
chunk_tokens = [tiktoken_len(chunk.page_content) for chunk in all_chunks]
total_tokens = sum(chunk_tokens)
print(f"""[+] Chunk Statistics:
Total chunks: {len(all_chunks)}
Total tokens: {total_tokens}
Min tokens per chunk: {min(chunk_tokens)}
Avg tokens per chunk: {int(total_tokens / len(all_chunks))}
Max tokens per chunk: {max(chunk_tokens)}""")

# Initialize embeddings
print("[+] Initializing OpenAI embeddings (text-embedding-3-large with 3072 dimensions)")
embed_model = OpenAIEmbeddings(
    model="text-embedding-3-large",
    # Full embedding dimensions (3072) - Higher quality embeddings
    dimensions=3072
)

# Delete existing collection to start fresh
print("[+] Removing old ChromaDB if it exists")
if os.path.exists(chroma_db_path):
    shutil.rmtree(chroma_db_path)
    print("[+] Old database removed")

# Process in batches to stay under 300k token limit
# Use conservative batch size to ensure we don't hit the limit
MAX_TOKENS_PER_BATCH = 250000  # Leave buffer under 300k limit
current_batch = []
current_batch_tokens = 0
batch_number = 1
db = None

print(f"[+] Processing chunks in batches (max {MAX_TOKENS_PER_BATCH} tokens per batch)")

for i, chunk in enumerate(all_chunks):
    chunk_token_count = tiktoken_len(chunk.page_content)
    
    # If adding this chunk would exceed limit, process current batch
    if current_batch_tokens + chunk_token_count > MAX_TOKENS_PER_BATCH and current_batch:
        print(f"[+] Processing batch {batch_number} ({len(current_batch)} chunks, {current_batch_tokens} tokens)")
        
        try:
            if db is None:
                # Create new database with first batch
                db = Chroma.from_documents(
                    current_batch,
                    embed_model,
                    collection_name="groups_collection",
                    persist_directory=chroma_db_path
                )
            else:
                # Add to existing database
                db.add_documents(current_batch)
            
            print(f"[+] Batch {batch_number} completed successfully")
            
            # Small delay to avoid rate limits
            time.sleep(1)
            
        except Exception as e:
            print(f"[!] Error processing batch {batch_number}: {e}")
            raise
        
        # Reset for next batch
        current_batch = []
        current_batch_tokens = 0
        batch_number += 1
    
    # Add chunk to current batch
    current_batch.append(chunk)
    current_batch_tokens += chunk_token_count

# Process final batch if there are remaining chunks
if current_batch:
    print(f"[+] Processing final batch {batch_number} ({len(current_batch)} chunks, {current_batch_tokens} tokens)")
    
    try:
        if db is None:
            # Create new database if this is the only batch
            db = Chroma.from_documents(
                current_batch,
                embed_model,
                collection_name="groups_collection",
                persist_directory=chroma_db_path
            )
        else:
            # Add to existing database
            db.add_documents(current_batch)
        
        print(f"[+] Final batch completed successfully")
        
    except Exception as e:
        print(f"[!] Error processing final batch: {e}")
        raise

# Verify the database
if db:
    collection = db._collection
    total_docs = collection.count()
    print(f"\n[+] Vector database created successfully!")
    print(f"[+] Total documents in database: {total_docs}")
    print(f"[+] Total chunks processed: {len(all_chunks)}")
    
    if total_docs != len(all_chunks):
        print(f"[!] WARNING: Document count mismatch! Expected {len(all_chunks)}, got {total_docs}")
else:
    print("[!] ERROR: Database was not created")

print("[+] Script complete")
