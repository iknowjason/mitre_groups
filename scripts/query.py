from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import SentenceTransformerEmbeddings
from langchain_openai import OpenAIEmbeddings
from langchain_openai import OpenAI
from langchain_chroma import Chroma
from langchain.chains import RetrievalQA
from langchain_core.prompts import PromptTemplate
from langchain.chains.combine_documents.stuff import create_stuff_documents_chain
import openai
import os
from dotenv import load_dotenv
import tqdm as notebook_tqdm
import chromadb

current_directory = os.path.dirname(__file__)
chroma_db = os.path.join(current_directory, "./chroma_db")
persistent_client = chromadb.PersistentClient(path=chroma_db)

embed_model = OpenAIEmbeddings(
    model="text-embedding-3-large",
    dimensions=768
)

db = Chroma(
    client=persistent_client,
    collection_name="groups_collection",
    embedding_function=embed_model,
)
db.get()

load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

# Create a retriever from the vector store
retriever = db.as_retriever(search_kwargs={"k":5})

# query 1:  Retrieve and answer a general question
query1 = "What threat actors sent text messages to their targets?"

print("[+] Getting relevant documents for query 1")
relevant_docs1 = retriever.invoke(query1)
for doc in relevant_docs1:
    print(doc.page_content)

# Use the RetrievalQA chain to answer query1 automatically
qa_chain = RetrievalQA.from_chain_type(
    llm=OpenAI(temperature=0),
    chain_type="stuff",
    retriever=retriever,
)

answer1 = qa_chain.invoke(query1)
print("Answer for query 1:")
print(answer1)

# Query 2: Retrieve documents manually and then run a custom chain with a custom prompt
query2 = "What threat actor groups sent text messages to their targets over social media accounts?"

relevant_docs2 = retriever.invoke(query2)
# Optionally, print out the retrieved documents for inspection
"""
print("Retrieved documents for query 2:")
if relevant_docs2:
    for idx, doc in enumerate(relevant_docs2):
        print(f"Document {idx+1}:")
        print(doc.page_content)
else:
    print("No documents retrieved for query 2.")
"""
# Define a custom prompt template
template = (
    "Use the following pieces of context to answer the question at the end.\n"
    "If you don't know the answer, just say that you don't know, don't try to make up an answer.\n"
    "Use three sentences maximum and keep the answer as concise as possible.\n"
    "Always say \"thanks for asking!\" at the end of the answer.\n\n"
    "{context}\n\n"
    "Question: {question}\n\n"
    "Helpful Answer:"
)

custom_prompt = PromptTemplate(
    template=template,
    input_variables=["context", "question"]
)

# Create the stuff chain using the recommended constructor
doc_chain = create_stuff_documents_chain(
    llm=OpenAI(temperature=0),
    prompt=custom_prompt,
)

print("[+] Asking LLM query 2")
result = doc_chain.invoke({"context": relevant_docs2, "question": query2})
print("[+] Answer for query 2")
print(result)

# Query 3: Retrieve documents manually and run a custom prompt chain
query3 = "What are some phishing techniques used by threat actors?"

print("[+] Getting relevant documents for query 3")
relevant_docs3 = retriever.invoke(query3)

#Optional
"""
print("Retrieved documents for query 3:")
for idx, doc in enumerate(relevant_docs3):
    print(f"Document {idx+1}:")
    print(doc.page_content)
"""

print("[+] Asking LLM query 3")
result3 = doc_chain.invoke({"context": relevant_docs3, "question": query3})

print("Answer for query 3:")
print(result3)
