import os
from pathlib import Path
import chromadb
from chromadb.config import Settings
from langchain_community.embeddings import HuggingFaceEmbeddings

# ---------------- CONFIG ----------------
# Dynamically get the project root (one level above the Resources folder)
BASE_DIR = Path(__file__).resolve().parent
PERSIST_DIR = BASE_DIR / "chroma_aws_db"  # <-- relative to project root
CHROMA_COLLECTION_NAME = "aws_sigma_rules"
TOP_K = 5  # Number of most relevant results to retrieve


# ---------------- LOAD CHROMA COLLECTION ----------------
chroma_client = chromadb.PersistentClient(path=PERSIST_DIR)
collection = chroma_client.get_collection(CHROMA_COLLECTION_NAME)

# ---------------- INITIALIZE HUGGING FACE EMBEDDINGS ----------------
embedding_model = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")

# ---------------- QUERY FUNCTION ----------------
def search_rules(query_text, top_k=TOP_K):
    # Compute embedding for query
    query_embedding = embedding_model.embed_query(query_text)

    # Perform similarity search
    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=top_k,
        include=["documents", "metadatas", "embeddings"]
    )

    return results

# ---------------- RUN ----------------
if __name__ == "__main__":
    query = input("Enter your query: ")
    results = search_rules(query, TOP_K)

    for i, (doc, meta) in enumerate(zip(results["documents"][0], results["metadatas"][0])):
        print(f"\n--- Result {i+1} ---")
        print(f"Title (from metadata): {meta.get('title')}")
        print(f"ID: {meta.get('rule_id')}")
        print(f"Document text (truncated): {doc[:500]}")  # Truncate for display
