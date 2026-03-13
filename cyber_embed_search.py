from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct

# Example documents
docs = [
    "Qdrant is a vector database used for similarity search.",
    "Cybersecurity analysts investigate suspicious login activity.",
    "Python is commonly used for machine learning and backend development.",
    "Network engineers troubleshoot routers, switches, and firewalls.",
]

# Load embedding model
model = SentenceTransformer("all-MiniLM-L6-v2")

# Convert documents into vectors
vectors = model.encode(docs).tolist()

# Start in-memory Qdrant
client = QdrantClient(":memory:")

collection_name = "text_embeddings"

# Reset collection
if client.collection_exists(collection_name):
    client.delete_collection(collection_name)

client.create_collection(
    collection_name=collection_name,
    vectors_config=VectorParams(size=len(vectors[0]), distance=Distance.COSINE),
)

# Insert embedded documents
points = []
for i, (doc, vector) in enumerate(zip(docs, vectors), start=1):
    points.append(
        PointStruct(
            id=i,
            vector=vector,
            payload={"text": doc}
        )
    )

client.upsert(collection_name=collection_name, points=points)

# Query
query_text = "How do security teams detect suspicious activity?"
query_vector = model.encode(query_text).tolist()

results = client.query_points(
    collection_name=collection_name,
    query=query_vector,
    limit=3,
)

print(f"\nQuery: {query_text}\n")
print("Top semantic matches:\n")

for r in results.points:
    print(r.payload["text"], r.score)
