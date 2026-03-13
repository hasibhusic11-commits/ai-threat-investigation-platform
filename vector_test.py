from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct

# Local embedded Qdrant database
client = QdrantClient(":memory:")

collection_name = "demo_vectors"

# Delete collection if it already exists
if client.collection_exists(collection_name):
    client.delete_collection(collection_name)

# Create collection
client.create_collection(
    collection_name=collection_name,
    vectors_config=VectorParams(size=4, distance=Distance.COSINE),
)

# Insert sample vectors
points = [
    PointStruct(id=1, vector=[0.9, 0.1, 0.1, 0.2], payload={"text": "apple fruit"}),
    PointStruct(id=2, vector=[0.1, 0.9, 0.2, 0.1], payload={"text": "car engine"}),
    PointStruct(id=3, vector=[0.85, 0.15, 0.05, 0.1], payload={"text": "banana apple"}),
]

client.upsert(collection_name=collection_name, points=points)

# Search using a query vector
results = client.query_points(
    collection_name=collection_name,
    query=[0.88, 0.12, 0.08, 0.15],
    limit=2,
)

print("\nTop matches:\n")
for r in results.points:
    print(r.payload["text"], r.score)
