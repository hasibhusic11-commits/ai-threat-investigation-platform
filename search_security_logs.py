from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient

COLLECTION_NAME = "security_logs"

def main():
    client = QdrantClient(path="./qdrant_data")
    model = SentenceTransformer("all-MiniLM-L6-v2")

    query_text = input("Enter security investigation query: ").strip()
    query_vector = model.encode(query_text).tolist()

    results = client.query_points(
        collection_name=COLLECTION_NAME,
        query=query_vector,
        limit=3,
    )

    print("\nTop matches:\n")

    for result in results.points:
        payload = result.payload

        print(f"Score: {result.score:.4f}")
        print(f"Event: {payload['event_text']}")
        print(f"Source: {payload['source']}")
        print(f"Severity: {payload['severity']}")
        print(f"Type: {payload['event_type']}")
        print("-" * 60)

if __name__ == "__main__":
    main()
