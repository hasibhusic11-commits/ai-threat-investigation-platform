import json
from pathlib import Path

from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct


DATA_FILE = Path("data/security_logs.jsonl")
COLLECTION_NAME = "security_logs"


def load_logs(file_path: Path) -> list[dict]:
    logs = []
    with file_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                logs.append(json.loads(line))
    return logs


def main() -> None:
    logs = load_logs(DATA_FILE)

    model = SentenceTransformer("all-MiniLM-L6-v2")
    texts = [log["event_text"] for log in logs]
    vectors = model.encode(texts).tolist()

    client = QdrantClient(path="./qdrant_data")

    if client.collection_exists(COLLECTION_NAME):
        client.delete_collection(COLLECTION_NAME)

    client.create_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=VectorParams(size=len(vectors[0]), distance=Distance.COSINE),
    )

    points = []
    for log, vector in zip(logs, vectors):
        points.append(
            PointStruct(
                id=log["id"],
                vector=vector,
                payload={
                    "event_text": log["event_text"],
                    "source": log["source"],
                    "severity": log["severity"],
                    "event_type": log["event_type"],
                },
            )
        )

    client.upsert(collection_name=COLLECTION_NAME, points=points)
    print(f"Ingested {len(points)} security log events into '{COLLECTION_NAME}'.")


if __name__ == "__main__":
    main()
