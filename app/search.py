from qdrant_client import QdrantClient

from app.config import COLLECTION_NAME, QDRANT_PATH
from app.model_loader import get_embedding_model


def search_logs(query_text: str, limit: int = 5) -> list[dict]:
    client = QdrantClient(path=QDRANT_PATH)
    model = get_embedding_model()

    query_vector = model.encode(query_text).tolist()

    results = client.query_points(
        collection_name=COLLECTION_NAME,
        query=query_vector,
        limit=limit,
    )

    output = []
    for result in results.points:
        output.append(
            {
                "score": float(result.score),
                "payload": result.payload,
            }
        )

    return output
