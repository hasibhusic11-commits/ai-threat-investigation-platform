import json
from pathlib import Path
from typing import Any

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, PointStruct, VectorParams

from app.config import COLLECTION_NAME, DATA_FILE, QDRANT_PATH
from app.enrichment import enrich_event
from app.model_loader import get_embedding_model


def load_logs(file_path: Path) -> list[dict]:
    logs: list[dict] = []
    if not file_path.exists():
        return logs

    with file_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                logs.append(json.loads(line))
    return logs


def build_search_text(log: dict) -> str:
    parts = [
        log.get("event_text", ""),
        f"source {log.get('source', '')}",
        f"type {log.get('event_type', '')}",
        f"severity {log.get('severity', '')}",
        f"host {log.get('host', '')}",
        f"user {log.get('username', '')}",
        f"src_ip {log.get('src_ip', '')}",
        f"dest_ip {log.get('dest_ip', '')}",
        f"signature {log.get('signature', '')}",
        f"category {log.get('category', '')}",
    ]
    return " | ".join(parts)


def ingest_logs() -> int:
    logs = load_logs(DATA_FILE)
    if not logs:
        return 0

    model = get_embedding_model()

    enriched_logs = []
    searchable_texts = []

    for log in logs:
        enrichment = enrich_event(log["event_text"], log.get("severity"))
        merged = {**log, **enrichment}
        enriched_logs.append(merged)
        searchable_texts.append(build_search_text(merged))

    vectors = model.encode(searchable_texts).tolist()
    client = QdrantClient(path=QDRANT_PATH)

    if client.collection_exists(COLLECTION_NAME):
        client.delete_collection(COLLECTION_NAME)

    client.create_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=VectorParams(size=len(vectors[0]), distance=Distance.COSINE),
    )

    points = []
    for log, vector in zip(enriched_logs, vectors):
        points.append(
            PointStruct(
                id=int(log["id"]),
                vector=vector,
                payload=log,
            )
        )

    client.upsert(collection_name=COLLECTION_NAME, points=points)
    return len(points)


def upsert_single_event(event: dict[str, Any]) -> dict[str, Any]:
    model = get_embedding_model()
    client = QdrantClient(path=QDRANT_PATH)

    enrichment = enrich_event(event["event_text"], event.get("severity"))
    merged = {**event, **enrichment}

    searchable_text = build_search_text(merged)
    vector = model.encode(searchable_text).tolist()

    if not client.collection_exists(COLLECTION_NAME):
        client.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=VectorParams(size=len(vector), distance=Distance.COSINE),
        )

    point = PointStruct(
        id=int(merged["id"]),
        vector=vector,
        payload=merged,
    )

    client.upsert(collection_name=COLLECTION_NAME, points=[point])
    return merged
