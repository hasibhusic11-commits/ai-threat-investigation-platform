from app.ingest import ingest_logs

if __name__ == "__main__":
    count = ingest_logs()
    print(f"Ingested {count} events into Qdrant.")
