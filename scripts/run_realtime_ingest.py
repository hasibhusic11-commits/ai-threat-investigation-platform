from app.realtime_ingest import run_realtime_pipeline


if __name__ == "__main__":
    run_realtime_pipeline(poll_interval=2)
