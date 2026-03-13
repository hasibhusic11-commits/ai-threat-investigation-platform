from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Core storage
DATA_FILE = Path(os.getenv("NORMALIZED_EVENTS_PATH", DATA_DIR / "security_logs.jsonl"))
CASE_STORE_FILE = Path(os.getenv("CASE_STORE_PATH", DATA_DIR / "cases.json"))

# Vector / search
QDRANT_PATH = os.getenv("QDRANT_PATH", str(BASE_DIR / "qdrant_data"))
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "security_logs")
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")

# Suricata / realtime
SURICATA_EVE_PATH = Path(
    os.getenv("SURICATA_EVE_PATH", DATA_DIR / "suricata" / "eve.json")
)
SURICATA_STATE_FILE = Path(
    os.getenv("SURICATA_STATE_FILE", DATA_DIR / "suricata_state.json")
)

# Threat intel
THREAT_INTEL_MODE = os.getenv("THREAT_INTEL_MODE", "disabled")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_BASE_URL = os.getenv(
    "ABUSEIPDB_BASE_URL",
    "https://api.abuseipdb.com/api/v2/check"
)
ALIENVAULT_OTX_API_KEY = os.getenv("ALIENVAULT_OTX_API_KEY", "")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "")

# Security
APP_ENV = os.getenv("APP_ENV", "development")
BACKEND_API_KEY = os.getenv("BACKEND_API_KEY", "")
CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS",
        "http://127.0.0.1:5173,http://localhost:5173"
    ).split(",")
    if origin.strip()
]

# Rate limiting
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_MAX_REQUESTS = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "60"))

DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
CASE_STORE_FILE.parent.mkdir(parents=True, exist_ok=True)
SURICATA_EVE_PATH.parent.mkdir(parents=True, exist_ok=True)
SURICATA_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
Path(QDRANT_PATH).mkdir(parents=True, exist_ok=True)
