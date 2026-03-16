from app.config import CASE_STORE_FILE, DATA_FILE

DATA_FILE.write_text("", encoding="utf-8")
CASE_STORE_FILE.write_text("[]", encoding="utf-8")

print("Demo data reset complete.")
