import time
from collections import defaultdict, deque
from typing import Deque

from fastapi import Header, HTTPException, Request

from app.config import (
    APP_ENV,
    BACKEND_API_KEY,
    RATE_LIMIT_MAX_REQUESTS,
    RATE_LIMIT_WINDOW_SECONDS,
)

_request_store: dict[str, Deque[float]] = defaultdict(deque)


def _get_client_key(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    if not BACKEND_API_KEY:
        if APP_ENV == "production":
            raise HTTPException(status_code=500, detail="Server API key is not configured")
        return

    if x_api_key != BACKEND_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def rate_limit(request: Request) -> None:
    client_key = _get_client_key(request)
    now = time.time()
    bucket = _request_store[client_key]

    while bucket and now - bucket[0] > RATE_LIMIT_WINDOW_SECONDS:
        bucket.popleft()

    if len(bucket) >= RATE_LIMIT_MAX_REQUESTS:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    bucket.append(now)
