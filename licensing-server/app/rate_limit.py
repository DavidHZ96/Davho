from __future__ import annotations

import math
import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request


class SlidingWindowRateLimiter:
    """Small single-process limiter; use a shared store before multi-instance scaling."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def check(self, client: str, scope: str, limit: int, window_seconds: int = 60) -> None:
        now = time.monotonic()
        key = (client, scope)
        with self._lock:
            bucket = self._requests[key]
            cutoff = now - window_seconds
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                retry_after = max(1, math.ceil(window_seconds - (now - bucket[0])))
                raise HTTPException(
                    status_code=429,
                    detail={"code": "rate_limited", "message": "Too many requests; try again shortly."},
                    headers={"Retry-After": str(retry_after)},
                )
            bucket.append(now)


def enforce_rate_limit(request: Request, scope: str, limit: int) -> None:
    client_host = request.client.host if request.client else "unknown"
    request.app.state.rate_limiter.check(client_host, scope, limit)
