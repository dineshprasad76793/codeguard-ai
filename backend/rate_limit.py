"""Per-endpoint rate limiting (slowapi) with a Redis backend in production.

Limits (per client IP):
- /api/analyze     6/minute   (most expensive: every call spends AI credits)
- /api/scan-url    8/minute   (SSRF-adjacent: performs outbound fetches)
- /api/scan-github 8/minute   (outbound GitHub API + AI credits)
- POST /api/share  10/minute  (writes to server-side storage)
- GET  /api/share  30/minute  (cheap reads, still brute-force-relevant)

Client identity uses security.client_ip(): Cloudflare's CF-Connecting-IP
when present, otherwise the RIGHTMOST X-Forwarded-For entry. The leftmost
entries are client-controlled — keying on them lets an attacker rotate a
fake XFF header and get a fresh bucket on every request.

Set REDIS_URL (e.g. Upstash/Render Redis) so limits are shared across
restarts and instances. Without it, slowapi falls back to in-memory
storage (single instance, resets on deploy).
"""
import os

from slowapi import Limiter
from slowapi.util import get_remote_address

from security import client_ip

REDIS_URL = os.getenv("REDIS_URL", "").strip() or None

limiter = Limiter(
    key_func=client_ip,
    storage_uri=REDIS_URL,
    headers_enabled=False,
)
