"""
Rate limiting via slowapi.

Production placement (IEEE paper discussion):
  - Global default: applied in main.py via SlowAPIMiddleware (60 req/min/IP).
  - Scan endpoints: stricter limit (10 req/min/user) on POST /scan/package and
    POST /scan/rescan-check — these trigger PyPI downloads + ML inference.
  - Auth endpoints: moderate limit (20 req/min/IP) on POST /auth/signup and
    POST /auth/login to mitigate token-replay / enumeration attempts.
  - PDF report: 5 req/min/user on GET /scan/report/{scan_id}/pdf (CPU-heavy).

Example per-route decorator (in endpoints/scans.py):
    from app.core.rate_limit import limiter
    @router.post("/scan/package")
    @limiter.limit(settings.rate_limit_scan)
    async def scan_package(...): ...
"""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
