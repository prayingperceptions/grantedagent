"""A small in-process rate limiter.

Deliberately not Redis-backed. A single-process token bucket is enough to blunt
credential stuffing and signup abuse, and it adds no infrastructure. The
limitation is honest and worth stating: with N application processes, the
effective limit is N times the configured rate, because each process keeps its
own counters. Moving to a shared store is the correct fix when the deployment
runs more than one worker.

The clock is injectable so tests advance time rather than sleep.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass
class _Bucket:
    tokens: float
    updated_at: float


@dataclass
class RateLimiter:
    """Token-bucket limiter keyed on an arbitrary string.

    ``capacity`` is the burst size; ``refill_per_second`` is the sustained
    rate. Keys are created on demand and pruned opportunistically, so a flood
    of distinct keys cannot grow the dict without bound.
    """

    capacity: int = 10
    refill_per_second: float = 0.2
    clock: Callable[[], float] = time.monotonic
    _buckets: dict[str, _Bucket] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _prune(self, now: float) -> None:
        """Drop buckets that have been idle long enough to be full again."""
        if len(self._buckets) < 4096:
            return
        idle_after = self.capacity / max(self.refill_per_second, 1e-9)
        stale = [
            key
            for key, bucket in self._buckets.items()
            if (now - bucket.updated_at) > idle_after
        ]
        for key in stale:
            self._buckets.pop(key, None)

    def allow(self, key: str, *, cost: float = 1.0) -> bool:
        """Consume ``cost`` tokens for ``key``. False when exhausted."""
        now = self.clock()
        with self._lock:
            self._prune(now)
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(tokens=float(self.capacity), updated_at=now)
                self._buckets[key] = bucket

            elapsed = max(0.0, now - bucket.updated_at)
            bucket.tokens = min(
                float(self.capacity), bucket.tokens + elapsed * self.refill_per_second
            )
            bucket.updated_at = now

            if bucket.tokens < cost:
                return False
            bucket.tokens -= cost
            return True

    def retry_after(self, key: str, *, cost: float = 1.0) -> float:
        """Seconds until ``cost`` tokens are available for ``key``."""
        now = self.clock()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                return 0.0
            elapsed = max(0.0, now - bucket.updated_at)
            available = min(
                float(self.capacity), bucket.tokens + elapsed * self.refill_per_second
            )
            deficit = cost - available
            if deficit <= 0:
                return 0.0
            return deficit / max(self.refill_per_second, 1e-9)

    def reset(self, key: str | None = None) -> None:
        """Clear one key, or every key when called without one. For tests."""
        with self._lock:
            if key is None:
                self._buckets.clear()
            else:
                self._buckets.pop(key, None)


def reset_all() -> None:
    """Clear every limiter's buckets.

    Only for tests: the limiters are module-level singletons, so counters would
    otherwise leak from one test case into the next.
    """
    for limiter in (LOGIN_IP, LOGIN_EMAIL, SIGNUP_IP, EMAIL_SEND_IP):
        limiter.reset()


# Named limiters, split by purpose so a burst of logins cannot lock a user out
# of password reset, and so tuning one does not affect the others.

# Login: generous enough for a human who mistypes, tight enough that guessing
# is hopeless. Keyed on IP and separately on the account, so neither a
# single-IP spray nor a distributed attack on one account gets through.
LOGIN_IP = RateLimiter(capacity=20, refill_per_second=20 / 300)
LOGIN_EMAIL = RateLimiter(capacity=8, refill_per_second=8 / 600)

# Signup and mail-sending endpoints cost money and can be used to flood a third
# party's inbox, so they are tighter.
SIGNUP_IP = RateLimiter(capacity=5, refill_per_second=5 / 3600)
EMAIL_SEND_IP = RateLimiter(capacity=5, refill_per_second=5 / 1800)

# Authenticated mutations.
API_WRITE = RateLimiter(capacity=120, refill_per_second=2.0)

# Unauthenticated endpoints in general.
GENERAL_IP = RateLimiter(capacity=240, refill_per_second=4.0)


def client_ip(request) -> str:
    """Best-effort client IP.

    ``X-Forwarded-For`` is honoured only because a reverse proxy is the
    expected deployment, and its left-most entry is what the proxy saw. Behind
    no proxy the header is client-controlled, so it is used for rate-limit
    keying only - never for an authorisation decision.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        first = forwarded.split(",")[0].strip()
        if first:
            return first[:64]
    real = request.headers.get("x-real-ip")
    if real:
        return real.strip()[:64]
    client = getattr(request, "client", None)
    return (client.host if client else "") or "unknown"


__all__ = [
    "API_WRITE",
    "EMAIL_SEND_IP",
    "GENERAL_IP",
    "LOGIN_EMAIL",
    "LOGIN_IP",
    "SIGNUP_IP",
    "RateLimiter",
    "client_ip",
]