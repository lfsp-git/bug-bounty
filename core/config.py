"""
Hunt3r — Unified configuration, constants, rate limiting, and deduplication.
Single source of truth for all runtime settings.
"""
from __future__ import annotations

import os
import re
import time
import logging
from collections import defaultdict
from typing import Iterable, List, Set

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scan constants
# ---------------------------------------------------------------------------
MAX_SUBS_PER_TARGET: int = 2000
REQUESTS_PER_SECOND: float = 1.0        # per-target inter-tool throttle


def _detect_ram_gb() -> int:
    """Best-effort RAM detection from /proc/meminfo (Linux)."""
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    kb = int(line.split()[1])
                    return max(1, kb // (1024 * 1024))
    except (OSError, ValueError, IndexError):
        pass
    return 4


CPU_CORES: int = max(1, os.cpu_count() or 1)
RAM_GB: int = _detect_ram_gb()

# Hardware-aware defaults (optimized for VPS reliability).
# 4 vCPU / 8 GB profile → RATE_LIMIT=80, NUCLEI_RATE_LIMIT=120, NUCLEI_CONCURRENCY=25
if CPU_CORES <= 2 or RAM_GB <= 4:
    RATE_LIMIT: int = 50
    NUCLEI_RATE_LIMIT: int = 80
    NUCLEI_CONCURRENCY: int = 15
elif CPU_CORES <= 4 or RAM_GB <= 8:
    RATE_LIMIT = 80
    NUCLEI_RATE_LIMIT = 120
    NUCLEI_CONCURRENCY = 25
else:
    RATE_LIMIT = 100
    NUCLEI_RATE_LIMIT = 150
    NUCLEI_CONCURRENCY = 35

# ---------------------------------------------------------------------------
# Watchdog
# ---------------------------------------------------------------------------
WATCHDOG_SLEEP_MIN: int = 14400   # 4 h
WATCHDOG_SLEEP_MAX: int = 21600   # 6 h
WATCHDOG_MAX_TARGETS: int = 50
WATCHDOG_CACHE_TTL: int = 43200   # 12 h
WATCHDOG_HOT_COUNT: int = 15
WATCHDOG_WORKERS: int = max(2, min(3, CPU_CORES - 1 if CPU_CORES > 2 else 2))

# ---------------------------------------------------------------------------
# AI
# ---------------------------------------------------------------------------
AI_MAX_TOKENS_SHORT: int = 500
AI_MAX_TOKENS_LONG: int = 1000
AI_TIMEOUT: int = 60
AI_SCORE_THRESHOLD: int = 80      # Minimum score to trigger AI validation

# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------
NOTIFY_HIGH_SEVERITIES: List[str] = ["critical", "high"]
DISCORD_BATCH_SIZE: int = 15

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASELINES_DIR: str = "recon/baselines"
REPORTS_DIR: str = "reports"
LOGS_DIR: str = "logs"
CACHE_DIR: str = "recon/cache"

# ---------------------------------------------------------------------------
# Auto-update
# ---------------------------------------------------------------------------
AUTO_UPDATE_ON_START: bool = True

# ---------------------------------------------------------------------------
# Tool timeouts (seconds)
# ---------------------------------------------------------------------------
TOOL_TIMEOUTS: dict = {
    "subfinder": 120,
    "dnsx": 120,
    "uncover": 90,
    "httpx": 180,
    "katana": 300,
    "js_hunter": 60,
    "nuclei": 3600,
    "api_request": 15,
    "ai_inference_short": 30,
    "ai_inference_long": 60,
    "openrouter_request": 60,
    "webhook_post": 10,
    "http_get": 15,
    "tool_update": 120,
}


def get_tool_timeout(tool_name: str, default: int = 60) -> int:
    """Return timeout for a tool by name (case-insensitive)."""
    return TOOL_TIMEOUTS.get(tool_name.lower(), default)


# ---------------------------------------------------------------------------
# Per-target rate limiter
# ---------------------------------------------------------------------------
class PerTargetRateLimiter:
    """Throttles inter-tool calls per target to avoid flooding."""

    def __init__(self, requests_per_second: float = 1.0) -> None:
        self.min_interval: float = 1.0 / max(requests_per_second, 0.001)
        self._last: defaultdict = defaultdict(float)

    def wait_and_record(self, target: str) -> None:
        """Sleep if needed to honour rate limit, then record timestamp."""
        elapsed = time.time() - self._last[target]
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last[target] = time.time()


_global_limiter: PerTargetRateLimiter | None = None


def get_rate_limiter(rps: float = 1.0) -> PerTargetRateLimiter:
    """Return (or create) the global rate limiter singleton."""
    global _global_limiter
    if _global_limiter is None:
        _global_limiter = PerTargetRateLimiter(rps)
    return _global_limiter


# ---------------------------------------------------------------------------
# Deduplication utilities
# ---------------------------------------------------------------------------
def to_set(items: Iterable[str]) -> Set[str]:
    """Convert iterable to lower-cased, stripped set (deduplication)."""
    return {item.strip().lower() for item in items if item and item.strip()}


def deduplicate(items: Iterable[str]) -> List[str]:
    """Return ordered, deduplicated list (case-insensitive comparison)."""
    seen: Set[str] = set()
    result: List[str] = []
    for item in items:
        if item:
            key = item.strip().lower()
            if key not in seen:
                seen.add(key)
                result.append(item.strip())
    return result


def merge_lists(*lists: List[str]) -> List[str]:
    """Merge multiple lists and deduplicate."""
    combined: List[str] = []
    for lst in lists:
        if lst:
            combined.extend(lst)
    return deduplicate(combined)


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
_DOMAIN_RE = re.compile(
    r'^(\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$',
    re.IGNORECASE,
)
_URL_RE = re.compile(
    r'^https?://(?:[a-z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+)$',
    re.IGNORECASE,
)


def is_valid_domain(domain: str) -> bool:
    """Return True if domain/wildcard is syntactically valid."""
    if not domain or len(domain) > 253:
        return False
    return bool(_DOMAIN_RE.match(domain.strip()))


def is_valid_url(url: str) -> bool:
    """Return True if URL is syntactically valid."""
    if not url or len(url) > 2048:
        return False
    return bool(_URL_RE.match(url.strip()))


def sanitize_domain(domain: str) -> str:
    """Strip whitespace and lowercase a domain string."""
    return domain.strip().lower()


def validate_and_extract_domain(input_str: str) -> str:
    """Extract domain from URL, or validate bare domain. Returns clean domain or ''."""
    if not input_str:
        return ""
    s = input_str.strip().lower()
    if s.startswith(("http://", "https://")):
        if not is_valid_url(s):
            return ""
        try:
            from urllib.parse import urlparse
            domain = urlparse(s).hostname or ""
            return domain if is_valid_domain(domain) else ""
        except (ValueError, AttributeError):
            return ""
    return s if is_valid_domain(s) else ""

# FASE 8: ML Filter Configuration
ML_FILTER_ENABLED = True                    # Enable ML-based FP filtering
ML_CONFIDENCE_THRESHOLD = 0.5               # Probability threshold for FP (0-1)
ML_MODEL_PATH = "/home/leonardofsp/bug-bounty/models/fp_filter_v1.pkl"
