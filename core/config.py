"""
Hunt3r — Unified configuration, constants, rate limiting, and deduplication.
Single source of truth for all runtime settings.
"""
from __future__ import annotations

import ipaddress
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
WATCHDOG_SLEEP_MIN: int = 3600    # 1 h
WATCHDOG_SLEEP_MAX: int = 7200    # 2 h
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
NOTIFY_DEDUP_TTL_SECONDS: int = 21600  # 6 h
NOTIFY_DEDUP_CACHE_FILE: str = "recon/cache/notifier_dedup.json"
NOTIFY_CROSS_PROGRAM_DEDUP: bool = os.getenv("NOTIFY_CROSS_PROGRAM_DEDUP", "false").strip().lower() in {"1", "true", "yes", "on"}

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


def is_ip_target(s: str) -> bool:
    """Return True if s is an IPv4, IPv6 address or CIDR block."""
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def expand_cidr(s: str) -> List[str]:
    """Expand CIDR to individual IP strings. Returns [s] if s is a single IP."""
    try:
        net = ipaddress.ip_network(s, strict=False)
        # Cap expansion at /16 (65536) to avoid memory issues
        if net.num_addresses > 65536:
            raise ValueError(f"CIDR {s} too large ({net.num_addresses} IPs), max /16")
        return [str(ip) for ip in net.hosts()] or [str(net.network_address)]
    except ValueError:
        return [s]


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

# ---------------------------------------------------------------------------
# Stealth / WAF Evasion  (v1.1-OVERLORD)
# ---------------------------------------------------------------------------
import random as _rng  # noqa: E402 — placed here to avoid circular import at top

# Real browser User-Agent pool for httpx/katana request rotation.
# Sourced from top browser market-share data (April 2025).
STEALTH_USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

# Gaussian jitter base delay (seconds) per tool.
# Spread is controlled by JITTER_SIGMA_RATIO — default 35% of base.
JITTER_BASE: dict = {
    "httpx":   1.5,
    "katana":  2.0,
    "nuclei":  1.0,
    "default": 1.0,
}

JITTER_SIGMA_RATIO: float = float(os.getenv("HUNT3R_JITTER_SIGMA", "0.35"))

# Master switch — set HUNT3R_STEALTH=false to disable all stealth delays.
STEALTH_ENABLED: bool = os.getenv("HUNT3R_STEALTH", "true").lower() in ("1", "true", "yes")


def jitter_sleep(tool: str = "default", base: float = 1.0, sigma_ratio: float | None = None) -> None:
    """Gaussian jitter sleep between tool launches to evade WAF rate-pattern detection.

    Draws delay from N(base, sigma) where sigma = base * JITTER_SIGMA_RATIO.
    Negative draws are clamped to 0.

    Args:
        tool:        Tool name key for per-tool base lookup (e.g. "httpx", "katana").
        base:        Fallback base delay when tool key is not in JITTER_BASE.
        sigma_ratio: Override JITTER_SIGMA_RATIO for this call.
    """
    if not STEALTH_ENABLED:
        return
    _base = JITTER_BASE.get(tool.lower(), base)
    _sigma = _base * (sigma_ratio if sigma_ratio is not None else JITTER_SIGMA_RATIO)
    delay = max(0.0, _rng.gauss(_base, _sigma))
    if delay > 0.05:
        time.sleep(delay)


def get_random_ua() -> str:
    """Return a random real browser User-Agent from the stealth pool."""
    return _rng.choice(STEALTH_USER_AGENTS)


def get_random_proxy() -> str | None:
    """Return a random proxy from HUNT3R_PROXIES env (comma-separated list), or None.

    Expected format: ``http://host:port`` or ``socks5://host:port``.
    Example: ``HUNT3R_PROXIES=http://127.0.0.1:8080,socks5://10.0.0.1:1080``
    """
    raw = os.getenv("HUNT3R_PROXIES", "").strip()
    if not raw:
        return None
    pool = [p.strip() for p in raw.split(",") if p.strip()]
    return _rng.choice(pool) if pool else None
