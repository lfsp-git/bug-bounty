"""Hunt3r Celery application — distributed scan broker (v1.1-OVERLORD).

Broker  : Redis  (REDIS_URL env, default redis://localhost:6379/0)
Backend : Redis  (same URL — stores task results for 24 h)
Queue   : hunt3r.scan  (all scan tasks are routed here)

Task contract (scan_target_task):
  Input  : target dict  {handle, original_handle, domains, platform, score, ...}
  Output : result dict  {ok, errors, counts, subdomains, alive, vulns, metrics, ...}
           — identical to ProOrchestrator.start_mission() return value —
"""

from __future__ import annotations

import logging
import os
import sys

from celery import Celery
from celery.utils.log import get_task_logger

# Ensure project root is importable when workers are launched from any directory.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# Add Go / projectdiscovery binary paths so workers find tools.
_HOME = os.path.expanduser("~")
os.environ["PATH"] = (
    os.environ.get("PATH", "")
    + os.pathsep + os.path.join(_HOME, "go", "bin")
    + os.pathsep + "/usr/local/bin"
    + os.pathsep + "/usr/local/go/bin"
)

REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
TASK_QUEUE: str = "hunt3r.scan"
# Per-task wall-clock limits (seconds).
# Soft: triggers SoftTimeLimitExceeded → task can clean up.
# Hard: SIGKILL after this many seconds.
_TASK_SOFT_LIMIT: int = int(os.getenv("CELERY_TASK_SOFT_LIMIT", str(7200)))   # 2 h
_TASK_HARD_LIMIT: int = int(os.getenv("CELERY_TASK_HARD_LIMIT", str(7800)))   # 2 h 10 m

app = Celery("hunt3r", broker=REDIS_URL, backend=REDIS_URL)

app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    # Acknowledge only after completion — prevents losing tasks on worker crash.
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    # Scans are heavy: one active task per worker process at a time.
    worker_prefetch_multiplier=1,
    # Route all scan tasks to the dedicated queue.
    task_routes={"hunt3r.scan_target": {"queue": TASK_QUEUE}},
    # Results expire after 24 h (cycle data, not long-term storage).
    result_expires=86400,
    broker_connection_retry_on_startup=True,
    # Human-readable task IDs in logs.
    task_track_started=True,
)

logger = get_task_logger(__name__)


@app.task(
    name="hunt3r.scan_target",
    bind=True,
    max_retries=2,
    default_retry_delay=60,
    soft_time_limit=_TASK_SOFT_LIMIT,
    time_limit=_TASK_HARD_LIMIT,
)
def scan_target_task(self, target: dict) -> dict:
    """Execute the full Hunt3r recon + vulnerability pipeline for one target.

    Runs ProOrchestrator.start_mission(target) inside the Celery worker process.
    All file I/O goes to recon/baselines/<handle>/ — mount as a shared volume
    when scaling across multiple hosts.

    Args:
        target: Target dict with keys:
            handle          (str)  — filesystem-safe name, e.g. "example_com"
            original_handle (str)  — raw scope string, e.g. "*.example.com"
            domains         (list) — list of seed domains / IPs
            platform        (str)  — "h1", "it", or "unknown"
            score           (int)  — bounty priority score 0-100

    Returns:
        Result dict (same contract as ProOrchestrator.start_mission):
            ok         (bool)
            errors     (list[str])
            subdomains (int)
            alive      (int)
            vulns      (int)
            metrics    (dict)  — phase_duration_seconds: {recon, vulnerability}
    """
    handle = target.get("handle", "unknown")
    logger.info(
        "Task %s | Starting scan for %s (score=%s)",
        self.request.id[:8] if self.request.id else "?",
        handle,
        target.get("score", 0),
    )

    try:
        from core.intel import AIClient, IntelMiner
        from core.runner import ProOrchestrator

        orch = ProOrchestrator(IntelMiner(AIClient()))
        result = orch.start_mission(target)

        logger.info(
            "Task %s | Done %s — subs=%s alive=%s vulns=%s ok=%s",
            self.request.id[:8] if self.request.id else "?",
            handle,
            result.get("subdomains", 0),
            result.get("alive", 0),
            result.get("vulns", 0),
            result.get("ok", False),
        )
        return result

    except Exception as exc:
        logger.error("Task %s | Scan failed for %s: %s", self.request.id, handle, exc)
        try:
            raise self.retry(exc=exc)
        except self.MaxRetriesExceededError:
            return {
                "ok": False,
                "handle": handle,
                "errors": [str(exc)],
                "subdomains": 0,
                "alive": 0,
                "open_ports": 0,
                "endpoints": 0,
                "hist_urls": 0,
                "js_secrets": 0,
                "vulns": 0,
                "metrics": {},
            }
