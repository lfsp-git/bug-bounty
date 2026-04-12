"""Unified runner interface over scanner orchestration.

Local execution (default):
    ProOrchestrator / MissionRunner run the full pipeline in-process.

Distributed execution (CELERY_ENABLED=true):
    dispatch_scan_async(target)  → enqueues to Celery queue, returns AsyncResult.
    collect_scan_results(items)  → waits and returns list of result dicts.
    The task contract (ok/errors/counts/metrics) is identical in both modes.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Tuple

from core.scanner import MissionRunner, ProOrchestrator
import core.scanner as _scanner


def set_record_tool_times(enabled: bool) -> None:
    _scanner._RECORD_TOOL_TIMES = enabled


def set_runtime_cache_enabled(enabled: bool) -> None:
    _scanner._DISABLE_RUNTIME_CACHE = not enabled


# ── Celery helpers ─────────────────────────────────────────────────────────────

def dispatch_scan_async(target: Dict[str, Any]) -> Any:
    """Enqueue a scan task on the Celery queue.

    Returns a Celery AsyncResult. Call .get(timeout=N) to block for the result.
    Requires CELERY_ENABLED=true and a running Redis broker.

    Raises:
        ImportError: if celery is not installed.
        celery.exceptions.OperationalError: if broker is unreachable.
    """
    from core.celery_app import scan_target_task
    return scan_target_task.delay(target)


def collect_scan_results(
    async_items: List[Tuple[Dict[str, Any], Any]],
    timeout: int = 7200,
) -> List[Dict[str, Any]]:
    """Block until all async scan tasks complete and return their result dicts.

    Args:
        async_items: List of (target_dict, AsyncResult) tuples.
        timeout:     Per-task timeout in seconds (default 2 h).

    Returns:
        List of result dicts in the same order as async_items.
        Failed / timed-out tasks produce a minimal error dict:
            {ok: False, handle: str, errors: [str], subdomains: 0, ...}
    """
    results: List[Dict[str, Any]] = []
    for target, async_result in async_items:
        handle = target.get("handle", "unknown")
        try:
            result = async_result.get(timeout=timeout, propagate=False)
            if isinstance(result, Exception):
                results.append(_error_result(handle, str(result)))
            else:
                results.append(result or _error_result(handle, "empty result"))
        except Exception as exc:
            results.append(_error_result(handle, str(exc)))
    return results


def _error_result(handle: str, reason: str) -> Dict[str, Any]:
    return {
        "ok": False,
        "handle": handle,
        "errors": [reason],
        "subdomains": 0,
        "alive": 0,
        "open_ports": 0,
        "endpoints": 0,
        "hist_urls": 0,
        "js_secrets": 0,
        "vulns": 0,
        "metrics": {},
    }
