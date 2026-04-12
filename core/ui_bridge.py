"""Redis PubSub bridge for Hunt3r UI events (v1.1-OVERLORD).

When Celery workers execute scan tasks, all ui_worker_* and ui_log calls happen
in the worker process — isolated from the watchdog that owns the Rich Live
render loop.  This module closes that gap:

  Worker process  → UIEventPublisher.publish() → Redis channel hunt3r:ui_events
  Watchdog process← UIEventSubscriber._loop()  ← Redis channel hunt3r:ui_events
                                                   ↓
                                          local ui_worker_* / ui_log calls
                                                   ↓
                                          _workers dict + activity log updated
                                                   ↓
                                          Rich Live re-renders

Channel : hunt3r:ui_events   (PubSub — real-time)
TTL list: hunt3r:ui_events:ttl (Redis LIST — crash-safe replay with max-age)
Encoding: JSON (UTF-8)

TTL strategy
------------
Each published event is also RPUSH-ed to a Redis list with EXPIRE=TTL_SECONDS.
The subscriber drains this list on start() so a watchdog restart can replay
recent events (e.g. a tool that finished while watchdog was restarting).
Events older than TTL_SECONDS are discarded automatically when the key expires.
Individual event age is stamped in the "ts" field and checked on replay.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any, Optional

CHANNEL = "hunt3r:ui_events"
TTL_LIST = "hunt3r:ui_events:ttl"
# Events in the TTL list expire after this many seconds (env-tunable).
import os as _os
TTL_SECONDS: int = int(_os.getenv("HUNT3R_UI_TTL", "300"))  # 5 min default

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────

def _make_redis(url: str):
    """Create a Redis client. Lazy import so non-Celery paths pay no cost."""
    import redis  # type: ignore[import]
    return redis.from_url(
        url,
        decode_responses=True,
        socket_connect_timeout=3,
        socket_timeout=3,
    )


# ─────────────────────────────────────────────────────────────
# Publisher — used by Celery workers
# ─────────────────────────────────────────────────────────────

class UIEventPublisher:
    """Publish UI state events from a Celery worker to the shared Redis channel.

    Each event is also appended to a TTL list (hunt3r:ui_events:ttl) so a
    watchdog restart can replay the last TTL_SECONDS of events without losing
    context from a crashed worker.

    Usage (inside scan_target_task, before start_mission):
        pub = UIEventPublisher(REDIS_URL)
        set_ui_bridge_publisher(pub)
        result = orch.start_mission(target)
        set_ui_bridge_publisher(None)
    """

    def __init__(self, redis_url: str) -> None:
        self._ok = False
        try:
            self._r = _make_redis(redis_url)
            self._r.ping()
            self._ok = True
            log.debug("UIEventPublisher: connected to %s", redis_url)
        except Exception as exc:
            log.warning(
                "UIEventPublisher: Redis unreachable — UI events disabled. %s", exc
            )

    def publish(self, event_type: str, **kwargs) -> None:
        if not self._ok:
            return
        try:
            payload = json.dumps(
                {"type": event_type, "ts": time.time(), **kwargs}, default=str
            )
            pipe = self._r.pipeline(transaction=False)
            pipe.publish(CHANNEL, payload)
            # Append to TTL list so a restarted watchdog can replay recent state.
            pipe.rpush(TTL_LIST, payload)
            pipe.expire(TTL_LIST, TTL_SECONDS)
            pipe.execute()
        except Exception as exc:
            log.debug("UIEventPublisher.publish failed: %s", exc)


# ─────────────────────────────────────────────────────────────
# Subscriber — used by watchdog
# ─────────────────────────────────────────────────────────────

class UIEventSubscriber:
    """Subscribe to UI events and replay them as local ui_worker_*/ui_log calls.

    Runs a daemon thread inside the watchdog process.

    On start(), drains the TTL list first (replay recent state from possibly
    crashed workers), then listens on the PubSub channel for live events.

    Usage (watchdog, around _dispatch_targets_celery):
        sub = UIEventSubscriber(REDIS_URL)
        sub.start()
        cycle_metrics = _dispatch_targets_celery(wildcards)
        sub.stop()
    """

    def __init__(self, redis_url: str) -> None:
        self._url = redis_url
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self) -> bool:
        """Start subscriber thread. Returns True if Redis is reachable."""
        try:
            r = _make_redis(self._url)
            r.ping()
            self._drain_ttl_list(r)
            ps = r.pubsub(ignore_subscribe_messages=True)
            ps.subscribe(CHANNEL)
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._loop,
                args=(ps,),
                daemon=True,
                name="ui-event-subscriber",
            )
            self._thread.start()
            log.info("UIEventSubscriber: listening on channel '%s'", CHANNEL)
            return True
        except Exception as exc:
            log.warning(
                "UIEventSubscriber: Redis unreachable — Live UI disabled for workers. %s",
                exc,
            )
            return False

    def stop(self) -> None:
        """Signal the subscriber thread to exit and wait for it."""
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._thread = None

    # ------------------------------------------------------------------
    # TTL list drain — replay events from before this subscriber started
    # ------------------------------------------------------------------

    def _drain_ttl_list(self, r) -> None:
        """Replay all events still in the TTL list that are within max age."""
        try:
            raw_events = r.lrange(TTL_LIST, 0, -1)
            cutoff = time.time() - TTL_SECONDS
            replayed = 0
            for raw in raw_events:
                try:
                    event = json.loads(raw)
                    # Discard events older than TTL_SECONDS.
                    if float(event.get("ts", 0)) < cutoff:
                        continue
                    _dispatch_event(event)
                    replayed += 1
                except Exception as exc:
                    log.debug("UIEventSubscriber TTL replay parse error: %s", exc)
            if replayed:
                log.info(
                    "UIEventSubscriber: replayed %d events from TTL list", replayed
                )
        except Exception as exc:
            log.debug("UIEventSubscriber TTL drain failed: %s", exc)

    # ------------------------------------------------------------------
    # Live PubSub loop
    # ------------------------------------------------------------------

    def _loop(self, ps) -> None:
        while not self._stop.is_set():
            try:
                msg = ps.get_message(timeout=0.5)
                if msg and msg.get("type") == "message":
                    try:
                        event = json.loads(msg["data"])
                        _dispatch_event(event)
                    except (json.JSONDecodeError, Exception) as exc:
                        log.debug("UIEventSubscriber parse error: %s", exc)
            except Exception as exc:
                log.debug("UIEventSubscriber loop error: %s", exc)
        try:
            ps.close()
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────
# Event dispatcher — called by subscriber in watchdog process
# ─────────────────────────────────────────────────────────────

def _dispatch_event(event: dict) -> None:
    """Translate an incoming PubSub event dict into a local ui_worker_*/ui_log call."""
    # Lazy import to avoid circular dependency (ui.py imports nothing from here).
    from core.ui import (
        ui_log,
        ui_worker_register,
        ui_worker_done,
        ui_worker_tool_started,
        ui_worker_tool_finished,
        ui_worker_tool_cached,
        ui_worker_tool_error,
        ui_worker_nuclei_update,
    )

    etype = event.get("type", "")
    wid = event.get("worker_id", "w0")

    if etype == "ui_log":
        ui_log(event.get("module", "WORKER"), event.get("message", ""))
    elif etype == "worker_register":
        ui_worker_register(
            wid,
            event.get("target", ""),
            event.get("idx", 0),
            event.get("total", 0),
        )
    elif etype == "worker_done":
        ui_worker_done(wid, event.get("results", {}))
    elif etype == "tool_started":
        ui_worker_tool_started(
            wid,
            event.get("tool", ""),
            event.get("input_count", 0),
            event.get("eta", 0.0),
        )
    elif etype == "tool_finished":
        ui_worker_tool_finished(
            wid,
            event.get("tool", ""),
            event.get("count", 0),
            event.get("elapsed", 0.0),
        )
    elif etype == "tool_cached":
        ui_worker_tool_cached(wid, event.get("tool", ""), event.get("count", 0))
    elif etype == "tool_error":
        ui_worker_tool_error(wid, event.get("tool", ""), event.get("error", ""))
    elif etype == "nuclei_update":
        ui_worker_nuclei_update(
            wid,
            event.get("done", 0),
            event.get("total", 0),
            event.get("rps", 0.0),
            event.get("matched", 0),
        )
    else:
        log.debug("UIEventSubscriber: unknown event type '%s'", etype)

