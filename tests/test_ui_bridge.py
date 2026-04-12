"""Unit tests for core.ui_bridge._dispatch_event().

Tests verify that each event type is correctly routed to the corresponding
ui_worker_* / ui_log function without requiring a live Redis connection.
"""

import time
import unittest
from unittest.mock import MagicMock, patch


# _dispatch_event does `from core.ui import ...` lazily at call time,
# so we patch the names at their definition site: core.ui.<name>.
_UI = "core.ui"


class TestDispatchEvent(unittest.TestCase):
    """Patch all ui_worker_* and ui_log, then assert correct calls per event."""

    def setUp(self):
        self.patches = {
            "ui_log":                  patch(f"{_UI}.ui_log"),
            "ui_worker_register":      patch(f"{_UI}.ui_worker_register"),
            "ui_worker_done":          patch(f"{_UI}.ui_worker_done"),
            "ui_worker_tool_started":  patch(f"{_UI}.ui_worker_tool_started"),
            "ui_worker_tool_finished": patch(f"{_UI}.ui_worker_tool_finished"),
            "ui_worker_tool_cached":   patch(f"{_UI}.ui_worker_tool_cached"),
            "ui_worker_tool_error":    patch(f"{_UI}.ui_worker_tool_error"),
            "ui_worker_nuclei_update": patch(f"{_UI}.ui_worker_nuclei_update"),
        }
        self.mocks = {k: p.start() for k, p in self.patches.items()}

    def tearDown(self):
        for p in self.patches.values():
            p.stop()

    def _dispatch(self, event: dict):
        from core.ui_bridge import _dispatch_event
        _dispatch_event(event)

    def _assert_only(self, mock_name: str, *args):
        """Assert mock_name was called with args and all others were not called."""
        self.mocks[mock_name].assert_called_once_with(*args)
        for name, m in self.mocks.items():
            if name != mock_name:
                m.assert_not_called()

    # ------------------------------------------------------------------
    # ui_log event
    # ------------------------------------------------------------------

    def test_ui_log_dispatches_correctly(self):
        self._dispatch({"type": "ui_log", "module": "NUCLEI", "message": "found 3 vulns"})
        self._assert_only("ui_log", "NUCLEI", "found 3 vulns")

    def test_ui_log_uses_defaults_when_fields_missing(self):
        self._dispatch({"type": "ui_log"})
        self._assert_only("ui_log", "WORKER", "")

    # ------------------------------------------------------------------
    # worker_register
    # ------------------------------------------------------------------

    def test_worker_register(self):
        self._dispatch({"type": "worker_register", "worker_id": "W2",
                        "target": "example.com", "idx": 3, "total": 10})
        self._assert_only("ui_worker_register", "W2", "example.com", 3, 10)

    def test_worker_register_defaults(self):
        self._dispatch({"type": "worker_register"})
        self._assert_only("ui_worker_register", "w0", "", 0, 0)

    # ------------------------------------------------------------------
    # worker_done
    # ------------------------------------------------------------------

    def test_worker_done(self):
        results = {"subdomains": 5, "alive": 3, "vulns": 1}
        self._dispatch({"type": "worker_done", "worker_id": "W1", "results": results})
        self._assert_only("ui_worker_done", "W1", results)

    def test_worker_done_empty_results(self):
        self._dispatch({"type": "worker_done", "worker_id": "W1"})
        self._assert_only("ui_worker_done", "W1", {})

    # ------------------------------------------------------------------
    # tool_started
    # ------------------------------------------------------------------

    def test_tool_started(self):
        self._dispatch({"type": "tool_started", "worker_id": "W1", "tool": "Nuclei",
                        "input_count": 42, "eta": 120.5})
        self._assert_only("ui_worker_tool_started", "W1", "Nuclei", 42, 120.5)

    def test_tool_started_defaults(self):
        self._dispatch({"type": "tool_started", "worker_id": "W1"})
        self._assert_only("ui_worker_tool_started", "W1", "", 0, 0.0)

    # ------------------------------------------------------------------
    # tool_finished
    # ------------------------------------------------------------------

    def test_tool_finished(self):
        self._dispatch({"type": "tool_finished", "worker_id": "W3", "tool": "HTTPX",
                        "count": 99, "elapsed": 45.2})
        self._assert_only("ui_worker_tool_finished", "W3", "HTTPX", 99, 45.2)

    # ------------------------------------------------------------------
    # tool_cached
    # ------------------------------------------------------------------

    def test_tool_cached(self):
        self._dispatch({"type": "tool_cached", "worker_id": "W2",
                        "tool": "Subfinder", "count": 15})
        self._assert_only("ui_worker_tool_cached", "W2", "Subfinder", 15)

    # ------------------------------------------------------------------
    # tool_error
    # ------------------------------------------------------------------

    def test_tool_error(self):
        self._dispatch({"type": "tool_error", "worker_id": "W1",
                        "tool": "Katana", "error": "timeout after 15s"})
        self._assert_only("ui_worker_tool_error", "W1", "Katana", "timeout after 15s")

    def test_tool_error_defaults(self):
        self._dispatch({"type": "tool_error", "worker_id": "W1"})
        self._assert_only("ui_worker_tool_error", "W1", "", "")

    # ------------------------------------------------------------------
    # nuclei_update
    # ------------------------------------------------------------------

    def test_nuclei_update(self):
        self._dispatch({"type": "nuclei_update", "worker_id": "W2",
                        "done": 300, "total": 1000, "rps": 12.5, "matched": 7})
        self._assert_only("ui_worker_nuclei_update", "W2", 300, 1000, 12.5, 7)

    def test_nuclei_update_defaults(self):
        self._dispatch({"type": "nuclei_update", "worker_id": "W2"})
        self._assert_only("ui_worker_nuclei_update", "W2", 0, 0, 0.0, 0)

    # ------------------------------------------------------------------
    # unknown event type — must not raise and must not call anything
    # ------------------------------------------------------------------

    def test_unknown_event_type_is_silent(self):
        self._dispatch({"type": "future_unknown_event", "worker_id": "W1"})
        for m in self.mocks.values():
            m.assert_not_called()

    # ------------------------------------------------------------------
    # TTL list: _drain_ttl_list skips stale events
    # ------------------------------------------------------------------

    def test_drain_ttl_list_skips_old_events(self):
        """Events older than TTL_SECONDS must be discarded; fresh ones replayed."""
        import json
        from core.ui_bridge import UIEventSubscriber, TTL_SECONDS

        old_ts   = time.time() - TTL_SECONDS - 60  # 1 min past expiry
        fresh_ts = time.time() - 10                 # 10 s ago (within TTL)

        old_raw   = json.dumps({"type": "ui_log", "module": "OLD",
                                "message": "old-msg",   "ts": old_ts})
        fresh_raw = json.dumps({"type": "ui_log", "module": "NEW",
                                "message": "fresh-msg", "ts": fresh_ts})

        mock_redis = MagicMock()
        mock_redis.lrange.return_value = [old_raw, fresh_raw]

        sub = UIEventSubscriber.__new__(UIEventSubscriber)
        sub._drain_ttl_list(mock_redis)

        # Only the fresh event should reach ui_log.
        self.mocks["ui_log"].assert_called_once_with("NEW", "fresh-msg")

    # ------------------------------------------------------------------
    # UIEventPublisher: publish adds ts field and uses pipeline
    # ------------------------------------------------------------------

    def test_publisher_adds_ts_and_uses_pipeline(self):
        import json
        from core.ui_bridge import UIEventPublisher

        mock_redis = MagicMock()
        mock_pipe  = MagicMock()
        mock_redis.pipeline.return_value = mock_pipe

        pub = UIEventPublisher.__new__(UIEventPublisher)
        pub._ok = True
        pub._r  = mock_redis

        before = time.time()
        pub.publish("tool_started", worker_id="W1", tool="Nuclei")
        after  = time.time()

        mock_redis.pipeline.assert_called_once_with(transaction=False)

        args, _ = mock_pipe.publish.call_args
        payload = json.loads(args[1])

        self.assertEqual(payload["type"],      "tool_started")
        self.assertEqual(payload["worker_id"], "W1")
        self.assertEqual(payload["tool"],      "Nuclei")
        self.assertIn("ts", payload)
        self.assertGreaterEqual(payload["ts"], before)
        self.assertLessEqual(payload["ts"],    after)

        mock_pipe.rpush.assert_called_once()
        mock_pipe.expire.assert_called_once()
        mock_pipe.execute.assert_called_once()

    # ------------------------------------------------------------------
    # UIEventPublisher: publish is no-op when Redis unreachable
    # ------------------------------------------------------------------

    def test_publisher_noop_when_redis_unreachable(self):
        from core.ui_bridge import UIEventPublisher

        pub = UIEventPublisher.__new__(UIEventPublisher)
        pub._ok = False  # simulates failed __init__

        pub.publish("tool_started", worker_id="W1", tool="Nuclei")  # must not raise


if __name__ == "__main__":
    unittest.main()

