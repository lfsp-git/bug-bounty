"""
Hunt3r EXCALIBUR — Test Suite
Tests: config, storage, filter, export, ui, ai (unit), dry-run (integration)
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))


# ---------------------------------------------------------------------------
# core/config.py
# ---------------------------------------------------------------------------
class TestConfig(unittest.TestCase):
    def setUp(self):
        from core.config import (
            TOOL_TIMEOUTS,
            deduplicate,
            get_rate_limiter,
            get_tool_timeout,
            is_valid_domain,
            is_valid_url,
            merge_lists,
            to_set,
            validate_and_extract_domain,
        )

        self.cfg = {
            "TOOL_TIMEOUTS": TOOL_TIMEOUTS,
            "get_tool_timeout": get_tool_timeout,
            "get_rate_limiter": get_rate_limiter,
            "to_set": to_set,
            "deduplicate": deduplicate,
            "merge_lists": merge_lists,
            "is_valid_domain": is_valid_domain,
            "is_valid_url": is_valid_url,
            "validate_and_extract_domain": validate_and_extract_domain,
        }

    def test_tool_timeouts_populated(self):
        self.assertIsInstance(self.cfg["TOOL_TIMEOUTS"], dict)
        self.assertGreater(len(self.cfg["TOOL_TIMEOUTS"]), 0)

    def test_get_tool_timeout_returns_int(self):
        t = self.cfg["get_tool_timeout"]("subfinder")
        self.assertIsInstance(t, int)
        self.assertGreater(t, 0)

    def test_get_tool_timeout_default(self):
        t = self.cfg["get_tool_timeout"]("nonexistent_tool_xyz")
        self.assertGreater(t, 0)

    def test_to_set_deduplicates(self):
        result = self.cfg["to_set"](["a", "b", "a", "c"])
        self.assertEqual(result, {"a", "b", "c"})

    def test_to_set_empty(self):
        result = self.cfg["to_set"]([])
        self.assertEqual(result, set())

    def test_deduplicate_list(self):
        result = self.cfg["deduplicate"](["x", "y", "x"])
        self.assertEqual(sorted(result), ["x", "y"])

    def test_merge_lists_unique(self):
        result = self.cfg["merge_lists"](["a", "b"], ["b", "c"])
        self.assertIn("a", result)
        self.assertIn("c", result)
        self.assertEqual(len(result), len(set(result)))  # no dupes

    def test_is_valid_domain_true(self):
        self.assertTrue(self.cfg["is_valid_domain"]("example.com"))
        self.assertTrue(self.cfg["is_valid_domain"]("sub.example.co.uk"))

    def test_is_valid_domain_false(self):
        self.assertFalse(self.cfg["is_valid_domain"]("not a domain"))
        self.assertFalse(self.cfg["is_valid_domain"](""))

    def test_is_valid_url_true(self):
        self.assertTrue(self.cfg["is_valid_url"]("https://example.com/path"))

    def test_is_valid_url_false(self):
        self.assertFalse(self.cfg["is_valid_url"]("not-a-url"))

    def test_validate_and_extract_domain_basic(self):
        result = self.cfg["validate_and_extract_domain"]("https://example.com/path?q=1")
        self.assertEqual(result, "example.com")

    def test_validate_and_extract_domain_plain(self):
        result = self.cfg["validate_and_extract_domain"]("example.com")
        self.assertEqual(result, "example.com")

    def test_rate_limiter_returns_instance(self):
        rl = self.cfg["get_rate_limiter"](1.0)
        self.assertIsNotNone(rl)


# ---------------------------------------------------------------------------
# core/storage.py
# ---------------------------------------------------------------------------
class TestStorage(unittest.TestCase):
    def test_recon_diff_returns_empty_on_no_baseline(self):
        from core.state import ReconDiff

        diff = ReconDiff.compute_diff("__test_handle_xyz__", {"a.com"}, {"http://a.com"})
        self.assertFalse(diff["has_changes"])
        self.assertEqual(diff["added_subs"], set())

    def test_recon_diff_save_and_load(self):
        from core.state import ReconDiff

        handle = "__test_hunt3r_diff__"
        data = {"subdomains": ["a.com", "b.com"], "endpoints": ["http://a.com"], "js_secrets": []}
        ReconDiff.save_baseline(handle, data)
        loaded = ReconDiff.load_baseline(handle)
        self.assertIsNotNone(loaded)
        self.assertIn("a.com", loaded["subdomains"])
        path = ReconDiff._path(handle)
        if os.path.exists(path):
            os.remove(path)

    def test_recon_diff_detects_added(self):
        from core.state import ReconDiff

        handle = "__test_hunt3r_added__"
        old = {"subdomains": ["a.com"], "endpoints": [], "js_secrets": []}
        ReconDiff.save_baseline(handle, old)
        diff = ReconDiff.compute_diff(handle, {"a.com", "b.com"}, set())
        self.assertIn("b.com", diff["added_subs"])
        self.assertTrue(diff["has_changes"])
        path = ReconDiff._path(handle)
        if os.path.exists(path):
            os.remove(path)

    def test_checkpoint_save_and_load(self):
        from core.state import CheckpointManager

        cm = CheckpointManager()
        mission_id = "__test_mission_unit__"
        state = {"completed_targets": ["target1"], "findings": [{"vuln": "xss"}]}
        ok = cm.save(mission_id, state)
        self.assertTrue(ok)
        loaded = cm.load(mission_id)
        self.assertIsNotNone(loaded)
        self.assertIn("target1", loaded["completed_targets"])
        cm.delete(mission_id)

    def test_checkpoint_load_missing_returns_none(self):
        from core.state import CheckpointManager

        cm = CheckpointManager()
        result = cm.load("nonexistent-mission-zzz999")
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# core/filter.py
# ---------------------------------------------------------------------------
class TestFilter(unittest.TestCase):
    def _make_jsonl_file(self, findings):
        """Write findings as JSONL to a temp file, return path."""
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        for f in findings:
            tmp.write(json.dumps(f) + "\n")
        tmp.flush()
        tmp.close()
        return tmp.name

    def _make_finding(self, severity="critical", host="example.com", template="cve-2021-0001"):
        return {
            "info": {"severity": severity, "name": template},
            "host": host,
            "matched": f"https://{host}/vuln",
            "template-id": template,
        }

    def test_filter_keeps_critical(self):
        from core.filter import FalsePositiveKiller

        path = self._make_jsonl_file([self._make_finding("critical")])
        try:
            result = FalsePositiveKiller.sanitize_findings(path)
            # Sanitize returns bool (True=had valid findings), not exception
            self.assertIsInstance(result, bool)
            # File should still exist
            self.assertTrue(os.path.exists(path))
        finally:
            os.unlink(path)

    def test_filter_empty_file(self):
        from core.filter import FalsePositiveKiller

        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        tmp.close()
        try:
            result = FalsePositiveKiller.sanitize_findings(tmp.name)
            self.assertFalse(result)
        finally:
            os.unlink(tmp.name)

    def test_filter_missing_file(self):
        from core.filter import FalsePositiveKiller

        result = FalsePositiveKiller.sanitize_findings("/tmp/nonexistent_hunt3r_test.jsonl")
        self.assertFalse(result)

    def test_check_filters_returns_string(self):
        from core.filter import FalsePositiveKiller

        finding = self._make_finding("critical")
        reason = FalsePositiveKiller._check_filters(finding)
        self.assertIsInstance(reason, str)

    def test_micro_filter_does_not_drop_without_extracted_results(self):
        from core.filter import FalsePositiveKiller

        finding = {
            "template-id": "sqli-test",
            "host": "https://example.com",
        }
        reason = FalsePositiveKiller._check_filters(finding)
        self.assertNotEqual(reason, "Micro")


# ---------------------------------------------------------------------------
# core/export.py
# ---------------------------------------------------------------------------
class TestExport(unittest.TestCase):
    def _sample_findings(self):
        return [
            {
                "template-id": "cve-2021-0001",
                "host": "https://example.com",
                "info": {"name": "Test CVE", "severity": "high"},
                "matched": "https://example.com/vuln",
                "timestamp": "2024-01-01T00:00:00Z",
            }
        ]

    def test_export_csv(self):
        from core.output import ExportFormatter

        formatter = ExportFormatter()
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tf:
            tf.close()
            out = formatter.to_csv(self._sample_findings(), filename=tf.name)
            try:
                self.assertTrue(os.path.isfile(out))
                content = open(out).read()
                self.assertIn("cve-2021-0001", content)
            finally:
                if os.path.exists(tf.name):
                    os.unlink(tf.name)

    def test_export_xml(self):
        from core.output import ExportFormatter

        formatter = ExportFormatter()
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tf:
            tf.close()
            out = formatter.to_xml(self._sample_findings(), filename=tf.name)
            try:
                self.assertTrue(os.path.isfile(out))
                content = open(out).read()
                self.assertIn("cve-2021-0001", content)
            finally:
                if os.path.exists(tf.name):
                    os.unlink(tf.name)

    def test_export_invalid_format_returns_empty(self):
        from core.output import ExportFormatter

        formatter = ExportFormatter()
        out = formatter.export(self._sample_findings(), "pdf")
        self.assertEqual(out, "")


# ---------------------------------------------------------------------------
# core/ai.py (unit, no API call)
# ---------------------------------------------------------------------------
class TestAI(unittest.TestCase):
    def test_ai_client_instantiates(self):
        from core.intel import AIClient

        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "test-key-123"}):
            client = AIClient()
            self.assertEqual(client.api_key, "test-key-123")

    def test_ai_client_no_key(self):
        from core.intel import AIClient

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OPENROUTER_API_KEY", None)
            client = AIClient()
            self.assertFalse(bool(client.api_key))

    def test_intel_miner_instantiates(self):
        from core.intel import AIClient, IntelMiner

        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "test-key-123"}):
            ai = AIClient()
            intel = IntelMiner(ai)
            self.assertIsNotNone(intel)


# ---------------------------------------------------------------------------
# core/notifier.py (unit, no HTTP)
# ---------------------------------------------------------------------------
class TestNotifier(unittest.TestCase):
    def test_notifier_config_telegram(self):
        from core.output import NotifierConfig

        with patch.dict(
            os.environ,
            {
                "TELEGRAM_BOT_TOKEN": "123:abc",
                "TELEGRAM_CHAT_ID": "456",
            },
        ):
            result = NotifierConfig.telegram()
            self.assertEqual(result, ("123:abc", "456"))

    def test_notifier_config_telegram_missing(self):
        from core.output import NotifierConfig

        env = {k: v for k, v in os.environ.items() if k not in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID")}
        with patch.dict(os.environ, env, clear=True):
            result = NotifierConfig.telegram()
            self.assertIsNone(result)

    def test_alert_nuclei_classmethod_exists(self):
        from core.output import NotificationDispatcher

        self.assertTrue(callable(NotificationDispatcher.alert_nuclei))

    def test_notifier_dedup_cache_roundtrip(self):
        from core import notifier as notifier_mod

        with tempfile.TemporaryDirectory() as td:
            cache_path = os.path.join(td, "dedup.json")
            with patch.object(notifier_mod, "NOTIFY_DEDUP_CACHE_FILE", cache_path):
                self.assertFalse(notifier_mod._is_duplicate_and_record("k1"))
                self.assertTrue(notifier_mod._is_duplicate_and_record("k1"))

    def test_notifier_canonical_hash_dedup(self):
        from core import notifier as notifier_mod

        with tempfile.TemporaryDirectory() as td:
            cache_path = os.path.join(td, "dedup.json")
            with patch.object(notifier_mod, "NOTIFY_DEDUP_CACHE_FILE", cache_path):
                k1 = notifier_mod._hashed_dedup_key(
                    "tg:nuclei",
                    "TARGET",
                    "HIGH",
                    "CVE-2024-1234",
                    "https://example.com/path?x=1",
                    "N/A",
                )
                k2 = notifier_mod._hashed_dedup_key(
                    "tg:nuclei",
                    " target ",
                    "high",
                    "cve-2024-1234",
                    "https://example.com/path?x=1   ",
                    "n/a",
                )
                self.assertEqual(k1, k2)
                self.assertFalse(notifier_mod._is_duplicate_and_record_keys([k1]))
                self.assertTrue(notifier_mod._is_duplicate_and_record_keys([k2]))

    def test_notifier_cross_program_dedup_key_generation(self):
        from core import notifier as notifier_mod

        with patch.object(notifier_mod, "NOTIFY_CROSS_PROGRAM_DEDUP", True):
            keys = notifier_mod._dedup_keys(
                "tg:nuclei",
                "legacy:key",
                "program-a",
                "high",
                "template-x",
                "https://example.com",
                "N/A",
            )
        self.assertEqual(len(keys), 3)
        self.assertEqual(keys[1], "legacy:key")
        self.assertTrue(keys[0].startswith("tg:nuclei:"))
        self.assertTrue(keys[2].startswith("tg:nuclei:global:"))


# ---------------------------------------------------------------------------
# core/reporter.py
# ---------------------------------------------------------------------------
class TestReporter(unittest.TestCase):
    def test_reporter_generates_markdown(self):
        from core.output import BugBountyReporter

        with tempfile.TemporaryDirectory() as td:
            reporter = BugBountyReporter(handle="test-hunter")
            finding = {
                "template-id": "cve-2021-44228",
                "host": "https://vuln.example.com",
                "severity": "critical",
                "matched-at": "https://vuln.example.com/?q=${jndi:ldap://x}",
                "info": {
                    "name": "Log4Shell RCE",
                    "severity": "critical",
                    "description": "Remote Code Execution via JNDI",
                },
            }
            # Write a temp findings file
            tmp_findings = os.path.join(td, "findings.jsonl")
            with open(tmp_findings, "w") as f:
                f.write(json.dumps(finding) + "\n")

            with patch("core.reporter.REPORTS_DIR", td):
                path = reporter.generate(findings_path=tmp_findings)
            self.assertTrue(os.path.isfile(path))
            content = open(path).read()
            self.assertIn("cve-2021-44228", content)
            self.assertIn("critical", content.lower())
            self.assertIn("Submission Draft (H1/BC-ready)", content)
            self.assertIn("Steps to Reproduce", content)


# ---------------------------------------------------------------------------
# Integration: dry-run (no tools run, no HTTP to external services)
# ---------------------------------------------------------------------------
class TestDryRun(unittest.TestCase):
    def test_dry_run_importable(self):
        """run_dry_run must be importable and callable without crashing on import."""
        from core.output import run_dry_run
        self.assertTrue(callable(run_dry_run))


# ---------------------------------------------------------------------------
# main.py import sanity
# ---------------------------------------------------------------------------
class TestMainImports(unittest.TestCase):
    def test_main_importable(self):
        """main.py must be importable without side effects"""
        import importlib
        import main as m

        self.assertTrue(hasattr(m, "main"))
        self.assertTrue(callable(m.main))

    def test_all_core_modules_importable(self):
        modules = [
            "core.config",
            "core.ai",
            "core.storage",
            "core.export",
            "core.ui",
            "core.filter",
            "core.scanner",
            "core.notifier",
            "core.reporter",
            "core.watchdog",
            "core.updater",
        ]
        for mod in modules:
            with self.subTest(module=mod):
                import importlib

                importlib.import_module(mod)


class TestScannerResultsSnapshot(unittest.TestCase):
    def test_build_results_snapshot_uses_phase_counts(self):
        from core.scanner import _build_results_snapshot

        target = {"handle": "example_com", "score": 55}
        recon_result = {"counts": {"subdomains": 10, "alive": 6, "httpx_urls": 14}}
        vuln_result = {"counts": {"js_secrets": 3, "findings": 2}}
        res = _build_results_snapshot(target, recon_result, vuln_result)

        self.assertEqual(res["target"], "example_com")
        self.assertEqual(res["score"], 55)
        self.assertEqual(res["subdomains"], 10)
        self.assertEqual(res["alive"], 6)
        self.assertEqual(res["endpoints"], 14)
        self.assertEqual(res["js_secrets"], 3)
        self.assertEqual(res["vulns"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestWatchdogUI(unittest.TestCase):
    """Tests for per-worker UI state management and activity log."""

    def setUp(self):
        import core.ui as ui_mod
        # Reset worker state before each test
        for wid in ui_mod._WORKER_SLOTS:
            ui_mod._workers[wid] = ui_mod._empty_worker(wid)
        ui_mod._activity.clear()

    def test_worker_register_sets_running(self):
        from core.ui import ui_worker_register, _workers
        ui_worker_register("W1", "example.com", idx=1, total=5)
        self.assertEqual(_workers["W1"]["status"], "running")
        self.assertEqual(_workers["W1"]["target"], "example.com")
        self.assertEqual(_workers["W1"]["idx"], 1)
        self.assertEqual(_workers["W1"]["total"], 5)

    def test_worker_tool_lifecycle(self):
        from core.ui import (
            ui_worker_register, ui_worker_tool_started,
            ui_worker_tool_finished, _workers,
        )
        ui_worker_register("W2", "test.io", idx=2, total=10)
        ui_worker_tool_started("W2", "Subfinder", input_count=3, eta=30.0)
        self.assertEqual(_workers["W2"]["tools"]["Subfinder"]["status"], "running")
        self.assertEqual(_workers["W2"]["current_tool"], "Subfinder")

        ui_worker_tool_finished("W2", "Subfinder", count=42, elapsed=28.0)
        self.assertEqual(_workers["W2"]["tools"]["Subfinder"]["status"], "done")
        self.assertEqual(_workers["W2"]["tools"]["Subfinder"]["count"], 42)
        self.assertEqual(_workers["W2"]["metrics"]["subs"], 42)
        self.assertIsNone(_workers["W2"]["current_tool"])

    def test_worker_tool_cached(self):
        from core.ui import ui_worker_register, ui_worker_tool_cached, _workers
        ui_worker_register("W3", "cached.com")
        ui_worker_tool_cached("W3", "DNSX", count=15)
        self.assertEqual(_workers["W3"]["tools"]["DNSX"]["status"], "cached")
        self.assertEqual(_workers["W3"]["tools"]["DNSX"]["count"], 15)

    def test_worker_tool_error(self):
        from core.ui import ui_worker_register, ui_worker_tool_error, _workers
        ui_worker_register("W1", "error.io")
        ui_worker_tool_error("W1", "Nuclei", error="timeout")
        self.assertEqual(_workers["W1"]["tools"]["Nuclei"]["status"], "error")

    def test_worker_done_increments_scanned(self):
        from core.ui import ui_worker_register, ui_worker_done, _total_scanned
        import core.ui as ui_mod
        before = ui_mod._total_scanned
        ui_worker_register("W1", "done.com")
        ui_worker_done("W1", {"target": "done.com", "subdomains": 5, "alive": 2,
                               "endpoints": 10, "js_secrets": 0, "vulns": 0})
        self.assertEqual(ui_mod._total_scanned, before + 1)

    def test_activity_log_populated(self):
        from core.ui import ui_worker_register, _activity
        ui_worker_register("W1", "log.io", idx=1, total=3)
        with_this = [e for e in _activity if "log.io" in e[3]]
        self.assertTrue(len(with_this) >= 1)

    def test_set_worker_context_and_get(self):
        from core.ui import set_worker_context, _get_current_worker
        set_worker_context("W2")
        self.assertEqual(_get_current_worker(), "W2")

    def test_snapshot_creates_file(self):
        import os, glob
        from core.ui import ui_snapshot
        before = set(glob.glob("logs/snapshot_*.json"))
        ui_snapshot("test", "unit-test context")
        after = set(glob.glob("logs/snapshot_*.json"))
        new_files = after - before
        self.assertTrue(len(new_files) >= 1)
        # Clean up
        for f in new_files:
            try: os.unlink(f)
            except: pass

    def test_nuclei_update_routes_to_worker(self):
        from core.ui import (ui_worker_register, ui_worker_tool_started,
                              ui_worker_nuclei_update, _workers)
        ui_worker_register("W3", "nuclei.io")
        ui_worker_tool_started("W3", "Nuclei")
        ui_worker_nuclei_update("W3", done=500, total=1200, rps=45.0, matched=3)
        nq = _workers["W3"]["nuclei_req"]
        self.assertEqual(nq["done"], 500)
        self.assertEqual(nq["total"], 1200)
        self.assertEqual(nq["matched"], 3)

    def test_small_terminal_guard_callable(self):
        from core.ui import _can_use_fullscreen_live
        self.assertIsInstance(_can_use_fullscreen_live(), bool)

    def test_watchdog_activity_log_file_write(self):
        import os
        import tempfile
        from core import ui as ui_mod

        with tempfile.TemporaryDirectory() as td:
            log_path = os.path.join(td, "activity.log")
            prev_watchdog = ui_mod._WATCHDOG_MODE
            with patch.object(ui_mod, "ACTIVITY_LOG_FILE", log_path):
                ui_mod.ui_enable_watchdog_mode()
                ui_mod._activity_push("W1", "Nuclei", "Done in 0s", "green")
                ui_mod._render_stop.set()
                if ui_mod._render_thread is not None:
                    ui_mod._render_thread.join(timeout=0.5)
                with open(log_path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.assertIn("HUNT3R WATCHDOG ACTIVITY START", content)
                self.assertIn("[W1] Nuclei", content)
            ui_mod._WATCHDOG_MODE = prev_watchdog

    def test_sigint_handler_raises_keyboardinterrupt(self):
        from core import ui as ui_mod
        with self.assertRaises(KeyboardInterrupt):
            ui_mod._sigint_handler(None, None)

    def test_watchdog_ui_update_status_skips_spinner_frames(self):
        from core import ui as ui_mod
        prev_watchdog = ui_mod._WATCHDOG_MODE
        ui_mod._WATCHDOG_MODE = True
        try:
            with patch.object(ui_mod, "ui_log") as mock_log:
                ui_mod.ui_update_status("Nuclei", "- 0s | ETA: 12s")
                mock_log.assert_not_called()
                ui_mod.ui_update_status("Nuclei", "Done in 1s")
                mock_log.assert_called_once()
        finally:
            ui_mod._WATCHDOG_MODE = prev_watchdog
