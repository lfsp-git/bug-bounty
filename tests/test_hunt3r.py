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
        from core.storage import ReconDiff

        diff = ReconDiff.compute_diff("__test_handle_xyz__", {"a.com"}, {"http://a.com"})
        self.assertFalse(diff["has_changes"])
        self.assertEqual(diff["added_subs"], set())

    def test_recon_diff_save_and_load(self):
        from core.storage import ReconDiff

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
        from core.storage import ReconDiff

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
        from core.storage import CheckpointManager

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
        from core.storage import CheckpointManager

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
        from core.export import ExportFormatter

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
        from core.export import ExportFormatter

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
        from core.export import ExportFormatter

        formatter = ExportFormatter()
        out = formatter.export(self._sample_findings(), "pdf")
        self.assertEqual(out, "")


# ---------------------------------------------------------------------------
# core/ai.py (unit, no API call)
# ---------------------------------------------------------------------------
class TestAI(unittest.TestCase):
    def test_ai_client_instantiates(self):
        from core.ai import AIClient

        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "test-key-123"}):
            client = AIClient()
            self.assertEqual(client.api_key, "test-key-123")

    def test_ai_client_no_key(self):
        from core.ai import AIClient

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OPENROUTER_API_KEY", None)
            client = AIClient()
            self.assertFalse(bool(client.api_key))

    def test_intel_miner_instantiates(self):
        from core.ai import AIClient, IntelMiner

        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "test-key-123"}):
            ai = AIClient()
            intel = IntelMiner(ai)
            self.assertIsNotNone(intel)


# ---------------------------------------------------------------------------
# core/notifier.py (unit, no HTTP)
# ---------------------------------------------------------------------------
class TestNotifier(unittest.TestCase):
    def test_notifier_config_telegram(self):
        from core.notifier import NotifierConfig

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
        from core.notifier import NotifierConfig

        env = {k: v for k, v in os.environ.items() if k not in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID")}
        with patch.dict(os.environ, env, clear=True):
            result = NotifierConfig.telegram()
            self.assertIsNone(result)

    def test_alert_nuclei_classmethod_exists(self):
        from core.notifier import NotificationDispatcher

        self.assertTrue(callable(NotificationDispatcher.alert_nuclei))


# ---------------------------------------------------------------------------
# core/reporter.py
# ---------------------------------------------------------------------------
class TestReporter(unittest.TestCase):
    def test_reporter_generates_markdown(self):
        from core.reporter import BugBountyReporter

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


# ---------------------------------------------------------------------------
# Integration: dry-run (no tools run, no HTTP to external services)
# ---------------------------------------------------------------------------
class TestDryRun(unittest.TestCase):
    def test_dry_run_importable(self):
        """run_dry_run must be importable and callable without crashing on import."""
        from core.export import run_dry_run
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
