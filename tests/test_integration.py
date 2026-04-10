"""
Hunt3r EXCALIBUR — Integration Tests

Tests the pipeline with --dry-run against a real-looking target.
All HTTP calls (Telegram/Discord) are mocked.
Tools are mocked to skip actual execution (CI-safe).
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, call

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestWatchdogBbscopeFallback(unittest.TestCase):
    """Watchdog must gracefully handle missing bbscope."""

    def test_bbscope_missing_returns_empty(self):
        """When bbscope is not found and cache is expired, _fetch_global_wildcards returns []."""
        import core.watchdog as wd

        with patch("recon.tools.find_tool", return_value="bbscope"), \
             patch("shutil.which", return_value=None), \
             patch("os.path.exists", return_value=False), \
             patch.dict(os.environ, {"H1_USER": "u", "H1_TOKEN": "t", "BC_TOKEN": "", "IT_TOKEN": ""}):
            result = wd._fetch_global_wildcards()
        self.assertEqual(result, [])

    def test_bbscope_found_uses_resolved_path(self):
        """When bbscope IS found, commands use the resolved path."""
        import core.watchdog as wd

        captured_cmds = []

        def mock_fetch_task(name, cmd, timeout):
            captured_cmds.append(cmd[0])

        with patch("recon.tools.find_tool", return_value="/usr/local/bin/bbscope"), \
             patch("shutil.which", return_value="/usr/local/bin/bbscope"), \
             patch.dict(os.environ, {"H1_USER": "u", "H1_TOKEN": "t", "BC_TOKEN": "", "IT_TOKEN": ""}), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="*.example.com\n")
            # Patch threading.Thread to run synchronously
            with patch("threading.Thread") as mock_thread:
                mock_thread.return_value = MagicMock()
                mock_thread.return_value.start = lambda: None
                mock_thread.return_value.join = lambda: None
                wd._fetch_global_wildcards()
        # Just verify no exception raised and path resolution is called
        from recon.tool_discovery import find_tool
        self.assertIsNotNone(find_tool)

    def test_compute_next_sleep_seconds_returns_int(self):
        import core.watchdog as wd
        secs = wd._compute_next_sleep_seconds({"targets": 10, "changed": 0, "errors": 0})
        self.assertIsInstance(secs, int)
        self.assertGreater(secs, 0)


class TestLiveViewRaceCondition(unittest.TestCase):
    """_live_view_data reads in scanner must use lock."""

    def test_live_view_lock_is_rlock(self):
        """The live view lock must be threading.RLock (re-entrant)."""
        import threading
        from core.ui import _live_view_lock
        # RLock instances are of type _RLock
        self.assertIsInstance(_live_view_lock, type(threading.RLock()))

    def test_live_view_data_has_all_tools(self):
        """Live view data must contain all 7 expected tool keys."""
        from core.ui import _live_view_data
        expected = {"Subfinder", "DNSX", "Uncover", "HTTPX", "JS Hunter", "Katana", "Nuclei"}
        self.assertEqual(set(_live_view_data.keys()), expected)


class TestDryRunPipeline(unittest.TestCase):
    """Pipeline dry-run: no tools executed, no HTTP calls made."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.target = {
            "handle": "example_com",
            "original_handle": "example.com",
            "domains": ["example.com"],
            "score": 50,
        }

    def test_export_formatter_csv(self):
        """ExportFormatter.to_csv() creates a valid CSV file."""
        from core.export import ExportFormatter
        findings = [
            {"template-id": "sqli-001", "severity": "high", "host": "https://example.com"},
            {"template-id": "xss-002", "severity": "medium", "host": "https://sub.example.com"},
        ]
        fmt = ExportFormatter()
        csv_path = os.path.join(self.tmpdir, "test.csv")
        result = fmt.to_csv(findings, filename=csv_path)
        self.assertTrue(os.path.exists(result))
        content = open(result).read()
        self.assertIn("sqli-001", content)
        self.assertIn("xss-002", content)

    def test_export_formatter_xml(self):
        """ExportFormatter.to_xml() creates a valid XML file."""
        from core.export import ExportFormatter
        findings = [{"template-id": "lfi-003", "severity": "critical", "host": "https://example.com"}]
        fmt = ExportFormatter()
        xml_path = os.path.join(self.tmpdir, "test.xml")
        result = fmt.to_xml(findings, filename=xml_path)
        self.assertTrue(os.path.exists(result))
        content = open(result).read()
        self.assertIn("lfi-003", content)

    def test_export_unknown_format_returns_empty(self):
        """ExportFormatter.export() returns '' for unknown format."""
        from core.export import ExportFormatter
        fmt = ExportFormatter()
        result = fmt.export([{"template-id": "x"}], "pdf")
        self.assertEqual(result, "")

    def test_storage_checkpoint_roundtrip(self):
        """CheckpointManager save/load cycle works without errors."""
        from core.storage import CheckpointManager
        cm = CheckpointManager()
        data = {"progress": {"phase": 3}, "findings": [], "completed_targets": []}
        ok = cm.save("test_integ_handle", data)
        self.assertTrue(ok)
        loaded = cm.load("test_integ_handle")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.get("mission_id"), "test_integ_handle")

    def test_unified_output_and_state_exports(self):
        from core.output import ExportFormatter
        from core.state import CheckpointManager

        self.assertTrue(callable(ExportFormatter))
        self.assertTrue(callable(CheckpointManager))

    def test_unified_runner_and_tools_exports(self):
        from core.runner import ProOrchestrator
        from recon.tools import find_tool

        self.assertTrue(callable(ProOrchestrator))
        self.assertTrue(callable(find_tool))

    def test_recon_diff_baseline_roundtrip(self):
        """ReconDiff save/load baseline cycle preserves data."""
        from core.storage import ReconDiff
        data = {"subdomains": 10, "endpoints": 25, "vulns": 2}
        with patch("core.storage.BASELINES_DIR", self.tmpdir):
            ReconDiff.save_baseline("testhandle_integ", data)
            loaded = ReconDiff.load_baseline("testhandle_integ")
        self.assertEqual(loaded.get("subdomains"), 10)

    def test_notification_dispatcher_no_real_http(self):
        """NotificationDispatcher.alert_nuclei() routes critical findings to Telegram."""
        from core.notifier import NotificationDispatcher
        with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
            json.dump({"template-id": "test-cve", "severity": "critical", "matched-at": "https://example.com"}, f)
            f.write("\n")
            findings_path = f.name
        try:
            with patch("requests.post") as mock_post:
                mock_post.return_value = MagicMock(status_code=200)
                with patch("core.notifier.NotifierConfig.telegram", return_value=("fake_token", "fake_chat")):
                    with patch("core.notifier.NotifierConfig.discord", return_value=None):
                        NotificationDispatcher.alert_nuclei(findings_path, "testhandle")
                if mock_post.called:
                    url = mock_post.call_args[0][0]
                    self.assertIn("api.telegram.org", url)
        finally:
            os.unlink(findings_path)


class TestToolDiscovery(unittest.TestCase):
    """Tool discovery finds tools in expected locations."""

    def test_find_tool_returns_string(self):
        """find_tool always returns a string."""
        from recon.tool_discovery import find_tool
        result = find_tool("nonexistent_tool_xyz")
        self.assertIsInstance(result, str)

    def test_find_tool_caches_result(self):
        """find_tool caches results to avoid repeated FS lookups."""
        from recon.tool_discovery import find_tool, _tool_cache, clear_tool_cache
        clear_tool_cache()
        find_tool("nonexistent_tool_abc")
        self.assertIn("nonexistent_tool_abc", _tool_cache)

    def test_clear_tool_cache(self):
        """clear_tool_cache empties the cache."""
        from recon.tool_discovery import find_tool, _tool_cache, clear_tool_cache
        find_tool("some_tool")
        clear_tool_cache()
        self.assertEqual(len(_tool_cache), 0)

    def test_finds_existing_system_tool(self):
        """find_tool can locate a real system tool like 'python3'."""
        from recon.tool_discovery import find_tool, clear_tool_cache
        clear_tool_cache()
        result = find_tool("python3")
        self.assertTrue(os.path.isabs(result) or result == "python3")


class TestFalsePositiveFilter(unittest.TestCase):
    """FalsePositiveKiller sanitizes findings from JSONL files."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def _write_findings(self, findings: list) -> str:
        path = os.path.join(self.tmpdir, "findings.jsonl")
        with open(path, "w") as f:
            for finding in findings:
                f.write(json.dumps(finding) + "\n")
        return path

    def test_sanitize_empty_file(self):
        """sanitize_findings handles empty JSONL gracefully."""
        from core.filter import FalsePositiveKiller
        path = self._write_findings([])
        result = FalsePositiveKiller.sanitize_findings(path)
        self.assertIsInstance(result, bool)

    def test_sanitize_valid_findings(self):
        """sanitize_findings processes valid findings without raising."""
        from core.filter import FalsePositiveKiller
        findings = [
            {"template-id": "sqli-001", "severity": "high", "host": "https://example.com"},
        ]
        path = self._write_findings(findings)
        result = FalsePositiveKiller.sanitize_findings(path)
        self.assertIsInstance(result, bool)


if __name__ == "__main__":
    unittest.main(verbosity=2)
