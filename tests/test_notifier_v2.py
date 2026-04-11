"""Comprehensive tests for core/notifier.py — all new methods and severity routing."""
import sys
import os
import json
import tempfile
import unittest
from unittest.mock import patch, MagicMock, call

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.notifier import (
    NotificationDispatcher, NotifierConfig,
    _tg_escape, _canonical_text, _hashed_dedup_key,
    _utc_now, _get_sev, _prune_dedup_cache, _dc_post, _tg_post,
)


# ── Helper utilities ──────────────────────────────────────────────────────────

class TestTgEscape:
    def test_escapes_ampersand(self):
        assert _tg_escape("a & b") == "a &amp; b"

    def test_escapes_lt(self):
        assert _tg_escape("<script>") == "&lt;script&gt;"

    def test_escapes_gt(self):
        assert _tg_escape("1 > 0") == "1 &gt; 0"

    def test_clean_string_unchanged(self):
        assert _tg_escape("hello world") == "hello world"


class TestCanonicalText:
    def test_lowercases_and_strips(self):
        assert _canonical_text("  Hello World  ") == "hello world"

    def test_collapses_whitespace(self):
        assert _canonical_text("a   b   c") == "a b c"

    def test_none_returns_empty(self):
        assert _canonical_text(None) == ""

    def test_truncates_to_max_len(self):
        long_str = "x" * 300
        result = _canonical_text(long_str, max_len=100)
        assert len(result) == 100


class TestHashedDedupKey:
    def test_returns_string_with_prefix(self):
        key = _hashed_dedup_key("tg:nuclei", "target", "CRITICAL", "template-id")
        assert key.startswith("tg:nuclei:")

    def test_same_inputs_same_hash(self):
        k1 = _hashed_dedup_key("prefix", "a", "b", "c")
        k2 = _hashed_dedup_key("prefix", "a", "b", "c")
        assert k1 == k2

    def test_different_inputs_different_hash(self):
        k1 = _hashed_dedup_key("prefix", "a", "b")
        k2 = _hashed_dedup_key("prefix", "a", "X")
        assert k1 != k2


class TestGetSev:
    def test_top_level_severity(self):
        assert _get_sev({"severity": "HIGH"}) == "high"

    def test_nested_info_severity(self):
        assert _get_sev({"info": {"severity": "Critical"}}) == "critical"

    def test_default_when_missing(self):
        assert _get_sev({}) == "info"
        assert _get_sev({}, "unknown") == "unknown"

    def test_top_level_takes_precedence(self):
        assert _get_sev({"severity": "medium", "info": {"severity": "critical"}}) == "medium"


class TestPruneDedupCache:
    def test_prunes_expired_entries(self):
        now = 1_000_000
        cache = {"key1": now - 1000, "key2": now - 100}
        result = _prune_dedup_cache(cache, now)
        # Both younger than default TTL (7 days), so both kept
        assert "key1" in result
        assert "key2" in result

    def test_removes_very_old_entries(self):
        now = 1_000_000
        ttl = 60 * 60 * 24 * 7  # 7 days default
        old_ts = now - ttl - 1
        cache = {"old_key": old_ts, "fresh_key": now - 60}
        result = _prune_dedup_cache(cache, now)
        assert "old_key" not in result
        assert "fresh_key" in result

    def test_ignores_non_int_values(self):
        cache = {"bad_key": "not_a_timestamp"}
        result = _prune_dedup_cache(cache, 1_000_000)
        assert "bad_key" not in result


# ── NotifierConfig ────────────────────────────────────────────────────────────

class TestNotifierConfig:
    def test_telegram_returns_none_when_missing(self):
        with patch.dict(os.environ, {}, clear=True):
            assert NotifierConfig.telegram() is None

    def test_telegram_returns_tuple_when_set(self):
        with patch.dict(os.environ, {
            "TELEGRAM_BOT_TOKEN": "fake_token",
            "TELEGRAM_CHAT_ID": "12345",
        }):
            result = NotifierConfig.telegram()
            assert result == ("fake_token", "12345")

    def test_discord_returns_none_when_missing(self):
        with patch.dict(os.environ, {}, clear=True):
            assert NotifierConfig.discord() is None

    def test_discord_returns_webhook_when_set(self):
        with patch.dict(os.environ, {"DISCORD_WEBHOOK": "https://discord.com/api/webhooks/fake"}):
            assert NotifierConfig.discord() == "https://discord.com/api/webhooks/fake"


# ── alert_scan_complete ───────────────────────────────────────────────────────

class TestAlertScanComplete:
    def _run(self, target="capitalone", platform="h1", results=None, webhook="https://discord.test"):
        """Run alert_scan_complete with mocked HTTP and captured embed."""
        if results is None:
            results = {"subdomains": 45, "alive": 12, "endpoints": 120, "js_secrets": 3}
        captured = []
        with patch.dict(os.environ, {"DISCORD_WEBHOOK": webhook}):
            with patch("core.notifier._dc_post") as mock_dc:
                NotificationDispatcher.alert_scan_complete(target, platform, results)
                return mock_dc.call_args_list, mock_dc

    def test_no_discord_webhook_no_crash(self):
        with patch.dict(os.environ, {}, clear=True):
            NotificationDispatcher.alert_scan_complete("target", "h1", {})

    def test_discord_called_once(self):
        calls, mock_dc = self._run()
        mock_dc.assert_called_once()

    def test_embed_has_title_with_target(self):
        calls, mock_dc = self._run(target="stripe")
        embed = mock_dc.call_args[0][1]
        assert "stripe" in embed["title"]

    def test_embed_has_description(self):
        calls, mock_dc = self._run(results={"subdomains": 10, "alive": 5, "endpoints": 50, "js_secrets": 1})
        embed = mock_dc.call_args[0][1]
        assert "Subdomains" in embed["description"]
        assert "10" in embed["description"]

    def test_platform_h1_label_in_fields(self):
        calls, mock_dc = self._run(platform="h1")
        embed = mock_dc.call_args[0][1]
        field_values = [f["value"] for f in embed.get("fields", [])]
        assert any("HackerOne" in v for v in field_values)

    def test_platform_bc_label(self):
        calls, mock_dc = self._run(platform="bc")
        embed = mock_dc.call_args[0][1]
        field_values = [f["value"] for f in embed.get("fields", [])]
        assert any("Bugcrowd" in v for v in field_values)

    def test_platform_unknown_shows_custom(self):
        calls, mock_dc = self._run(platform="unknown")
        embed = mock_dc.call_args[0][1]
        field_values = " ".join(f["value"] for f in embed.get("fields", []))
        assert "Custom" in field_values or "UNKNOWN" in field_values.upper()

    def test_green_color_when_clean(self):
        calls, mock_dc = self._run(results={"subdomains": 5, "alive": 2, "endpoints": 10, "js_secrets": 0, "errors": []})
        embed = mock_dc.call_args[0][1]
        assert embed["color"] == 0x2ECC71

    def test_red_color_when_criticals_found(self):
        calls, mock_dc = self._run(results={
            "subdomains": 5, "alive": 2, "endpoints": 10, "js_secrets": 0, "errors": [],
            "severity_counts": {"critical": 2, "high": 0, "medium": 0},
        })
        embed = mock_dc.call_args[0][1]
        assert embed["color"] == 0xFF0000

    def test_orange_color_when_errors(self):
        calls, mock_dc = self._run(results={
            "subdomains": 5, "alive": 2, "endpoints": 10, "js_secrets": 0,
            "errors": ["phase failed"],
        })
        embed = mock_dc.call_args[0][1]
        assert embed["color"] == 0xFF4500

    def test_yellow_color_when_medium_found(self):
        calls, mock_dc = self._run(results={
            "subdomains": 5, "alive": 2, "endpoints": 10, "js_secrets": 0, "errors": [],
            "severity_counts": {"critical": 0, "high": 0, "medium": 1},
        })
        embed = mock_dc.call_args[0][1]
        assert embed["color"] == 0xFFFF00

    def test_embed_has_footer(self):
        calls, mock_dc = self._run()
        embed = mock_dc.call_args[0][1]
        assert "footer" in embed

    def test_embed_has_timestamp(self):
        calls, mock_dc = self._run()
        embed = mock_dc.call_args[0][1]
        assert "timestamp" in embed


# ── alert_watchdog_heartbeat ──────────────────────────────────────────────────

class TestAlertWatchdogHeartbeat:
    def _run(self, cycle=1, targets=10, errors=0, avg_r=80.0, avg_v=120.0, next_in="2h0m"):
        with patch.dict(os.environ, {"DISCORD_WEBHOOK": "https://discord.test"}):
            with patch("core.notifier._dc_post") as mock_dc:
                NotificationDispatcher.alert_watchdog_heartbeat(
                    cycle=cycle, targets_scanned=targets, errors=errors,
                    avg_recon_s=avg_r, avg_vuln_s=avg_v, next_cycle_in=next_in,
                )
                return mock_dc

    def test_no_webhook_no_crash(self):
        with patch.dict(os.environ, {}, clear=True):
            NotificationDispatcher.alert_watchdog_heartbeat(1, 5, 0, 80.0, 120.0)

    def test_discord_called_once(self):
        mock_dc = self._run()
        mock_dc.assert_called_once()

    def test_embed_mentions_cycle_number(self):
        mock_dc = self._run(cycle=3)
        embed = mock_dc.call_args[0][1]
        assert "3" in embed["description"]

    def test_embed_mentions_target_count(self):
        mock_dc = self._run(targets=15)
        embed = mock_dc.call_args[0][1]
        assert "15" in embed["description"]

    def test_blue_color_when_no_errors(self):
        mock_dc = self._run(errors=0)
        embed = mock_dc.call_args[0][1]
        assert embed["color"] == 0x3498DB

    def test_orange_color_when_errors(self):
        mock_dc = self._run(errors=3)
        embed = mock_dc.call_args[0][1]
        assert embed["color"] == 0xFF4500

    def test_embed_mentions_next_cycle(self):
        mock_dc = self._run(next_in="1h30m")
        embed = mock_dc.call_args[0][1]
        assert "1h30m" in embed["description"]

    def test_embed_has_rain_check_title(self):
        mock_dc = self._run()
        embed = mock_dc.call_args[0][1]
        assert "Rain-Check" in embed["title"] or "Watchdog" in embed["title"]


# ── alert_watchdog_error ──────────────────────────────────────────────────────

class TestAlertWatchdogError:
    def test_no_webhook_no_crash(self):
        with patch.dict(os.environ, {}, clear=True):
            NotificationDispatcher.alert_watchdog_error("something broke")

    def test_discord_called_with_error_embed(self):
        with patch.dict(os.environ, {"DISCORD_WEBHOOK": "https://discord.test"}):
            with patch("core.notifier._dc_post") as mock_dc:
                NotificationDispatcher.alert_watchdog_error("Critical failure in phase X")
                mock_dc.assert_called_once()
                embed = mock_dc.call_args[0][1]
                assert embed["color"] == 0xFF0000
                assert "Critical failure" in embed["description"]

    def test_long_message_truncated(self):
        long_msg = "x" * 5000
        with patch.dict(os.environ, {"DISCORD_WEBHOOK": "https://discord.test"}):
            with patch("core.notifier._dc_post") as mock_dc:
                NotificationDispatcher.alert_watchdog_error(long_msg)
                embed = mock_dc.call_args[0][1]
                assert len(embed["description"]) <= 2100  # code block wrapper adds ~10 chars


# ── alert_nuclei — severity routing ──────────────────────────────────────────

class TestAlertNucleiSeverityRouting:
    def _write_findings(self, findings: list) -> str:
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        for f in findings:
            tmp.write(json.dumps(f) + "\n")
        tmp.flush()
        return tmp.name

    def _run_with_tg(self, findings: list):
        path = self._write_findings(findings)
        with patch.dict(os.environ, {
            "TELEGRAM_BOT_TOKEN": "token", "TELEGRAM_CHAT_ID": "123",
        }):
            with patch("core.notifier._tg_post") as mock_tg, \
                 patch("core.notifier._is_duplicate_and_record_keys", return_value=False):
                NotificationDispatcher.alert_nuclei(path, "target.com")
                return mock_tg
        os.unlink(path)

    def _finding(self, sev):
        return {
            "severity": sev,
            "template-id": f"test-{sev}",
            "matched-at": "https://target.com/path",
        }

    def test_critical_finding_sent_to_telegram(self):
        mock_tg = self._run_with_tg([self._finding("critical")])
        mock_tg.assert_called_once()

    def test_high_finding_sent_to_telegram(self):
        mock_tg = self._run_with_tg([self._finding("high")])
        mock_tg.assert_called_once()

    def test_medium_finding_sent_to_telegram(self):
        mock_tg = self._run_with_tg([self._finding("medium")])
        mock_tg.assert_called_once()

    def test_low_finding_dropped(self):
        mock_tg = self._run_with_tg([self._finding("low")])
        mock_tg.assert_not_called()

    def test_info_finding_dropped(self):
        mock_tg = self._run_with_tg([self._finding("info")])
        mock_tg.assert_not_called()

    def test_multiple_severities_only_medium_plus_sent(self):
        findings = [
            self._finding("critical"),
            self._finding("high"),
            self._finding("medium"),
            self._finding("low"),
            self._finding("info"),
        ]
        mock_tg = self._run_with_tg(findings)
        assert mock_tg.call_count == 3  # critical + high + medium

    def test_empty_file_no_crash(self):
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        tmp.close()
        with patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": "tok", "TELEGRAM_CHAT_ID": "1"}):
            with patch("core.notifier._tg_post") as mock_tg:
                NotificationDispatcher.alert_nuclei(tmp.name, "target")
                mock_tg.assert_not_called()
        os.unlink(tmp.name)

    def test_missing_file_no_crash(self):
        with patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": "tok", "TELEGRAM_CHAT_ID": "1"}):
            with patch("core.notifier._tg_post") as mock_tg:
                NotificationDispatcher.alert_nuclei("/nonexistent/path.jsonl", "target")
                mock_tg.assert_not_called()

    def test_no_telegram_no_crash(self):
        path = self._write_findings([self._finding("critical")])
        with patch.dict(os.environ, {}, clear=True):
            NotificationDispatcher.alert_nuclei(path, "target")
        os.unlink(path)


# ── alert_nuclei_discord_batch — deprecated no-op ────────────────────────────

class TestAlertNucleiDiscordBatchDeprecated:
    def test_deprecated_method_is_noop(self):
        with patch.dict(os.environ, {"DISCORD_WEBHOOK": "https://discord.test"}):
            with patch("core.notifier._dc_post") as mock_dc:
                NotificationDispatcher.alert_nuclei_discord_batch(
                    [{"severity": "info", "template-id": "x"}], "target"
                )
                mock_dc.assert_not_called()


# ── alert_js_secrets — severity routing ──────────────────────────────────────

class TestAlertJsSecretsSeverityRouting:
    def _write_secrets(self, entries: list) -> str:
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".js_secrets", delete=False)
        for e in entries:
            tmp.write(json.dumps(e) + "\n")
        tmp.flush()
        return tmp.name

    def _secret(self, severity, stype="aws_key", value="AKIAIOSFODNN7EXAMPLE"):
        return {"type": stype, "severity": severity, "source": "https://target.com/app.js",
                "value": value}

    def _run(self, entries):
        path = self._write_secrets(entries)
        with patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": "tok", "TELEGRAM_CHAT_ID": "1"}):
            with patch("core.notifier._tg_post") as mock_tg, \
                 patch("core.notifier._is_duplicate_and_record_keys", return_value=False):
                NotificationDispatcher.alert_js_secrets(path, "target.com")
                os.unlink(path)
                return mock_tg

    def test_critical_secret_sent_to_telegram(self):
        mock_tg = self._run([self._secret("CRITICAL")])
        mock_tg.assert_called_once()

    def test_high_secret_sent_to_telegram(self):
        mock_tg = self._run([self._secret("HIGH")])
        mock_tg.assert_called_once()

    def test_medium_secret_sent_to_telegram(self):
        mock_tg = self._run([self._secret("MEDIUM")])
        mock_tg.assert_called_once()

    def test_low_secret_dropped(self):
        mock_tg = self._run([self._secret("low")])
        mock_tg.assert_not_called()

    def test_no_discord_for_any_secrets(self):
        path = self._write_secrets([self._secret("HIGH")])
        with patch.dict(os.environ, {
            "TELEGRAM_BOT_TOKEN": "tok", "TELEGRAM_CHAT_ID": "1",
            "DISCORD_WEBHOOK": "https://discord.test",
        }):
            with patch("core.notifier._dc_post") as mock_dc, \
                 patch("core.notifier._tg_post"), \
                 patch("core.notifier._is_duplicate_and_record_keys", return_value=False):
                NotificationDispatcher.alert_js_secrets(path, "target")
                mock_dc.assert_not_called()
        os.unlink(path)

    def test_empty_file_no_crash(self):
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".js_secrets", delete=False)
        tmp.close()
        with patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": "tok", "TELEGRAM_CHAT_ID": "1"}):
            with patch("core.notifier._tg_post") as mock_tg:
                NotificationDispatcher.alert_js_secrets(tmp.name, "target")
                mock_tg.assert_not_called()
        os.unlink(tmp.name)

    def test_missing_file_no_crash(self):
        with patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": "tok", "TELEGRAM_CHAT_ID": "1"}):
            with patch("core.notifier._tg_post") as mock_tg:
                NotificationDispatcher.alert_js_secrets("/nonexistent.js_secrets", "target")
                mock_tg.assert_not_called()
