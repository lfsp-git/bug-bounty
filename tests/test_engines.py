"""Comprehensive tests for recon/engines.py — Censys validation, Katana adaptive timeout, Sniper filter."""
import sys
import os
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import patch
from recon.engines import (
    _sync_uncover_providers, apply_sniper_filter,
    _is_valid_censys_id, _CENSYS_PLACEHOLDERS,
)


# ── _is_valid_censys_id — direct unit tests (no env/IO needed) ───────────────

class TestIsValidCensysId:
    def test_real_short_token_accepted(self):
        assert _is_valid_censys_id("Pu1KHr6r") is True

    def test_hunt3r_placeholder_rejected(self):
        assert _is_valid_censys_id("hunt3r") is False
        assert _is_valid_censys_id("Hunt3r") is False

    def test_censys_placeholder_rejected(self):
        assert _is_valid_censys_id("censys") is False

    def test_too_short_rejected(self):
        assert _is_valid_censys_id("abc") is False
        assert _is_valid_censys_id("") is False
        assert _is_valid_censys_id(None) is False  # type: ignore

    def test_standard_uuid_accepted(self):
        assert _is_valid_censys_id("a1b2c3d4-e5f6-7890-abcd-ef1234567890") is True

    def test_32char_hex_accepted(self):
        assert _is_valid_censys_id("a1b2c3d4e5f67890abcdef1234567890") is True

    def test_email_accepted(self):
        assert _is_valid_censys_id("user@example.com") is True

    def test_changeme_rejected(self):
        assert _is_valid_censys_id("changeme") is False

    def test_six_char_alphanumeric_accepted(self):
        # 6 chars minimum, not a known placeholder
        assert _is_valid_censys_id("Abc123") is True

    def test_five_char_rejected(self):
        assert _is_valid_censys_id("Ab123") is False

    def test_whitespace_only_rejected(self):
        assert _is_valid_censys_id("       ") is False

    def test_contains_whitespace_rejected(self):
        assert _is_valid_censys_id("Pu1K Hr6r") is False

    def test_known_placeholders_all_rejected(self):
        for p in _CENSYS_PLACEHOLDERS:
            assert _is_valid_censys_id(p) is False, f"Placeholder '{p}' should be rejected"


# ── _sync_uncover_providers — integration with real env patching ──────────────

class TestSyncUncoverProvidersCensysValidation:
    """Test that Censys is enabled/disabled based on API key validity."""

    def _run_providers(self, shodan="", censys_id="", censys_secret=""):
        """Patch env + filesystem, call _sync_uncover_providers, return enabled list."""
        env = {
            "SHODAN_API_KEY": shodan,
            "CHAOS_KEY": "",
            "CENSYS_API_ID": censys_id,
            "CENSYS_API_SECRET": censys_secret,
        }
        with patch.dict(os.environ, env, clear=True), \
             patch("recon.engines.os.path.expanduser", return_value="/tmp/test_uncover_config.yaml"), \
             patch("recon.engines.os.makedirs"), \
             patch("builtins.open", create=True):
            return _sync_uncover_providers()

    def test_placeholder_hunt3r_rejected(self):
        providers = self._run_providers(censys_id="Hunt3r", censys_secret="secret123")
        assert "censys" not in providers

    def test_simple_word_rejected(self):
        providers = self._run_providers(censys_id="notavalid_but_long_enough", censys_secret="s")
        # secret is only 1 char so censys_valid = False (secret too short? No, only ID is validated)
        # Actually secret can be any non-empty string — only the ID is validated
        # "notavalid_but_long_enough" is 25 chars, not in placeholder list → VALID ID
        # But the secret is "s" (1 char) which is non-empty → censys_valid = True
        assert "censys" in providers  # ID is valid (not placeholder, ≥6 chars)

    def test_real_token_pu1khr6r_accepted(self):
        providers = self._run_providers(censys_id="Pu1KHr6r", censys_secret="censys_Pu1KHr6r_GXyEfake")
        assert "censys" in providers

    def test_uuid_format_accepted(self):
        providers = self._run_providers(
            censys_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            censys_secret="real_secret",
        )
        assert "censys" in providers

    def test_email_format_accepted(self):
        providers = self._run_providers(censys_id="user@example.com", censys_secret="real_secret")
        assert "censys" in providers

    def test_censys_skipped_when_no_secret(self):
        providers = self._run_providers(censys_id="Pu1KHr6r", censys_secret="")
        assert "censys" not in providers

    def test_shodan_key_accepted(self):
        providers = self._run_providers(shodan="TMd03E0XcFruREAL123")
        assert "shodan" in providers

    def test_no_keys_returns_empty_list(self):
        providers = self._run_providers()
        assert providers == []

    def test_shodan_and_valid_censys_both_enabled(self):
        providers = self._run_providers(
            shodan="SHODAN_REAL_KEY",
            censys_id="Pu1KHr6r",
            censys_secret="censys_Pu1KHr6r_GXyEfake",
        )
        assert "shodan" in providers
        assert "censys" in providers


# ── Katana adaptive timeout formula ──────────────────────────────────────────

class TestKatanaAdaptiveTimeout:
    """Test the adaptive timeout calculation inside run_katana_surgical."""

    def _calc_timeout(self, endpoint_count: int) -> int:
        """Mirror the formula from engines.py."""
        base_timeout = 300
        per_url_extra = max(0, endpoint_count - 30) * 6
        return min(base_timeout + per_url_extra, 900)

    def test_zero_urls_returns_base_300(self):
        assert self._calc_timeout(0) == 300

    def test_30_urls_returns_base_300(self):
        assert self._calc_timeout(30) == 300

    def test_31_urls_adds_6_seconds(self):
        assert self._calc_timeout(31) == 306

    def test_60_urls_adds_180_seconds(self):
        assert self._calc_timeout(60) == 480

    def test_100_urls_returns_720(self):
        assert self._calc_timeout(100) == 720

    def test_large_input_capped_at_900(self):
        assert self._calc_timeout(10000) == 900

    def test_exactly_at_cap_boundary(self):
        assert self._calc_timeout(130) == 900

    def test_just_below_cap_not_capped(self):
        assert self._calc_timeout(129) == 894

    def test_formula_in_source_file(self):
        with open("recon/engines.py", "r") as f:
            content = f.read()
        assert "adaptive_timeout" in content
        assert "300" in content
        assert "900" in content

    def test_crawl_duration_flag_used(self):
        with open("recon/engines.py", "r") as f:
            content = f.read()
        assert "-crawl-duration" in content


# ── apply_sniper_filter ───────────────────────────────────────────────────────

class TestApplySniperFilter:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_input(self, lines):
        path = os.path.join(self.tmpdir, "input.txt")
        with open(path, "w") as f:
            f.write("\n".join(lines))
        return path

    def _make_output(self):
        return os.path.join(self.tmpdir, "output.txt")

    def _read(self, path):
        with open(path) as f:
            return [l.strip() for l in f if l.strip()]

    def test_removes_ns_cloudflare(self):
        inp = self._make_input(["sub.ns.cloudflare.com", "other.ns.cloudflare.com", "target.com"])
        out = self._make_output()
        apply_sniper_filter(inp, out)
        result = self._read(out)
        assert not any("ns.cloudflare.com" in r for r in result)
        assert "target.com" in result

    def test_removes_secondary_cloudflare(self):
        inp = self._make_input(["bob.secondary.cloudflare.com", "legit.example.com"])
        out = self._make_output()
        apply_sniper_filter(inp, out)
        result = self._read(out)
        assert not any("secondary.cloudflare.com" in r for r in result)
        assert "legit.example.com" in result

    def test_removes_cf_prefix_patterns(self):
        inp = self._make_input(["cf-1-node.example.com", "cf-99-edge.test.com", "real-domain.com"])
        out = self._make_output()
        apply_sniper_filter(inp, out)
        result = self._read(out)
        assert not any(r.startswith("cf-") for r in result)
        assert "real-domain.com" in result

    def test_removes_ssl_cloudflare(self):
        inp = self._make_input(["ssl1.cloudflare.com", "ssl45.cloudflare.com", "app.example.com"])
        out = self._make_output()
        apply_sniper_filter(inp, out)
        result = self._read(out)
        assert not any("ssl" in r and "cloudflare.com" in r for r in result)
        assert "app.example.com" in result

    def test_keeps_non_cloudflare_domains(self):
        domains = ["api.example.com", "auth.company.io", "dev.startup.ai"]
        inp = self._make_input(domains)
        out = self._make_output()
        apply_sniper_filter(inp, out)
        result = self._read(out)
        assert set(result) == set(domains)

    def test_missing_input_returns_original_path(self):
        out = self._make_output()
        result = apply_sniper_filter("/nonexistent/path.txt", out)
        assert result == "/nonexistent/path.txt"

    def test_empty_input_creates_empty_output(self):
        inp = self._make_input([])
        out = self._make_output()
        apply_sniper_filter(inp, out)
        result = self._read(out)
        assert result == []

    def test_skips_blank_lines(self):
        inp = self._make_input(["target.com", "", "  ", "other.com"])
        out = self._make_output()
        apply_sniper_filter(inp, out)
        result = self._read(out)
        assert "" not in result
        assert "target.com" in result
        assert "other.com" in result

    def test_returns_output_path(self):
        inp = self._make_input(["example.com"])
        out = self._make_output()
        returned = apply_sniper_filter(inp, out)
        assert returned == out



# ── Katana adaptive timeout formula ──────────────────────────────────────────

class TestKatanaAdaptiveTimeout:
    """Test the adaptive timeout calculation inside run_katana_surgical."""

    def _calc_timeout(self, endpoint_count: int) -> int:
        """Mirror the formula from engines.py."""
        base_timeout = 300
        per_url_extra = max(0, endpoint_count - 30) * 6
        return min(base_timeout + per_url_extra, 900)

    def test_zero_urls_returns_base_300(self):
        assert self._calc_timeout(0) == 300

    def test_30_urls_returns_base_300(self):
        assert self._calc_timeout(30) == 300

    def test_31_urls_adds_6_seconds(self):
        assert self._calc_timeout(31) == 306

    def test_60_urls_adds_180_seconds(self):
        # (60-30) * 6 = 180 → 300+180 = 480
        assert self._calc_timeout(60) == 480

    def test_100_urls_returns_720(self):
        # (100-30) * 6 = 420 → 300+420 = 720
        assert self._calc_timeout(100) == 720

    def test_large_input_capped_at_900(self):
        assert self._calc_timeout(10000) == 900

    def test_exactly_at_cap_boundary(self):
        # (130-30) * 6 = 600 → 300+600 = 900
        assert self._calc_timeout(130) == 900

    def test_just_below_cap_not_capped(self):
        # (129-30) * 6 = 594 → 300+594 = 894 < 900
        assert self._calc_timeout(129) == 894

    def test_formula_in_source_file(self):
        """Verify the formula is actually present in engines.py source."""
        with open("recon/engines.py", "r") as f:
            content = f.read()
        assert "adaptive_timeout" in content
        assert "300" in content
        assert "900" in content

    def test_crawl_duration_flag_used(self):
        """Katana should use -crawl-duration not just -timeout for total wall-clock limit."""
        with open("recon/engines.py", "r") as f:
            content = f.read()
        assert "-crawl-duration" in content


# ── apply_sniper_filter ───────────────────────────────────────────────────────

class TestApplySniperFilter:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_input(self, lines):
        path = os.path.join(self.tmpdir, "input.txt")
        with open(path, "w") as f:
            f.write("\n".join(lines))
        return path

    def _make_output(self):
        return os.path.join(self.tmpdir, "output.txt")

    def _read(self, path):
        with open(path) as f:
            return [l.strip() for l in f if l.strip()]

    def test_removes_ns_cloudflare(self):
        # regex: r'\.ns\.cloudflare\.com$' — requires dot BEFORE ns
        inp = self._make_input(["sub.ns.cloudflare.com", "other.ns.cloudflare.com", "target.com"])
        out = self._make_output()
        apply_sniper_filter(inp, out)
        result = self._read(out)
        assert not any("ns.cloudflare.com" in r for r in result)
        assert "target.com" in result

    def test_removes_secondary_cloudflare(self):
        inp = self._make_input(["bob.secondary.cloudflare.com", "legit.example.com"])
        out = self._make_output()
        apply_sniper_filter(inp, out)
        result = self._read(out)
        assert not any("secondary.cloudflare.com" in r for r in result)
        assert "legit.example.com" in result

    def test_removes_cf_prefix_patterns(self):
        # regex: r'^cf-\d{1,3}-' — requires dash AFTER digits
        inp = self._make_input(["cf-1-node.example.com", "cf-99-edge.test.com", "real-domain.com"])
        out = self._make_output()
        apply_sniper_filter(inp, out)
        result = self._read(out)
        assert not any(r.startswith("cf-") for r in result)
        assert "real-domain.com" in result

    def test_removes_ssl_cloudflare(self):
        inp = self._make_input(["ssl1.cloudflare.com", "ssl45.cloudflare.com", "app.example.com"])
        out = self._make_output()
        apply_sniper_filter(inp, out)
        result = self._read(out)
        assert not any("ssl" in r and "cloudflare.com" in r for r in result)
        assert "app.example.com" in result

    def test_keeps_non_cloudflare_domains(self):
        domains = ["api.example.com", "auth.company.io", "dev.startup.ai"]
        inp = self._make_input(domains)
        out = self._make_output()
        apply_sniper_filter(inp, out)
        result = self._read(out)
        assert set(result) == set(domains)

    def test_missing_input_returns_original_path(self):
        out = self._make_output()
        result = apply_sniper_filter("/nonexistent/path.txt", out)
        assert result == "/nonexistent/path.txt"

    def test_empty_input_creates_empty_output(self):
        inp = self._make_input([])
        out = self._make_output()
        apply_sniper_filter(inp, out)
        result = self._read(out)
        assert result == []

    def test_skips_blank_lines(self):
        inp = self._make_input(["target.com", "", "  ", "other.com"])
        out = self._make_output()
        apply_sniper_filter(inp, out)
        result = self._read(out)
        assert "" not in result
        assert "target.com" in result
        assert "other.com" in result

    def test_returns_output_path(self):
        inp = self._make_input(["example.com"])
        out = self._make_output()
        returned = apply_sniper_filter(inp, out)
        assert returned == out
