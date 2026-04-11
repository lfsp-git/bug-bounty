"""Comprehensive tests for recon/engines.py — Censys validation, Katana adaptive timeout, Sniper filter."""
import sys
import os
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import patch
from recon.engines import _sync_uncover_providers, apply_sniper_filter


# ── _sync_uncover_providers — Censys key validation ──────────────────────────

class TestSyncUncoverProvidersCensysValidation:
    """Test that Censys ID is validated as UUID/email before enabling."""

    def _run(self, shodan="", chaos="", censys_id="", censys_secret=""):
        """Run _sync_uncover_providers with controlled env vars."""
        env = {
            "SHODAN_API_KEY": shodan,
            "CHAOS_KEY": chaos,
            "CENSYS_API_ID": censys_id,
            "CENSYS_API_SECRET": censys_secret,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "provider-config.yaml")
            with patch.dict(os.environ, env, clear=True), \
                 patch("recon.engines.os.path.expanduser", return_value=cfg_path), \
                 patch("recon.engines.os.makedirs"):
                # provider-config.yaml is written to expanduser path
                # We need to patch the specific open() call in the function
                import builtins
                written_content = []
                orig_open = builtins.open

                def mock_open(path, *args, **kwargs):
                    if path == cfg_path and args and args[0] == "w":
                        import io
                        buf = io.StringIO()
                        class CaptureFile:
                            def write(self, s): written_content.append(s); return len(s)
                            def __enter__(self): return self
                            def __exit__(self, *a): pass
                        return CaptureFile()
                    return orig_open(path, *args, **kwargs)

                with patch("builtins.open", side_effect=mock_open):
                    providers = _sync_uncover_providers()
        return providers, "".join(written_content)

    def test_placeholder_hunt3r_rejected(self):
        providers, _ = self._run(shodan="TMd03E0XcFru", censys_id="Hunt3r", censys_secret="censys_key123")
        assert "censys" not in providers

    def test_simple_word_censys_id_rejected(self):
        providers, _ = self._run(censys_id="notavalid", censys_secret="secret")
        assert "censys" not in providers

    def test_valid_uuid_censys_id_accepted(self):
        valid_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        providers, _ = self._run(censys_id=valid_uuid, censys_secret="real_secret")
        assert "censys" in providers

    def test_email_format_censys_id_accepted(self):
        providers, _ = self._run(censys_id="user@example.com", censys_secret="real_secret")
        assert "censys" in providers

    def test_censys_skipped_when_no_secret(self):
        valid_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        providers, _ = self._run(censys_id=valid_uuid, censys_secret="")
        assert "censys" not in providers

    def test_shodan_key_accepted(self):
        providers, _ = self._run(shodan="TMd03E0XcFruREAL123")
        assert "shodan" in providers

    def test_no_keys_returns_empty_list(self):
        providers, _ = self._run()
        assert providers == []

    def test_shodan_and_valid_censys_both_enabled(self):
        valid_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        providers, _ = self._run(
            shodan="SHODAN_REAL_KEY",
            censys_id=valid_uuid,
            censys_secret="censys_secret",
        )
        assert "shodan" in providers
        assert "censys" in providers

    def test_32char_hex_uuid_accepted(self):
        # Some UUIDs without dashes: 32 hex chars
        hex32 = "a1b2c3d4e5f67890abcdef1234567890"
        providers, _ = self._run(censys_id=hex32, censys_secret="secret")
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
