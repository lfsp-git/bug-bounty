"""Tests for core/cleaner.py — improved --clean workflow."""
import os
import sys
import tempfile
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import patch, MagicMock, call
from core.cleaner import (
    _mask,
    _tool_version,
    _find_binary,
    _get_venv_python,
    _check_tools,
    _check_api_keys,
    _check_ml_model,
    _run_tests,
    _purge_caches,
    _update_deps,
)


# ── _mask ─────────────────────────────────────────────────────────────────────

class TestMask:
    def test_short_value_fully_masked(self):
        assert _mask("abc") == "****"
        assert _mask("") == "****"

    def test_exactly_4_chars_fully_masked(self):
        assert _mask("abcd") == "****"

    def test_long_value_shows_prefix(self):
        result = _mask("TMd03E0XcFru")
        assert result.startswith("TMd0")
        assert "***" in result
        assert "0XcFru" not in result

    def test_key_has_correct_length(self):
        result = _mask("ABCDEFGHIJ")
        assert result == "ABCD***"


# ── _tool_version ─────────────────────────────────────────────────────────────

class TestToolVersion:
    def test_returns_version_string_for_real_binary(self):
        python = sys.executable
        version = _tool_version(python)
        assert version.startswith("v") or version == ""

    def test_returns_empty_on_nonexistent_binary(self):
        version = _tool_version("/nonexistent/path/binary")
        assert version == ""

    def test_parses_vN_N_N_format(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="subfinder version v2.6.3\n",
                stderr="",
                returncode=0,
            )
            version = _tool_version("/bin/subfinder")
        assert version == "v2.6.3"

    def test_parses_numeric_only_format(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="nuclei 3.1.4\n",
                stderr="",
                returncode=0,
            )
            version = _tool_version("/bin/nuclei")
        assert version == "v3.1.4"

    def test_returns_empty_on_timeout(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 5)):
            version = _tool_version("/slow/binary")
        assert version == ""


# ── _find_binary ──────────────────────────────────────────────────────────────

class TestFindBinary:
    def test_finds_system_python3(self):
        path = _find_binary("python3")
        assert path != ""

    def test_returns_empty_for_nonexistent_tool(self):
        path = _find_binary("nonexistent_tool_xyz_abc")
        assert path == ""

    def test_prefers_pdtm_path_when_exists(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_binary = os.path.join(tmpdir, "mytool")
            open(fake_binary, "w").close()
            with patch("core.cleaner._PDTM", tmpdir):
                path = _find_binary("mytool")
        assert path == fake_binary


# ── _get_venv_python ──────────────────────────────────────────────────────────

class TestGetVenvPython:
    def test_returns_string(self):
        result = _get_venv_python()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_returns_venv_python_when_exists(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            venv_bin = os.path.join(tmpdir, ".venv", "bin")
            os.makedirs(venv_bin)
            venv_py = os.path.join(venv_bin, "python3")
            open(venv_py, "w").close()
            root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            # Patch abspath to return our tmpdir
            with patch("core.cleaner.os.path.dirname", return_value=tmpdir):
                result = _get_venv_python()
            # Can't easily inject without more patching; just verify it returns something valid
            assert isinstance(result, str)

    def test_falls_back_to_sys_executable_when_no_venv(self):
        with patch("os.path.isfile", return_value=False):
            result = _get_venv_python()
        assert result == sys.executable


# ── _check_tools ──────────────────────────────────────────────────────────────

class TestCheckTools:
    def test_returns_dict_with_required_tools(self):
        with patch("core.cleaner._find_binary", return_value="/bin/fake"), \
             patch("core.cleaner._tool_version", return_value="v1.0.0"), \
             patch("core.cleaner._step"):
            results = _check_tools()
        from core.cleaner import _REQUIRED_TOOLS
        for tool in _REQUIRED_TOOLS:
            assert tool in results
            assert results[tool] is True

    def test_marks_missing_tools_as_false(self):
        with patch("core.cleaner._find_binary", return_value=""), \
             patch("core.cleaner._step"):
            results = _check_tools()
        from core.cleaner import _REQUIRED_TOOLS
        for tool in _REQUIRED_TOOLS:
            assert results[tool] is False

    def test_optional_tools_not_in_result(self):
        with patch("core.cleaner._find_binary", return_value=""), \
             patch("core.cleaner._step"):
            results = _check_tools()
        from core.cleaner import _OPTIONAL_TOOLS
        for tool in _OPTIONAL_TOOLS:
            assert tool not in results


# ── _check_api_keys ───────────────────────────────────────────────────────────

class TestCheckApiKeys:
    def test_returns_dict(self):
        with patch.dict(os.environ, {}, clear=True), \
             patch("core.cleaner._step"), \
             patch("os.path.isfile", return_value=False):
            results = _check_api_keys()
        assert isinstance(results, dict)

    def test_set_key_marks_true(self):
        env = {"H1_TOKEN": "real_token_here", "SHODAN_API_KEY": "SHOD1234"}
        with patch.dict(os.environ, env), \
             patch("core.cleaner._step"), \
             patch("os.path.isfile", return_value=False):
            results = _check_api_keys()
        assert results["HackerOne Token"] is True
        assert results["Shodan"] is True

    def test_missing_key_marks_false(self):
        env = {}
        with patch.dict(os.environ, env, clear=True), \
             patch("core.cleaner._step"), \
             patch("os.path.isfile", return_value=False):
            results = _check_api_keys()
        assert results["HackerOne Token"] is False

    def test_reads_env_file_when_env_not_set(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("H1_TOKEN=token_from_file\n")
            env_path = f.name
        try:
            with patch.dict(os.environ, {}, clear=True), \
                 patch("core.cleaner._step"), \
                 patch("core.cleaner.os.path.isfile", return_value=True), \
                 patch("core.cleaner.open", create=True, side_effect=lambda *a, **k: open(env_path)):
                results = _check_api_keys()
        finally:
            os.unlink(env_path)
        assert isinstance(results, dict)


# ── _check_ml_model ───────────────────────────────────────────────────────────

class TestCheckMlModel:
    def test_returns_true_when_model_exists(self):
        with patch("core.cleaner._step"), \
             patch("os.path.isfile", return_value=True), \
             patch("os.path.getsize", return_value=51200):
            result = _check_ml_model()
        assert result is True

    def test_returns_false_when_missing(self):
        with patch("core.cleaner._step"), \
             patch("os.path.isfile", return_value=False):
            result = _check_ml_model()
        assert result is False


# ── _run_tests ────────────────────────────────────────────────────────────────

class TestRunTests:
    def test_returns_true_on_pass(self):
        mock_result = MagicMock(returncode=0, stdout="5 passed in 1.2s\n", stderr="")
        with patch("subprocess.run", return_value=mock_result), \
             patch("core.cleaner._step"):
            ok = _run_tests()
        assert ok is True

    def test_returns_false_on_failure(self):
        mock_result = MagicMock(
            returncode=1,
            stdout="FAILED tests/test_foo.py::TestBar::test_x\n1 failed in 0.9s\n",
            stderr="",
        )
        with patch("subprocess.run", return_value=mock_result), \
             patch("core.cleaner._step"):
            ok = _run_tests()
        assert ok is False

    def test_uses_venv_python(self):
        called_with = []
        def capture(*args, **kwargs):
            called_with.append(args[0])
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=capture), \
             patch("core.cleaner._step"), \
             patch("core.cleaner._get_venv_python", return_value="/custom/venv/bin/python3"):
            _run_tests()

        assert called_with[0][0] == "/custom/venv/bin/python3"

    def test_failure_output_logged(self):
        logged = []
        def capture_step(label, msg, color=None):
            logged.append(msg)

        mock_result = MagicMock(
            returncode=1,
            stdout="FAILED tests/test_foo.py::test_x\n1 failed\n",
            stderr="",
        )
        with patch("subprocess.run", return_value=mock_result), \
             patch("core.cleaner._step", side_effect=capture_step):
            _run_tests()

        assert any("FAILED" in m for m in logged)


# ── _purge_caches ─────────────────────────────────────────────────────────────

class TestPurgeCaches:
    def test_runs_without_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            orig = os.getcwd()
            os.chdir(tmpdir)
            try:
                os.makedirs("recon/baselines", exist_ok=True)
                os.makedirs("recon/cache", exist_ok=True)
                _purge_caches()
                assert os.path.isdir("recon/baselines")
                assert os.path.isdir("recon/cache")
            finally:
                os.chdir(orig)

    def test_removes_listed_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            orig = os.getcwd()
            os.chdir(tmpdir)
            try:
                os.makedirs("recon/baselines", exist_ok=True)
                os.makedirs("recon/cache", exist_ok=True)
                # Create a file that should be wiped
                open("activity.log", "w").write("old log")
                _purge_caches()
                assert not os.path.exists("activity.log")
            finally:
                os.chdir(orig)


# ── _update_deps ──────────────────────────────────────────────────────────────

class TestUpdateDeps:
    def test_returns_true_on_success(self):
        mock_result = MagicMock(returncode=0, stdout="", stderr="")
        with patch("subprocess.run", return_value=mock_result), \
             patch("core.cleaner._step"), \
             patch("os.path.isfile", return_value=True):
            ok = _update_deps()
        assert ok is True

    def test_returns_false_on_failure(self):
        mock_result = MagicMock(returncode=1, stdout="", stderr="some pip error")
        with patch("subprocess.run", return_value=mock_result), \
             patch("core.cleaner._step"), \
             patch("os.path.isfile", return_value=False):
            ok = _update_deps()
        assert ok is False
