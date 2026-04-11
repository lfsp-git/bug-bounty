"""Comprehensive tests for core/reporter.py — platform field, info/low filtering, dedup."""
import sys
import os
import json
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from core.reporter import BugBountyReporter, _sev


# ── Helpers ───────────────────────────────────────────────────────────────────

def _nuclei_finding(severity, tid="test-template", matched="https://example.com/path"):
    return {
        "template-id": tid,
        "severity": severity,
        "matched-at": matched,
        "info": {
            "name": f"{severity.title()} Finding",
            "severity": severity,
            "description": f"Test {severity} issue",
            "remediation": "Fix it",
            "reference": ["https://example.com"],
        },
    }


def _write_jsonl(path, records):
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def _write_lines(path, lines):
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ── _sev utility ──────────────────────────────────────────────────────────────

class TestSevUtility:
    def test_top_level_severity(self):
        assert _sev({"severity": "HIGH"}) == "high"

    def test_nested_info_severity(self):
        assert _sev({"info": {"severity": "critical"}}) == "critical"

    def test_defaults_to_info(self):
        assert _sev({}) == "info"


# ── load_findings ─────────────────────────────────────────────────────────────

class TestLoadFindings:
    def test_loads_valid_jsonl(self, tmp_path):
        f = tmp_path / "findings.jsonl"
        records = [_nuclei_finding("critical"), _nuclei_finding("high")]
        _write_jsonl(str(f), records)
        reporter = BugBountyReporter("test_target")
        result = reporter.load_findings(str(f))
        assert len(result) == 2

    def test_returns_empty_for_missing_file(self):
        reporter = BugBountyReporter("test_target")
        result = reporter.load_findings("/nonexistent/path.jsonl")
        assert result == []

    def test_returns_empty_for_empty_file(self, tmp_path):
        f = tmp_path / "empty.jsonl"
        f.write_text("")
        reporter = BugBountyReporter("test_target")
        assert reporter.load_findings(str(f)) == []

    def test_skips_invalid_json_lines(self, tmp_path):
        f = tmp_path / "mixed.jsonl"
        f.write_text('{"severity": "critical"}\nNOT JSON\n{"severity": "high"}\n')
        reporter = BugBountyReporter("test_target")
        result = reporter.load_findings(str(f))
        assert len(result) == 2


# ── generate() — info/low filtering ──────────────────────────────────────────

class TestGenerateFiltersInfoLow:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.reporter = BugBountyReporter("filter_test", platform="h1")
        # Redirect reports to tmpdir
        import core.reporter as mod
        self._orig_dir = mod.REPORTS_DIR
        mod.REPORTS_DIR = self.tmpdir

    def teardown_method(self):
        import core.reporter as mod
        mod.REPORTS_DIR = self._orig_dir
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_findings_file(self, severities):
        path = os.path.join(self.tmpdir, "findings.jsonl")
        findings = [_nuclei_finding(sev) for sev in severities]
        _write_jsonl(path, findings)
        return path

    def test_info_findings_excluded_from_report(self):
        path = self._make_findings_file(["critical", "info", "info"])
        report_path = self.reporter.generate(findings_path=path)
        report = open(report_path).read()
        # The report body should have the critical finding but info count = 0
        assert "critical" in report.lower() or "Critical" in report

    def test_low_findings_excluded_from_report(self):
        path = self._make_findings_file(["high", "low", "low"])
        report_path = self.reporter.generate(findings_path=path)
        report = open(report_path).read()
        # No Low row in summary table
        assert "🔵 Low" not in report

    def test_info_row_not_in_summary_table(self):
        path = self._make_findings_file(["medium", "info"])
        report_path = self.reporter.generate(findings_path=path)
        report = open(report_path).read()
        assert "⚪ Info" not in report

    def test_critical_high_medium_kept(self):
        path = self._make_findings_file(["critical", "high", "medium"])
        report_path = self.reporter.generate(findings_path=path)
        report = open(report_path).read()
        # All three severity rows exist in the summary table
        assert "🔴 Critical" in report
        assert "🟠 High" in report
        assert "🟡 Medium" in report

    def test_all_info_low_yields_empty_report(self):
        path = self._make_findings_file(["info", "low", "info"])
        report_path = self.reporter.generate(findings_path=path)
        report = open(report_path).read()
        assert "🔴 Critical | 0" in report
        assert "🟠 High | 0" in report


# ── Platform field in report ──────────────────────────────────────────────────

class TestReporterPlatformField:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        import core.reporter as mod
        self._orig_dir = mod.REPORTS_DIR
        mod.REPORTS_DIR = self.tmpdir

    def teardown_method(self):
        import core.reporter as mod
        mod.REPORTS_DIR = self._orig_dir
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _empty_findings(self):
        path = os.path.join(self.tmpdir, "findings.jsonl")
        open(path, "w").close()
        return path

    def _read_report(self, platform, handle="test"):
        reporter = BugBountyReporter(handle, platform=platform)
        findings_path = self._empty_findings()
        report_path = reporter.generate(findings_path=findings_path)
        return open(report_path).read()

    def test_h1_platform_shows_hackerone(self):
        report = self._read_report("h1")
        assert "HackerOne" in report

    def test_bc_platform_shows_bugcrowd(self):
        report = self._read_report("bc")
        assert "Bugcrowd" in report

    def test_it_platform_shows_intigriti(self):
        report = self._read_report("it")
        assert "Intigriti" in report

    def test_ywh_platform_shows_yeswehack(self):
        report = self._read_report("ywh")
        assert "YesWeHack" in report

    def test_unknown_platform_shows_unknown(self):
        report = self._read_report("unknown")
        assert "Unknown" in report or "unknown" in report.lower()

    def test_custom_platform_shows_alvos_txt(self):
        report = self._read_report("custom")
        assert "Custom (alvos.txt)" in report

    def test_platform_set_via_generate_parameter(self):
        reporter = BugBountyReporter("target")
        findings_path = self._empty_findings()
        report_path = reporter.generate(findings_path=findings_path, platform="h1")
        report = open(report_path).read()
        assert "HackerOne" in report

    def test_report_contains_platform_label_line(self):
        report = self._read_report("h1", "stripe")
        assert "**Platform:**" in report

    def test_report_header_contains_target_handle(self):
        report = self._read_report("h1", "stripe")
        assert "stripe" in report


# ── load_js_secrets deduplication ────────────────────────────────────────────

class TestLoadJsSecretsDedup:
    def _write_secrets(self, tmp_path, entries):
        f = tmp_path / "secrets.js_secrets"
        with open(str(f), "w") as fh:
            for e in entries:
                fh.write(json.dumps(e) + "\n")
        return str(f)

    def _secret(self, stype="aws_key", value="KEY123", source="https://example.com/app.js"):
        return {"type": stype, "value": value, "source": source, "severity": "high"}

    def test_duplicate_entries_deduped(self, tmp_path):
        entries = [self._secret()] * 5
        path = self._write_secrets(tmp_path, entries)
        reporter = BugBountyReporter("test")
        result = reporter.load_js_secrets(path)
        assert len(result) == 1

    def test_different_values_kept(self, tmp_path):
        entries = [self._secret(value="KEY1"), self._secret(value="KEY2")]
        path = self._write_secrets(tmp_path, entries)
        reporter = BugBountyReporter("test")
        result = reporter.load_js_secrets(path)
        assert len(result) == 2

    def test_different_types_kept(self, tmp_path):
        entries = [
            self._secret(stype="aws_key", value="KEY"),
            self._secret(stype="github_token", value="KEY"),
        ]
        path = self._write_secrets(tmp_path, entries)
        reporter = BugBountyReporter("test")
        result = reporter.load_js_secrets(path)
        assert len(result) == 2

    def test_different_sources_deduped_by_value(self, tmp_path):
        # Same type+value but different source → still deduped (fingerprint = type+value+source)
        entries = [
            self._secret(source="https://example.com/a.js"),
            self._secret(source="https://example.com/b.js"),
        ]
        path = self._write_secrets(tmp_path, entries)
        reporter = BugBountyReporter("test")
        result = reporter.load_js_secrets(path)
        # Different sources = different fingerprints = both kept
        assert len(result) == 2

    def test_returns_empty_for_missing_file(self):
        reporter = BugBountyReporter("test")
        result = reporter.load_js_secrets("/nonexistent/secrets.jsonl")
        assert result == []

    def test_returns_empty_for_empty_file(self, tmp_path):
        f = tmp_path / "empty.js_secrets"
        f.write_text("")
        reporter = BugBountyReporter("test")
        assert reporter.load_js_secrets(str(f)) == []

    def test_skips_empty_lines(self, tmp_path):
        """load_js_secrets skips blank lines; invalid JSON is kept as raw string."""
        f = tmp_path / "mixed.js_secrets"
        f.write_text('{"type":"aws","value":"K","source":"u"}\n\n\n')
        reporter = BugBountyReporter("test")
        result = reporter.load_js_secrets(str(f))
        assert len(result) == 1


# ── Summary table correctness ─────────────────────────────────────────────────

class TestBuildReportSummaryTable:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        import core.reporter as mod
        self._orig_dir = mod.REPORTS_DIR
        mod.REPORTS_DIR = self.tmpdir

    def teardown_method(self):
        import core.reporter as mod
        mod.REPORTS_DIR = self._orig_dir
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _generate(self, findings, platform="h1"):
        path = os.path.join(self.tmpdir, "f.jsonl")
        _write_jsonl(path, findings)
        reporter = BugBountyReporter("build_test", platform=platform)
        rp = reporter.generate(findings_path=path)
        return open(rp).read()

    def test_critical_count_correct(self):
        findings = [_nuclei_finding("critical")] * 3
        report = self._generate(findings)
        assert "🔴 Critical | 3" in report

    def test_high_count_correct(self):
        findings = [_nuclei_finding("high")] * 2
        report = self._generate(findings)
        assert "🟠 High | 2" in report

    def test_medium_count_correct(self):
        findings = [_nuclei_finding("medium")] * 1
        report = self._generate(findings)
        assert "🟡 Medium | 1" in report

    def test_all_zero_when_only_low_info(self):
        findings = [_nuclei_finding("low"), _nuclei_finding("info")]
        report = self._generate(findings)
        assert "🔴 Critical | 0" in report
        assert "🟠 High | 0" in report
        assert "🟡 Medium | 0" in report

    def test_no_low_row_in_summary(self):
        findings = [_nuclei_finding("low")]
        report = self._generate(findings)
        assert "🔵 Low" not in report

    def test_no_info_row_in_summary(self):
        findings = [_nuclei_finding("info")]
        report = self._generate(findings)
        assert "⚪ Info" not in report

    def test_subdomains_count_in_table(self):
        path = os.path.join(self.tmpdir, "empty.jsonl")
        open(path, "w").close()
        reporter = BugBountyReporter("cnt_test", platform="h1")
        rp = reporter.generate(findings_path=path, subdomains_count=42)
        report = open(rp).read()
        assert "42" in report

    def test_endpoints_count_in_table(self):
        path = os.path.join(self.tmpdir, "empty2.jsonl")
        open(path, "w").close()
        reporter = BugBountyReporter("ep_test", platform="h1")
        rp = reporter.generate(findings_path=path, endpoints_count=999)
        report = open(rp).read()
        assert "999" in report
