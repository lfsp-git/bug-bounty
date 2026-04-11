"""
Hunt3r v1.0-EXCALIBUR - Bug Bounty Report Generator
Generates structured Markdown reports from scan findings,
ready for submission to H1, BugCrowd, and Intigriti.
"""
from __future__ import annotations

import json
import os
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

REPORTS_DIR = "reports"

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class BugBountyReporter:
    """Generate submission-ready Markdown reports from Nuclei/JS findings."""

    def __init__(self, handle: str):
        self.handle = handle
        os.makedirs(REPORTS_DIR, exist_ok=True)

    def load_findings(self, findings_path: str) -> List[Dict[str, Any]]:
        """Parse JSONL findings file into list of dicts."""
        findings = []
        if not os.path.exists(findings_path):
            return findings
        try:
            with open(findings_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        logger.debug(f"Skipping malformed JSONL: {e}")
        except OSError as e:
            logger.error(f"Cannot read findings file {findings_path}: {e}")
        return findings

    def load_js_secrets(self, js_secrets_path: str) -> List[str]:
        """Load raw lines from JS secrets file."""
        secrets: List[str] = []
        if not js_secrets_path or not os.path.exists(js_secrets_path):
            return secrets
        try:
            with open(js_secrets_path, 'r', encoding='utf-8', errors='ignore') as f:
                secrets = [l.strip() for l in f if l.strip()]
        except OSError as e:
            logger.error(f"Cannot read JS secrets file: {e}")
        return secrets

    def generate(
        self,
        findings_path: str,
        js_secrets_path: str | None = None,
        subdomains_count: int = 0,
        endpoints_count: int = 0,
    ) -> str:
        """
        Generate full bug bounty report. Returns path to report file.
        """
        findings = self.load_findings(findings_path)
        js_secrets = self.load_js_secrets(js_secrets_path) if js_secrets_path else []

        # Sort by severity
        findings.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "info").lower(), 99))

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(REPORTS_DIR, f"{self.handle}_{timestamp}_report.md")

        report = self._build_report(findings, js_secrets, subdomains_count, endpoints_count)

        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(report)
            logger.info(f"Report saved: {report_path}")
        except OSError as e:
            logger.error(f"Failed to save report: {e}")
            return ""

        return report_path

    def _build_report(
        self,
        findings: List[Dict],
        js_secrets: List[str],
        subdomains_count: int,
        endpoints_count: int,
    ) -> str:
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        lines = []

        # Header
        lines.append(f"# Hunt3r Scan Report — `{self.handle}`")
        lines.append(f"**Generated:** {date_str}  ")
        lines.append(f"**Target:** `{self.handle}`  ")
        lines.append(f"**Tool:** Hunt3r v1.0-EXCALIBUR\n")

        # Summary table
        crits = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
        highs = sum(1 for f in findings if f.get("severity", "").lower() == "high")
        meds = sum(1 for f in findings if f.get("severity", "").lower() == "medium")
        lows = sum(1 for f in findings if f.get("severity", "").lower() == "low")
        infos = sum(1 for f in findings if f.get("severity", "info").lower() == "info")

        lines.append("## 📊 Scan Summary\n")
        lines.append("| Metric | Count |")
        lines.append("|--------|-------|")
        lines.append(f"| Subdomains Found | {subdomains_count} |")
        lines.append(f"| Endpoints Discovered | {endpoints_count} |")
        lines.append(f"| 🔴 Critical | {crits} |")
        lines.append(f"| 🟠 High | {highs} |")
        lines.append(f"| 🟡 Medium | {meds} |")
        lines.append(f"| 🔵 Low | {lows} |")
        lines.append(f"| ⚪ Info | {infos} |")
        lines.append(f"| 🟣 JS Secrets | {len(js_secrets)} |")
        lines.append("")

        # Critical + High findings (full detail for submission)
        priority = [f for f in findings if f.get("severity", "").lower() in ("critical", "high")]
        if priority:
            lines.append("## 🚨 Priority Findings (Critical / High)\n")
            for i, finding in enumerate(priority, 1):
                lines.extend(self._format_finding(i, finding, detailed=True))

        # Medium findings
        medium = [f for f in findings if f.get("severity", "").lower() == "medium"]
        if medium:
            lines.append("## ⚠️ Medium Severity Findings\n")
            for i, finding in enumerate(medium, 1):
                lines.extend(self._format_finding(i, finding, detailed=False))

        # JS Secrets
        if js_secrets:
            lines.append("## 🟣 JS Secrets Discovered\n")
            lines.append("> ⚠️ These may contain API keys, tokens, or credentials. Verify before reporting.\n")
            for secret in js_secrets[:50]:
                lines.append(f"- `{secret}`")
            if len(js_secrets) > 50:
                lines.append(f"\n*...and {len(js_secrets) - 50} more. See full findings file.*")
            lines.append("")

        # Low / Info (brief table)
        low_info = [f for f in findings if f.get("severity", "info").lower() in ("low", "info")]
        if low_info:
            lines.append("## ℹ️ Low / Informational\n")
            lines.append("| Severity | Template | Host | Matched |")
            lines.append("|----------|----------|------|---------|")
            for f in low_info[:30]:
                sev = f.get("severity", "info").upper()
                tid = f.get("template-id", "?")
                host = f.get("host", "?")[:50]
                matched = f.get("matched-at", "?")[:60]
                lines.append(f"| {sev} | `{tid}` | `{host}` | `{matched}` |")
            if len(low_info) > 30:
                lines.append(f"\n*...and {len(low_info) - 30} more.*")
            lines.append("")

        # Submission checklist
        lines.append("## 📋 Submission Checklist\n")
        lines.append("- [ ] Verify Critical/High findings manually (reproduce in browser/Burp)")
        lines.append("- [ ] Remove any sensitive test data before submitting")
        lines.append("- [ ] Check program scope — ensure target is in scope")
        lines.append("- [ ] Write clear reproduction steps for each bug")
        lines.append("- [ ] Attach screenshots/PoC to report")
        lines.append("- [ ] Submit to platform (H1/BC/IT) with CVSS score estimate")
        lines.append("")
        lines.append("---")
        lines.append("*Generated by Hunt3r v1.0-EXCALIBUR — autonomous bug bounty hunter*")

        return "\n".join(lines)

    def _format_finding(self, idx: int, finding: Dict, detailed: bool) -> List[str]:
        sev = finding.get("severity", "info").lower()
        emoji = SEVERITY_EMOJI.get(sev, "⚪")
        tid = finding.get("template-id", "unknown")
        host = finding.get("host", "N/A")
        matched = finding.get("matched-at", "N/A")
        cve = finding.get("info", {}).get("classification", {}).get("cve-id", [])
        cve_str = ", ".join(cve) if cve else "N/A"
        description = finding.get("info", {}).get("description", "")
        remediation = finding.get("info", {}).get("remediation", "")
        name = finding.get("info", {}).get("name", tid)
        refs = finding.get("info", {}).get("reference", [])

        lines = [f"### {emoji} {idx}. {name}\n"]
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| **Severity** | `{sev.upper()}` |")
        lines.append(f"| **Template** | `{tid}` |")
        lines.append(f"| **Host** | `{host}` |")
        lines.append(f"| **Matched At** | `{matched}` |")
        lines.append(f"| **CVE** | `{cve_str}` |")
        lines.append("")

        if description:
            lines.append(f"**Description:** {description}\n")

        if detailed:
            lines.extend(self._submission_ready_block(finding))
            extracted = finding.get("extracted-results", [])
            if extracted:
                lines.append("**Extracted Results:**")
                lines.append("```")
                for r in extracted[:5]:
                    lines.append(str(r)[:200])
                lines.append("```\n")

            curl = finding.get("curl-command", "")
            if curl:
                lines.append("**Reproduction (curl):**")
                lines.append("```bash")
                lines.append(curl[:500])
                lines.append("```\n")

        if remediation:
            lines.append(f"**Remediation:** {remediation}\n")

        if refs and detailed:
            lines.append("**References:**")
            for ref in refs[:3]:
                lines.append(f"- {ref}")
            lines.append("")

        lines.append("---\n")
        return lines

    def _submission_ready_block(self, finding: Dict) -> List[str]:
        """Build a concise submission-ready section for H1/BC style reports."""
        severity = finding.get("severity", "info").upper()
        host = finding.get("host", "N/A")
        matched = finding.get("matched-at", "N/A")
        name = finding.get("info", {}).get("name", finding.get("template-id", "Finding"))
        description = finding.get("info", {}).get("description", "")
        impact = finding.get("info", {}).get("impact", "")

        lines = [
            "**Submission Draft (H1/BC-ready):**",
            "```markdown",
            f"Title: [{severity}] {name} on {host}",
            "",
            "Summary:",
            description or "Security issue detected by automated recon; manual validation required.",
            "",
            "Impact:",
            impact or "Potential security impact depends on target context and exploitability.",
            "",
            "Steps to Reproduce:",
            f"1. Access target: {host}",
            f"2. Trigger/check vector observed at: {matched}",
            "3. Confirm behavior and collect evidence (response/body/status).",
            "",
            "Expected Behavior:",
            "The application should not expose this vulnerable behavior.",
            "",
            "Actual Behavior:",
            "The vulnerable behavior was observable in scan evidence.",
            "```",
            "",
        ]
        return lines
