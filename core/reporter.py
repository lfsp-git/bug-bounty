"""
Hunt3r v1.1-OVERLORD - Bug Bounty Report Generator
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

# CVSS v3.1 base score ranges by template-id keyword for common vuln classes
_CVSS_HINTS: Dict[str, tuple] = {
    "sqli":              ("9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "sql-injection":     ("9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "command-injection": ("9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "rce":               ("9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "xss-stored":        ("8.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"),
    "xss-reflected":     ("6.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "xss":               ("6.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "lfi":               ("7.5", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "file-upload":       ("9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "ssrf":              ("9.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "xxe":               ("9.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "idor":              ("8.1", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    "cors":              ("7.5", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "cors-misconfig":    ("7.5", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "broken-auth":       ("8.1", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    "jwt":               ("8.1", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    "default-login":     ("9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "default-credentials": ("9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "open-redirect":     ("6.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "prototype-pollution": ("6.5", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
    "csrf":              ("6.5", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"),
    "nosql":             ("9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "ssti":              ("9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "info-disclosure":   ("5.3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "exposure":          ("5.3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "misconfig":         ("5.3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
}

_IMPACT_MAP: Dict[str, str] = {
    "sqli":           "An attacker can extract the entire database, bypass authentication, or escalate to OS-level code execution via INTO OUTFILE or xp_cmdshell.",
    "command-injection": "An attacker can execute arbitrary OS commands as the web server user, potentially leading to full system compromise, data exfiltration, and lateral movement.",
    "xss-stored":     "Stored XSS persists across sessions. An attacker can steal session cookies, perform CSRF, redirect users to phishing pages, or install keyloggers.",
    "xss-reflected":  "An attacker can steal session cookies, perform unauthorized actions on behalf of the victim, or redirect to phishing pages via a crafted URL.",
    "lfi":            "An attacker can read arbitrary files from the server, including /etc/passwd, application source code, credentials, and private keys.",
    "file-upload":    "An attacker can upload a web shell and achieve Remote Code Execution as the web server user.",
    "ssrf":           "An attacker can probe internal services, access cloud metadata APIs (AWS/GCP/Azure), pivot to internal network, or bypass authentication.",
    "xxe":            "An attacker can read arbitrary server files, perform SSRF, or trigger denial-of-service via billion-laughs attack.",
    "idor":           "An attacker can access or modify other users' data, perform account takeover, or extract sensitive PII without authorization.",
    "cors-misconfig": "A malicious website can read cross-origin responses, steal authenticated data (tokens, PII), or perform unauthorized actions as any logged-in user.",
    "jwt":            "An attacker can forge authentication tokens to gain unauthorized access, escalate privileges, or impersonate any user including administrators.",
    "default-login":  "An attacker can gain administrative access using publicly known default credentials, leading to full application compromise.",
    "open-redirect":  "An attacker can craft phishing URLs that appear legitimate, redirecting victims to malicious sites to steal credentials or install malware.",
    "csrf":           "An attacker can trick a logged-in user into performing unintended actions (change password, transfer funds, etc.) via a forged request.",
    "nosql":          "An attacker can bypass authentication, extract all database documents, or manipulate queries to access unauthorized data.",
    "ssti":           "An attacker can inject template expressions to achieve Remote Code Execution or read sensitive server-side files.",
    "prototype-pollution": "An attacker can pollute JavaScript prototype chains to alter application behavior, bypass security controls, or achieve XSS/RCE.",
    "exposure":       "Sensitive information exposed may aid further attacks, including credential-based attacks, network mapping, or targeted exploitation.",
}


def _sev(finding: Dict) -> str:
    """Extract severity from a finding, checking both top-level and nested info.severity."""
    return (finding.get("severity") or finding.get("info", {}).get("severity", "info")).lower()


def _cvss_for_tid(tid: str) -> tuple:
    """Return (score_str, vector_str) for a template-id, or ('', '') if unknown."""
    tid_lower = tid.lower()
    for key, val in _CVSS_HINTS.items():
        if key in tid_lower:
            return val
    return ("", "")


def _impact_for_tid(tid: str) -> str:
    """Return impact statement for a template-id."""
    tid_lower = tid.lower()
    for key, val in _IMPACT_MAP.items():
        if key in tid_lower:
            return val
    return ""


class BugBountyReporter:
    """Generate submission-ready Markdown reports from Nuclei/JS findings."""

    def __init__(self, handle: str, platform: str = "unknown"):
        self.handle = handle
        self.platform = platform
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

    def load_js_secrets(self, js_secrets_path: str) -> List[dict]:
        """Load, deduplicate and parse JS secrets. Returns list of dicts."""
        secrets: List[dict] = []
        if not js_secrets_path or not os.path.exists(js_secrets_path):
            return secrets
        try:
            seen: set = set()
            with open(js_secrets_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    raw = line.strip()
                    if not raw:
                        continue
                    try:
                        import json as _json
                        obj = _json.loads(raw)
                        fp = (obj.get("type", ""), obj.get("value", ""), obj.get("source", ""))
                    except Exception:
                        obj = {"type": "unknown", "value": raw, "source": "", "severity": "unknown"}
                        fp = raw
                    if fp not in seen:
                        seen.add(fp)
                        secrets.append(obj)
        except OSError as e:
            logger.error(f"Cannot read JS secrets file: {e}")
        return secrets

    def generate(
        self,
        findings_path: str,
        js_secrets_path: str | None = None,
        subdomains_count: int = 0,
        endpoints_count: int = 0,
        platform: str | None = None,
    ) -> str:
        """
        Generate full bug bounty report. Returns path to report file.
        """
        if platform:
            self.platform = platform
        findings = self.load_findings(findings_path)
        js_secrets = self.load_js_secrets(js_secrets_path) if js_secrets_path else []

        # Only keep medium/high/critical findings in report — info/low are noise
        findings = [f for f in findings if _sev(f) in ("critical", "high", "medium")]

        # Sort by severity
        findings.sort(key=lambda x: SEVERITY_ORDER.get(_sev(x), 99))

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
        js_secrets: List[dict],
        subdomains_count: int,
        endpoints_count: int,
    ) -> str:
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        lines = []

        # Header
        lines.append(f"# Hunt3r Scan Report — `{self.handle}`")
        lines.append(f"**Generated:** {date_str}  ")
        lines.append(f"**Target:** `{self.handle}`  ")
        _platform_label = {
            "h1": "HackerOne", "bc": "Bugcrowd", "it": "Intigriti",
            "ywh": "YesWeHack", "hf": "HackFarm",
            "custom": "Custom (alvos.txt)",
        }.get(str(self.platform).lower(), self.platform.upper() if self.platform not in ("unknown", "") else "Unknown")
        lines.append(f"**Platform:** {_platform_label}  ")
        lines.append(f"**Tool:** Hunt3r v1.1-OVERLORD\n")

        # Summary table
        crits = sum(1 for f in findings if _sev(f) == "critical")
        highs = sum(1 for f in findings if _sev(f) == "high")
        meds = sum(1 for f in findings if _sev(f) == "medium")

        lines.append("## 📊 Scan Summary\n")
        lines.append("| Metric | Count |")
        lines.append("|--------|-------|")
        lines.append(f"| Subdomains Found | {subdomains_count} |")
        lines.append(f"| Endpoints Discovered | {endpoints_count} |")
        lines.append(f"| 🔴 Critical | {crits} |")
        lines.append(f"| 🟠 High | {highs} |")
        lines.append(f"| 🟡 Medium | {meds} |")
        lines.append(f"| 🟣 JS Secrets | {len(js_secrets)} |")
        lines.append("")

        # Executive Summary
        total_vulns = crits + highs + meds
        if total_vulns > 0:
            risk = "CRITICAL" if crits else ("HIGH" if highs else "MEDIUM")
            lines.append("## 🎯 Executive Summary\n")
            lines.append(f"> **Overall Risk: {risk}** — {total_vulns} vulnerabilities found across {self.handle}.\n")

            # Group by vuln class
            from collections import Counter
            classes = Counter()
            for f in findings:
                tid = f.get("template-id", "")
                for key in _CVSS_HINTS:
                    if key in tid.lower():
                        classes[key] += 1
                        break
                else:
                    classes["other"] += 1

            if classes:
                lines.append("**Vulnerability Classes Detected:**\n")
                for vuln_class, count in sorted(classes.items(), key=lambda x: -x[1]):
                    lines.append(f"- `{vuln_class}` — {count} finding(s)")
                lines.append("")

            # Risk narrative
            narratives = []
            if crits:
                narratives.append(f"🔴 **{crits} CRITICAL** findings require immediate remediation — potential for full system compromise.")
            if highs:
                narratives.append(f"🟠 **{highs} HIGH** findings can lead to unauthorized data access or account takeover.")
            if meds:
                narratives.append(f"🟡 **{meds} MEDIUM** findings indicate security misconfigurations that expand attack surface.")
            if js_secrets:
                narratives.append(f"🟣 **{len(js_secrets)} secrets** found in JavaScript — verify each for real exposure risk.")
            for n in narratives:
                lines.append(n + "  ")
            lines.append("")

        # Critical + High findings (full detail for submission)
        priority = [f for f in findings if _sev(f) in ("critical", "high")]
        if priority:
            lines.append("## 🚨 Priority Findings (Critical / High)\n")
            for i, finding in enumerate(priority, 1):
                lines.extend(self._format_finding(i, finding, detailed=True))

        # Medium findings
        medium = [f for f in findings if _sev(f) == "medium"]
        if medium:
            lines.append("## ⚠️ Medium Severity Findings\n")
            for i, finding in enumerate(medium, 1):
                lines.extend(self._format_finding(i, finding, detailed=False))

        # JS Secrets
        if js_secrets:
            _SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "unknown": "⚪"}
            lines.append("## 🟣 JS Secrets Discovered\n")
            lines.append("> ⚠️ These may contain API keys, tokens, or credentials. Verify before reporting.\n")
            _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
            sorted_secrets = sorted(js_secrets[:50], key=lambda s: _sev_order.get(str(s.get("severity", "unknown")).lower(), 4))
            for s in sorted_secrets:
                stype = s.get("type", "unknown").replace("_", " ").title()
                sval = s.get("value", "").strip()
                src = s.get("url") or s.get("source", "")
                sev = str(s.get("severity", "unknown")).lower()
                icon = _SEV_ICON.get(sev, "⚪")
                lines.append(f"- {icon} **{stype}**: `{sval}`")
                if src:
                    lines.append(f"  - Source: {src}")
            if len(js_secrets) > 50:
                lines.append(f"\n*...and {len(js_secrets) - 50} more. See full findings file.*")
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
        lines.append("*Generated by Hunt3r v1.1-OVERLORD — autonomous bug bounty hunter*")

        return "\n".join(lines)

    def _format_finding(self, idx: int, finding: Dict, detailed: bool) -> List[str]:
        sev = _sev(finding)
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
        cvss_score, cvss_vector = _cvss_for_tid(tid)
        impact = finding.get("info", {}).get("impact", "") or _impact_for_tid(tid)

        lines = [f"### {emoji} {idx}. {name}\n"]
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| **Severity** | `{sev.upper()}` |")
        if cvss_score:
            lines.append(f"| **CVSS Score** | `{cvss_score}` |")
        lines.append(f"| **Template** | `{tid}` |")
        lines.append(f"| **Host** | `{host}` |")
        lines.append(f"| **Matched At** | `{matched}` |")
        lines.append(f"| **CVE** | `{cve_str}` |")
        if cvss_vector:
            lines.append(f"| **CVSS Vector** | `{cvss_vector}` |")
        lines.append("")

        if description:
            lines.append(f"**Description:** {description}\n")

        if impact:
            lines.append(f"**Impact:** {impact}\n")

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
        severity = _sev(finding).upper()
        host = finding.get("host", "N/A")
        matched = finding.get("matched-at", "N/A")
        name = finding.get("info", {}).get("name", finding.get("template-id", "Finding"))
        description = finding.get("info", {}).get("description", "")
        impact = finding.get("info", {}).get("impact", "") or _impact_for_tid(finding.get("template-id", ""))
        tid = finding.get("template-id", "")
        extracted = finding.get("extracted-results", [])
        curl = finding.get("curl-command", "")

        # Build PoC steps
        poc_steps = [
            f"1. Navigate to: `{matched}`",
            "2. Observe the vulnerability trigger (check response body/headers/status).",
        ]
        if curl:
            poc_steps.append(f"3. Reproduce with:\n   ```bash\n   {curl[:300]}\n   ```")
        else:
            poc_steps.append(f"3. Use the following curl command or Burp Suite to reproduce.")
        if extracted:
            poc_steps.append(f"4. Evidence — extracted results: `{str(extracted[0])[:100]}`")

        lines = [
            "**Submission Draft (H1/BC-ready):**",
            "```markdown",
            f"Title: [{severity}] {name} on {host}",
            "",
            "Summary:",
            description or "Security vulnerability detected during automated reconnaissance.",
            "",
            "Impact:",
            impact or "Potential security impact — manual validation required to confirm exploitability.",
            "",
            "Steps to Reproduce:",
        ]
        lines.extend(poc_steps)
        lines += [
            "",
            "Expected Behavior:",
            "The application should not be vulnerable to this attack vector.",
            "",
            "Actual Behavior:",
            f"The vulnerable behavior was confirmed at: {matched}",
            "```",
            "",
        ]
        return lines
