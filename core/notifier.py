"""
HUNT3R v2.2 - Notifier [Telegram + Discord]
Telegram (Prioridade Maxima): Critical, High, JS secrets
Discord (Monitoramento): Medium, Low, Info, Recon logs
"""

import os
import json
import logging
import requests
from datetime import datetime
from core.ui_manager import ui_log, Colors


class NotifierConfig:
    """ENV vars loaded once at runtime."""

    @staticmethod
    def telegram():
        token = os.getenv("TELEGRAM_BOT_TOKEN")
        chat_id = os.getenv("TELEGRAM_CHAT_ID")
        return (token, chat_id) if token and chat_id else None

    @staticmethod
    def discord():
        return os.getenv("DISCORD_WEBHOOK")


SEV_COLORS = {
    "CRITICAL": 0xFF0000,
    "HIGH": 0xFF4500,
    "MEDIUM": 0xFFFF00,
    "LOW": 0x00FF00,
    "INFO": 0x00BFFF,
}


def _tg_post(token, chat_id, html: str) -> bool:
    """Telegram supports HTML parse mode (safer than Markdown)."""
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        r = requests.post(url, json={
            "chat_id": chat_id,
            "text": html,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }, timeout=10)
        return r.status_code == 200
    except Exception as e:
        logging.error(f"Telegram error: {e}")
        return False


def _dc_post(webhook_url: str, embed: dict) -> bool:
    """Discord webhook with embed payload."""
    payload = {
        "username": "Hunt3r",
        "embeds": [embed],
    }
    try:
        r = requests.post(webhook_url, json=payload, timeout=10)
        return r.status_code == 204
    except Exception as e:
        logging.error(f"Discord error: {e}")
        return False


def _tg_escape(text: str) -> str:
    """Escape characters that break Telegram HTML parse mode."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _build_tg_nuclei_alert(sev, target, tid, matched, cve, is_deep=False):
    """Build HTML-formatted Telegram alert."""
    emoji = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
    }.get(sev, "⚪")

    prefix = "<b>[DEEP-SCAN]</b> " if is_deep else ""
    html = (
        f"{emoji} {prefix}<b>[{sev}] {target}</b>\n"
        f"Template: <code>{tid}</code>\n"
        f"Matched: <code>{matched[:80]}</code>\n"
    )
    if cve and cve != "N/A":
        html += f"CVE: <code>{cve}</code>\n"
    return html


def _build_dc_nuclei_embed(sev, target, tid, matched, cve):
    """Build Discord embed for vulnerability."""
    color = SEV_COLORS.get(sev, 0x808080)
    fields = [
        {"name": "Target", "value": target, "inline": True},
        {"name": "Severity", "value": sev, "inline": True},
        {"name": "Template", "value": tid, "inline": True},
        {"name": "Matched", "value": f"`{matched[:100]}`", "inline": False},
    ]
    if cve and cve != "N/A":
        fields.append({"name": "CVE", "value": cve, "inline": True})
    return {
        "title": f"[{sev}] {target} — {tid}",
        "description": f"Vulnerability detected",
        "color": color,
        "fields": fields,
    }


class NotificationDispatcher:
    """Route vulnerability alerts to Telegram (priority) and Discord (monitoring)."""

    @classmethod
    def alert_nuclei_telegram(cls, findings: list, target: str):
        """Send a list of pre-filtered findings (Medium+/escalated) to Telegram."""
        tg = NotifierConfig.telegram()
        if not tg or not findings:
            return

        for d in findings:
            sev = d.get("severity", "info").upper()
            tid = d.get("template-id", "unknown")
            matched = d.get("matched-at", "")
            cve = d.get("cve-id", "N/A")
            escalated = d.get("_escalated", "")
            report = d.get("_escalation_report", "")
            is_deep = d.get("_deep_scan", False)

            if sev in ("CRITICAL", "HIGH"):
                html = _build_tg_nuclei_alert(sev, target, tid, matched, cve, is_deep)
                _tg_post(tg[0], tg[1], html)
            elif escalated:
                # Escalated finding with simulated severity
                sim_sev = d.get("_simulated_severity", "info").upper()
                prefix = "<b>[DEEP-SCAN]</b> " if is_deep else ""
                html = (
                    f"{prefix}[ESCALATED] <b>Trigger: {escalated}</b>\n"
                    f"Original: {tid} [{sev}]\n"
                    f"Simulated severity: {sim_sev}\n"
                    f"Report:\n<pre>{_tg_escape(report)}</pre>\n"
                )
                _tg_post(tg[0], tg[1], html)
            elif sev == "MEDIUM":
                html = _build_tg_nuclei_alert(sev, target, tid, matched, cve, is_deep)
                _tg_post(tg[0], tg[1], html)

    @classmethod
    def alert_nuclei_discord_batch(cls, findings: list, target: str):
        """Group low-noise Info/Low findings into a single Discord embed."""
        dc = NotifierConfig.discord()
        if not dc or not findings:
            return

        # Build a summary table (max 15 entries to avoid embed overflow)
        entries = []
        for d in findings[:15]:
            sev = d.get("severity", "?").upper()
            tid = d.get("template-id", "unknown")
            matched = d.get("matched-at", "")[:50]
            entries.append(f"`[{sev:>8}]` {tid} — `{matched}`")

        description = "\n".join(entries)
        if len(findings) > 15:
            description += f"\n...e mais {len(findings) - 15} findings (filtrados)."

        embed = {
            "title": f"[Hunt3r Scan Log] {target}",
            "description": description or "Nenhum finding adicional.",
            "color": 0x555555,
            "footer": {"text": f"Total: {len(findings)} | Info/Low batched"},
            "timestamp": datetime.utcnow().isoformat(),
        }
        _dc_post(dc, embed)

    @classmethod
    def alert_nuclei(cls, findings_path, target):
        """
        Legacy: Parse findings and route by severity.
        - Critical/High → Telegram
        - Medium/Low/Info → Discord
        Kept for backward compatibility with Watchdog mode.
        """
        tg = NotifierConfig.telegram()
        dc = NotifierConfig.discord()
        if not tg and not dc:
            return
        if not os.path.exists(findings_path) or os.path.getsize(findings_path) == 0:
            return

        try:
            with open(findings_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    sev = d.get("severity", "info").upper()
                    tid = d.get("template-id", "unknown")
                    matched = d.get("matched-at", "")
                    cve = d.get("cve-id", "N/A")
                    is_deep = d.get("_deep_scan", False)

                    # Telegram: Critical + High
                    if sev in ("CRITICAL", "HIGH") and tg:
                        html = _build_tg_nuclei_alert(sev, target, tid, matched, cve, is_deep)
                        _tg_post(tg[0], tg[1], html)

                    # Discord: all severities for monitoring
                    if dc:
                        embed = _build_dc_nuclei_embed(sev, target, tid, matched, cve)
                        _dc_post(dc, embed)
        except Exception as e:
            logging.error(f"Notifier Nuclei error: {e}")

    @classmethod
    def alert_js_secrets(cls, js_file, target):
        """Send ALL JS secrets to Telegram (they are priority)."""
        tg = NotifierConfig.telegram()
        if not tg:
            return
        if not os.path.exists(js_file) or os.path.getsize(js_file) == 0:
            return

        count = 0
        try:
            with open(js_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    stype = d.get("type", "?")
                    source = d.get("source", "")
                    val = d.get("value", "")[:80]

                    html = (
                        f"🟣 <b>[JS SECRET] {target}</b>\n"
                        f"Type: <code>{stype}</code>\n"
                        f"Source: <code>{source[:80]}</code>\n"
                    )
                    if "_escalation_report" in d:
                        html += f"<b>Validação:</b>\n<pre>{_tg_escape(d['_escalation_report'])}</pre>\n"
                    else:
                        html += f"Value: <code>{val}</code>\n"
                    _tg_post(tg[0], tg[1], html)
                    count += 1
                    if count >= 20:
                        break  # Prevent flood
        except Exception as e:
            logging.error(f"Notifier JS alert error: {e}")

        if count > 0:
            ui_log("NOTIFIER", f"Aliased {count} JS secrets to Telegram.", Colors.SUCCESS)

    @classmethod
    def recon_log(cls, message):
        """Send recon status update to Discord only."""
        dc = NotifierConfig.discord()
        if not dc:
            return
        embed = {
            "title": "Hunt3r Recon Log",
            "description": message,
            "color": 0x3366CC,
            "timestamp": datetime.utcnow().isoformat(),
        }
        _dc_post(dc, embed)

    @staticmethod
    def _finding_files():
        """Yield all known findings file paths (current scan + any residual)."""
        import glob
        for f in glob.glob("recon/db/*/findings*"):
            yield f
        if os.path.exists("findings.txt"):
            yield "findings.txt"
