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
from core.ui import ui_log, Colors
from core.config import NOTIFY_DEDUP_CACHE_FILE, NOTIFY_DEDUP_TTL_SECONDS


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


def _load_dedup_cache() -> dict:
    try:
        if os.path.exists(NOTIFY_DEDUP_CACHE_FILE):
            with open(NOTIFY_DEDUP_CACHE_FILE, "r", encoding="utf-8") as f:
                payload = json.load(f)
                if isinstance(payload, dict):
                    return payload
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def _save_dedup_cache(cache: dict) -> None:
    try:
        os.makedirs(os.path.dirname(NOTIFY_DEDUP_CACHE_FILE), exist_ok=True)
        with open(NOTIFY_DEDUP_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f)
    except OSError as e:
        logging.debug(f"Notifier dedup cache save failed: {e}")


def _is_duplicate_and_record(key: str) -> bool:
    now = int(datetime.utcnow().timestamp())
    cache = _load_dedup_cache()
    # prune expired entries
    fresh = {
        k: ts for k, ts in cache.items()
        if isinstance(ts, int) and (now - ts) < NOTIFY_DEDUP_TTL_SECONDS
    }
    last_ts = fresh.get(key)
    if isinstance(last_ts, int) and (now - last_ts) < NOTIFY_DEDUP_TTL_SECONDS:
        _save_dedup_cache(fresh)
        return True
    fresh[key] = now
    _save_dedup_cache(fresh)
    return False


def _build_tg_nuclei_alert(sev, target, tid, matched, cve, is_deep=False):
    """Build HTML-formatted Telegram alert."""
    emoji = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
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
                dedup_key = f"tg:nuclei:{target}:{sev}:{tid}:{matched[:120]}"
                if _is_duplicate_and_record(dedup_key):
                    continue
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
                dedup_key = f"tg:escalated:{target}:{escalated}:{tid}"
                if _is_duplicate_and_record(dedup_key):
                    continue
                _tg_post(tg[0], tg[1], html)
            elif sev == "MEDIUM":
                dedup_key = f"tg:nuclei:{target}:{sev}:{tid}:{matched[:120]}"
                if _is_duplicate_and_record(dedup_key):
                    continue
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

                    # Telegram: Critical + High + Medium
                    if sev in ("CRITICAL", "HIGH", "MEDIUM") and tg:
                        dedup_key = f"tg:nuclei:{target}:{sev}:{tid}:{matched[:120]}"
                        if _is_duplicate_and_record(dedup_key):
                            continue
                        html = _build_tg_nuclei_alert(sev, target, tid, matched, cve, is_deep)
                        _tg_post(tg[0], tg[1], html)

                    # Discord: Low + Info (monitoring)
                    if sev in ("LOW", "INFO") and dc:
                        embed = _build_dc_nuclei_embed(sev, target, tid, matched, cve)
                        _dc_post(dc, embed)
        except Exception as e:
            logging.error(f"Notifier Nuclei error: {e}")

    @classmethod
    def alert_js_secrets(cls, js_file, target):
        """Route JS secrets by severity: Critical/High/Medium → Telegram, Low → Discord."""
        tg = NotifierConfig.telegram()
        dc = NotifierConfig.discord()
        if not tg and not dc:
            return
        if not os.path.exists(js_file) or os.path.getsize(js_file) == 0:
            return

        tg_count = 0
        dc_count = 0
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
                    source = d.get("source", d.get("url", ""))
                    val = d.get("value", "")[:80]
                    severity = d.get("severity", "low").upper()

                    if severity in ("CRITICAL", "HIGH", "MEDIUM") and tg:
                        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(severity, "🟣")
                        html = (
                            f"{emoji} <b>[JS SECRET] [{severity}] {target}</b>\n"
                            f"Type: <code>{_tg_escape(stype)}</code>\n"
                            f"Source: <code>{_tg_escape(source[:80])}</code>\n"
                            f"Value: <code>{_tg_escape(val)}</code>\n"
                        )
                        dedup_key = f"tg:js:{target}:{severity}:{stype}:{source[:120]}:{val[:80]}"
                        if _is_duplicate_and_record(dedup_key):
                            continue
                        _tg_post(tg[0], tg[1], html)
                        tg_count += 1
                    elif dc:
                        dedup_key = f"dc:js:{target}:{severity}:{stype}:{source[:120]}:{val[:80]}"
                        if _is_duplicate_and_record(dedup_key):
                            continue
                        embed = {
                            "title": f"[JS Secret] {target}",
                            "description": f"Type: `{stype}`\nSource: `{source[:80]}`\nValue: `{val}`",
                            "color": 0x9B59B6,
                        }
                        _dc_post(dc, embed)
                        dc_count += 1

                    if tg_count + dc_count >= 30:
                        break  # Prevent flood
        except Exception as e:
            logging.error(f"Notifier JS alert error: {e}")

        total = tg_count + dc_count
        if total > 0:
            ui_log("NOTIFIER", f"JS secrets: {tg_count} → Telegram, {dc_count} → Discord", Colors.SUCCESS)

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
