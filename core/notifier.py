"""
HUNT3R v2.3 - Notifier [Telegram + Discord]

Telegram (High-priority findings only):
  - Critical, High, Medium vulnerabilities
  - JS secrets (Critical/High/Medium)

Discord (Operational monitoring):
  - Scan completion statistics per target
  - Watchdog heartbeat / rain-check messages
  - Error alerts
  - NO individual vulnerability details (keeps Discord clean)
"""

import os
import re
import json
import logging
import hashlib
import requests
from datetime import datetime, timezone
from core.ui import ui_log, Colors
from core.config import (
    NOTIFY_DEDUP_CACHE_FILE,
    NOTIFY_DEDUP_TTL_SECONDS,
    NOTIFY_CROSS_PROGRAM_DEDUP,
)


def _get_sev(finding: dict, default: str = "info") -> str:
    """Extract severity, checking top-level then info.severity for nuclei v2/v3 compat."""
    return (finding.get("severity") or finding.get("info", {}).get("severity", default)).lower()


_PROBE_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
_PROBE_INTERESTING_KEYS = re.compile(
    r'"(?:data|users|user|email|token|key|secret|password|id|access|auth|admin|'
    r'config|internal|debug|settings|api_key|api_token|refresh_token|session|'
    r'results|items|records|accounts|credentials)["\s:]',
    re.I,
)
_PROBE_SENSITIVE_PATHS = ("/admin", "/debug", "/internal", "/config", "/settings", "/graphql")


def _probe_generic_url(url: str) -> str:
    """
    Probe a URL without authentication headers.
    Returns 'escalate' if endpoint responds 200 with interesting/sensitive content.
    Returns 'skip' for everything else (auth-required, errors, non-JSON noise).
    """
    try:
        resp = requests.get(
            url,
            timeout=8,
            allow_redirects=True,
            headers={"User-Agent": _PROBE_UA},
        )
        if resp.status_code != 200:
            return "skip"
        body = resp.text[:4096]
        content_type = resp.headers.get("Content-Type", "")
        is_json = "json" in content_type or body.lstrip()[:1] in ("{", "[")
        if not is_json:
            return "skip"
        if _PROBE_INTERESTING_KEYS.search(body):
            return "escalate"
        # Even without matching keys, sensitive paths returning 200+JSON are worth alerting
        url_lower = url.lower()
        if any(p in url_lower for p in _PROBE_SENSITIVE_PATHS):
            return "escalate"
        return "skip"
    except Exception:
        return "skip"


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


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


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


def _prune_dedup_cache(cache: dict, now: int) -> dict:
    return {
        k: ts for k, ts in cache.items()
        if isinstance(ts, int) and (now - ts) < NOTIFY_DEDUP_TTL_SECONDS
    }


def _canonical_text(value, max_len: int = 240) -> str:
    if value is None:
        return ""
    return " ".join(str(value).strip().lower().split())[:max_len]


def _hashed_dedup_key(prefix: str, *parts) -> str:
    canonical = "|".join(_canonical_text(p) for p in parts if _canonical_text(p))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]
    return f"{prefix}:{digest}"


def _is_duplicate_and_record_keys(keys: list[str]) -> bool:
    now = int(_utc_now().timestamp())
    cache = _load_dedup_cache()
    fresh = _prune_dedup_cache(cache, now)
    if any(isinstance(fresh.get(k), int) and (now - fresh[k]) < NOTIFY_DEDUP_TTL_SECONDS for k in keys):
        _save_dedup_cache(fresh)
        return True
    for key in keys:
        fresh[key] = now
    _save_dedup_cache(fresh)
    return False


def _dedup_keys(prefix: str, legacy_key: str, target: str | None = None, *parts) -> list[str]:
    keys = [_hashed_dedup_key(prefix, target or "", *parts), legacy_key]
    if NOTIFY_CROSS_PROGRAM_DEDUP:
        keys.append(_hashed_dedup_key(f"{prefix}:global", *parts))
    return keys


def _is_duplicate_and_record(key: str) -> bool:
    return _is_duplicate_and_record_keys([key])


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
            sev = _get_sev(d, "info").upper()
            tid = d.get("template-id", "unknown")
            matched = d.get("matched-at", "")
            cve = d.get("cve-id", "N/A")
            escalated = d.get("_escalated", "")
            report = d.get("_escalation_report", "")
            is_deep = d.get("_deep_scan", False)

            if sev in ("CRITICAL", "HIGH"):
                legacy_key = f"tg:nuclei:{target}:{sev}:{tid}:{matched[:120]}"
                if _is_duplicate_and_record_keys(_dedup_keys("tg:nuclei", legacy_key, target, sev, tid, matched, cve)):
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
                legacy_key = f"tg:escalated:{target}:{escalated}:{tid}"
                if _is_duplicate_and_record_keys(_dedup_keys("tg:escalated", legacy_key, target, escalated, tid, sim_sev)):
                    continue
                _tg_post(tg[0], tg[1], html)
            elif sev == "MEDIUM":
                legacy_key = f"tg:nuclei:{target}:{sev}:{tid}:{matched[:120]}"
                if _is_duplicate_and_record_keys(_dedup_keys("tg:nuclei", legacy_key, target, sev, tid, matched, cve)):
                    continue
                html = _build_tg_nuclei_alert(sev, target, tid, matched, cve, is_deep)
                _tg_post(tg[0], tg[1], html)

    @classmethod
    def alert_nuclei_discord_batch(cls, findings: list, target: str):
        """Deprecated: Info/Low findings are dropped. Kept for backward compatibility."""
        pass  # Low/Info no longer sent to Discord

    @classmethod
    def alert_nuclei(cls, findings_path, target):
        """
        Parse findings file and route by severity to Telegram only.
        Critical/High/Medium → Telegram.
        Info/Low → dropped (no Discord spam).
        """
        tg = NotifierConfig.telegram()
        if not tg:
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

                    sev = _get_sev(d, "info").upper()
                    if sev not in ("CRITICAL", "HIGH", "MEDIUM"):
                        continue

                    tid = d.get("template-id", "unknown")
                    matched = d.get("matched-at", "")
                    cve = d.get("cve-id", "N/A")
                    is_deep = d.get("_deep_scan", False)

                    legacy_key = f"tg:nuclei:{target}:{sev}:{tid}:{matched[:120]}"
                    if _is_duplicate_and_record_keys(_dedup_keys("tg:nuclei", legacy_key, target, sev, tid, matched, cve)):
                        continue
                    html = _build_tg_nuclei_alert(sev, target, tid, matched, cve, is_deep)
                    _tg_post(tg[0], tg[1], html)
        except Exception as e:
            logging.error(f"Notifier Nuclei error: {e}")

    @classmethod
    def alert_js_secrets(cls, js_file, target):
        """Route JS secrets: Critical/High/Medium → Telegram only. Low → dropped."""
        tg = NotifierConfig.telegram()
        if not tg:
            return
        if not os.path.exists(js_file) or os.path.getsize(js_file) == 0:
            return

        tg_count = 0
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

                    # Probe generic_url_params before notifying
                    if stype == "generic_url_param":
                        probe = _probe_generic_url(val)
                        if probe == "skip":
                            continue
                        severity = "HIGH"

                    if severity not in ("CRITICAL", "HIGH", "MEDIUM"):
                        continue  # drop low/info secrets

                    emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(severity, "🟣")
                    html = (
                        f"{emoji} <b>[JS SECRET] [{severity}] {target}</b>\n"
                        f"Type: <code>{_tg_escape(stype)}</code>\n"
                        f"Source: <code>{_tg_escape(source[:80])}</code>\n"
                        f"Value: <code>{_tg_escape(val)}</code>\n"
                    )
                    legacy_key = f"tg:js:{target}:{severity}:{stype}:{source[:120]}:{val[:80]}"
                    if _is_duplicate_and_record_keys(_dedup_keys("tg:js", legacy_key, target, severity, stype, source, val)):
                        continue
                    _tg_post(tg[0], tg[1], html)
                    tg_count += 1

                    if tg_count >= 30:
                        break  # Prevent flood
        except Exception as e:
            logging.error(f"Notifier JS alert error: {e}")

        if tg_count > 0:
            ui_log("NOTIFIER", f"JS secrets: {tg_count} → Telegram", Colors.SUCCESS)

    @classmethod
    def alert_scan_complete(cls, target: str, platform: str, results: dict):
        """Send scan statistics summary to Discord.

        Posted after every mission — gives rain-check visibility without
        flooding with individual vuln details.
        """
        dc = NotifierConfig.discord()
        if not dc:
            return

        _PLATFORM_NAMES = {
            "h1": "HackerOne", "bc": "Bugcrowd", "it": "Intigriti",
            "ywh": "YesWeHack", "hf": "HackFarm",
        }
        platform_label = _PLATFORM_NAMES.get(str(platform).lower(), platform.upper() if platform and platform != "unknown" else "Custom")

        subs   = results.get("subdomains", 0)
        live   = results.get("live_hosts", results.get("endpoints", 0))
        eps    = results.get("endpoints", 0)
        sec    = results.get("js_secrets", 0)
        vulns  = results.get("vulnerabilities", 0)
        errors = len(results.get("errors", []))

        # Severity breakdown
        sev = results.get("severity_counts", {})
        crits = sev.get("critical", 0)
        highs = sev.get("high", 0)
        meds  = sev.get("medium", 0)

        # Status indicator
        if errors:
            status_color = 0xFF4500   # orange = ran with errors
            status_icon  = "⚠️"
        elif crits or highs:
            status_color = 0xFF0000   # red = critical/high found
            status_icon  = "🔴"
        elif meds or sec:
            status_color = 0xFFFF00   # yellow = medium/secrets found
            status_icon  = "🟡"
        else:
            status_color = 0x2ECC71   # green = clean
            status_icon  = "✅"

        desc_lines = [
            f"📡 **Subdomains:** {subs}",
            f"🌐 **Hosts ativos:** {live}",
            f"🔗 **Endpoints:** {eps}",
            f"🟣 **JS Secrets:** {sec}",
        ]
        if crits or highs or meds:
            vuln_parts = []
            if crits: vuln_parts.append(f"🔴 {crits} Critical")
            if highs: vuln_parts.append(f"🟠 {highs} High")
            if meds:  vuln_parts.append(f"🟡 {meds} Medium")
            desc_lines.append(f"🐛 **Vulns:** {' · '.join(vuln_parts)}")
        else:
            desc_lines.append(f"🐛 **Vulns:** 0")
        if errors:
            desc_lines.append(f"⚠️ **Erros de fase:** {errors}")

        embed = {
            "title": f"{status_icon} Hunt3r — {target}",
            "description": "\n".join(desc_lines),
            "color": status_color,
            "fields": [
                {"name": "Plataforma", "value": platform_label, "inline": True},
                {"name": "Target", "value": f"`{target}`", "inline": True},
            ],
            "footer": {"text": "Hunt3r EXCALIBUR · Watchdog"},
            "timestamp": _utc_now().isoformat(),
        }
        _dc_post(dc, embed)

    @classmethod
    def alert_watchdog_heartbeat(cls, cycle: int, targets_scanned: int,
                                  errors: int, avg_recon_s: float, avg_vuln_s: float,
                                  next_cycle_in: str = ""):
        """Discord rain-check: confirms watchdog is alive and reports cycle metrics."""
        dc = NotifierConfig.discord()
        if not dc:
            return

        color = 0xFF4500 if errors else 0x3498DB  # orange if errors, blue otherwise
        icon  = "⚠️" if errors else "🤖"

        desc = (
            f"📊 **Ciclo #{cycle}** concluído\n"
            f"🎯 Alvos escaneados: **{targets_scanned}**\n"
            f"⏱ Avg recon: **{avg_recon_s:.0f}s** · Avg vuln: **{avg_vuln_s:.0f}s**\n"
        )
        if errors:
            desc += f"⚠️ Erros: **{errors}**\n"
        if next_cycle_in:
            desc += f"😴 Próximo ciclo em: **{next_cycle_in}**"

        embed = {
            "title": f"{icon} Hunt3r Watchdog — Rain-Check",
            "description": desc,
            "color": color,
            "footer": {"text": "Hunt3r EXCALIBUR · Watchdog"},
            "timestamp": _utc_now().isoformat(),
        }
        _dc_post(dc, embed)

    @classmethod
    def alert_watchdog_error(cls, message: str):
        """Discord alert for critical watchdog errors."""
        dc = NotifierConfig.discord()
        if not dc:
            return
        embed = {
            "title": "🚨 Hunt3r — Erro Crítico",
            "description": f"```\n{message[:1900]}\n```",
            "color": 0xFF0000,
            "footer": {"text": "Hunt3r EXCALIBUR · Watchdog"},
            "timestamp": _utc_now().isoformat(),
        }
        _dc_post(dc, embed)

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
            "timestamp": _utc_now().isoformat(),
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
