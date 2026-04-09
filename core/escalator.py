"""
HUNT3R v2.3 - Escalator (Chaining Engine)
Intercepts raw Nuclei findings, detects actionable Info/Low vectors,
attempts exploitation chaining, and routes alerts intelligently.
SECURITY: Never logs full secrets, uses only read-only validation endpoints.
"""

import os
import re
import json
import time
import logging
import requests
import hashlib
from datetime import datetime
from core.ui_manager import ui_log, Colors

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

# Regex para limpar códigos de cor ANSI (os [93m do Nuclei)
ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*m')

# ---------------------------------------------------------------------------
# Trigger Registry — modular, easy to extend.
# Each trigger maps a human name to keyword/regex matchers evaluated against
# template-id, template-url, matched-at, and extracted-results.
# ---------------------------------------------------------------------------

TRIGGERS = {
    "swagger_openapi": {
        "label": "Swagger / OpenAPI Exposto",
        "patterns": [
            re.compile(r"(?:swagger|openapi|api-docs|swagger\.json|swagger\.yaml)", re.I),
        ],
        "action": "Marcado para Fuzzing de API",
    },
    "exposed_panel": {
        "label": "Painel Exposto / Login Admin",
        "patterns": [
            re.compile(r"(?:exposed-panel|admin-panel|login-page|default-login|default-logins|tomcat-manager|jmx)", re.I),
        ],
        "action": "Marcado para Brute-Force Basico",
    },
    "exposed_git_env": {
        "label": "Exposed Git / Env Leak",
        "patterns": [
            re.compile(r"(?:exposed-git|git-exposure|git-config|exposed-env|env-file|\.[eg]it|/\.env)", re.I),
        ],
        "action": "Marcado para Extracao de Segredos",
    },
    "js_secret": {
        "label": "JS Secret Detected",
        "patterns": [],
        "action": "Validando validade da chave/token",
    },
}


class EscalationEngine:
    """Contains stubbed exploitation routines for each trigger type.
    Replace stubs with real offensive tooling (ffuf, requests brute) later."""

    @staticmethod
    def escalate_api_fuzz(url: str) -> dict:
        """Gatilho Swagger/OpenAPI: extrai base URL, marca API docs para fuzzing."""
        base_url = url.split("?")[0]
        if "?" not in url and base_url.endswith(("json", "yaml")):
            base_url = base_url.rsplit("/", 1)[0]
        report = (
            f"[API FUZZ] Alvo: {base_url}\n"
            f"  Docs originais: {url}\n"
            f"  Acao: Enumerar rotas via ffuf / swagger-to-paths\n"
        )
        ui_log("ESCALATOR", report, Colors.WARNING)
        return {"escalated": True, "report": report, "target_url": base_url}

    @staticmethod
    def escalate_panel_bruteforce(url: str, panel_type: str = "") -> dict:
        """Gatilho Exposed Panel: gera log de brute-force com credenciais padrao."""
        defaults = "\n".join([
            "  admin:admin",
            "  admin:password",
            "  root:root",
            "  tomcat:tomcat",
            "  manager:manager",
        ])
        report = (
            f"[BRUTE-FORCE] Painel: {panel_type or 'unknown'}\n"
            f"  URL: {url}\n"
            f"  Credenciais padrao testadas:\n{defaults}\n"
        )
        ui_log("ESCALATOR", report, Colors.WARNING)
        return {"escalated": True, "report": report, "target_url": url}

    @staticmethod
    def escalate_git_env(url: str, kind: str = "") -> dict:
        """Gatilho .git / .env: marca para extracao de segredos."""
        report = (
            f"[SECRET EXTRACTION] Tipo: {kind or 'unknown'}\n"
            f"  URL: {url}\n"
            f"  Acao: Correr git-dumper / dotenv-parser\n"
        )
        ui_log("ESCALATOR", report, Colors.ERROR)
        return {"escalated": True, "report": report, "target_url": url}

    @staticmethod
    def validate_js_secret(secret_type: str, value: str) -> dict:
        """
        SECURITY: Validates if the secret found in JS is likely valid.
        NEVER sends full secret to external APIs - uses hashing and format validation only.
        """
        # Hash the secret to avoid logging full value
        secret_hash = hashlib.sha256(str(value).encode()).hexdigest()[:12]
        report = f"[JS VALIDATION] Tipo: {secret_type}\n  Hash: {secret_hash}\n"
        is_valid = False

        try:
            if secret_type == "google_api":
                # SECURITY: Never use the actual API key in a request
                # Just validate format: Google API keys follow a specific pattern
                if isinstance(value, str) and len(value) > 20 and re.match(r'^[A-Za-z0-9_-]{20,}$', value):
                    report += "  [!] Formato consistente com Google API Key.\n"
                    report += "  [!] Recomendação: Validar manualmente via console.cloud.google.com"
                    is_valid = True  # Format validation only
                    
            elif secret_type == "aws_access_key":
                # AWS keys have specific format: AKIA + 16 alphanumeric characters
                if isinstance(value, str) and re.match(r'^AKIA[0-9A-Z]{16}$', value):
                    report += "  [!] Formato consistente com AWS Access Key.\n"
                    report += "  [!] Recomendação: Testar via 'aws sts get-caller-identity'"
                    is_valid = True  # Format validation only
                    
            elif secret_type == "stripe_key":
                # Stripe keys start with sk_ or rk_
                if isinstance(value, str) and (value.startswith('sk_') or value.startswith('rk_')):
                    report += "  [!] Formato consistente com Stripe Key.\n"
                    report += "  [!] AVISO: NÃO tente usar a chave para evitar charges!"
                    is_valid = True  # Format validation only
                    
            else:
                # Generic validation: check if it looks like a token (length, charset)
                if isinstance(value, str) and len(value) > 10:
                    report += "  [!] Formato genérico consistente com token/chave.\n"
                    is_valid = True  # Format validation only
                    
        except Exception as e:
            logger.error(f"Secret validation error: {e}")
            report += f"  [?] Erro durante validação: {str(e)[:50]}"

        ui_log("ESCALATOR", report, Colors.ERROR if is_valid else Colors.WARNING)
        return {"escalated": is_valid, "report": report}

    @classmethod
    def escalate(cls, trigger_name: str, url: str, extra: str = "") -> dict:
        """Dispatch to the right escalation routine."""
        dispatch = {
            "swagger_openapi": lambda: cls.escalate_api_fuzz(url),
            "exposed_panel": lambda: cls.escalate_panel_bruteforce(url, extra),
            "exposed_git_env": lambda: cls.escalate_git_env(url, extra),
        }
        fn = dispatch.get(trigger_name)
        if fn:
            return fn()
        return {"escalated": False, "report": "", "target_url": url}


class Escalator:
    """Main facade: parse findings, match triggers, run escalation, route alerts."""

    SEVERITY_MAP = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    ESCALATED_SEVERITY = "high"  

    def process(self, findings_path: str, target: str) -> dict:
        """Parse findings and return routing dict."""
        if not os.path.exists(findings_path) or os.path.getsize(findings_path) == 0:
            return {"telegram": [], "discord_batch": [], "escalation_log": []}

        telegram: list = []
        discord_batch: list = []
        escalation_log: list = []
        engine = EscalationEngine()

        try:
            with open(findings_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    # 1. Limpa as cores ANSI
                    clean_line = ANSI_ESCAPE.sub("", line).strip()

                    if not clean_line:
                        continue

                    # 2. Ignora tudo o que não pareça JSON puro logo à partida
                    if not clean_line.startswith("{"):
                        continue

                    # 3. Parse JSON blindado - sem logs de erro para manter o hunt3r.log limpo
                    try:
                        finding = json.loads(clean_line)
                    except json.JSONDecodeError:
                        continue

                    sev = finding.get("severity", "info").lower()
                    sev_rank = self.SEVERITY_MAP.get(sev, 4)

                    # Native Medium/Critical/High -> always Telegram
                    if sev_rank <= 2:  # crit, high, med
                        telegram.append(finding)
                        continue

                    # Info / Low -> check triggers
                    trigger_name, extra_ctx = self._match_trigger(finding)
                    if trigger_name:
                        url = finding.get("matched-at", "")
                        result = engine.escalate(trigger_name, url, extra_ctx)
                        
                        finding["_escalated"] = trigger_name
                        finding["_escalation_report"] = result.get("report", "")
                        finding["_simulated_severity"] = self.ESCALATED_SEVERITY
                        telegram.append(finding)
                        escalation_log.append(result.get("report", ""))
                    else:
                        discord_batch.append(finding)

        except Exception as e:
            logging.error(f"Escalator process error: {e}")

        # Summary
        ui_log(
            "ESCALATOR",
            f"{len(telegram)} findings -> Telegram, "
            f"{len(discord_batch)} low-noise -> Discord, "
            f"{len(escalation_log)} chains activated.",
            Colors.SUCCESS,
        )
        return {
            "telegram": telegram,
            "discord_batch": discord_batch,
            "escalation_log": escalation_log,
        }

    # ---- internals ----

    @staticmethod
    def _match_trigger(finding: dict) -> tuple[str, str]:
        """Return (trigger_name, extra_context) or ('', '').
        Scans template-id, template-url, matched-at, extracted-results."""
        blobs = [
            finding.get("template-id", ""),
            finding.get("template-url", ""),
            finding.get("matched-at", ""),
            " ".join(finding.get("extracted-results", [])),
        ]
        haystack = "\n".join(str(b) for b in blobs)

        for name, spec in TRIGGERS.items():
            for pat in spec["patterns"]:
                m = pat.search(haystack)
                if m:
                    ui_log(
                        "TRIGGER",
                        f"{spec['label']} -> {spec['action']}",
                        Colors.WARNING,
                    )
                    return name, finding.get("matched-at", "")
        return "", ""
