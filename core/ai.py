"""
Hunt3r — AI client and target intelligence scoring.
"""
from __future__ import annotations

import json
import os
import re
import time
import logging
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

try:
    import psutil  # type: ignore
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False


# ---------------------------------------------------------------------------
# AI Client (OpenRouter)
# ---------------------------------------------------------------------------
class AIClient:
    MODELS_FILE = "config/selected_model.json"

    def __init__(self) -> None:
        self.api_key: str = os.getenv("OPENROUTER_API_KEY", "")
        self.base_url: str = "https://openrouter.ai/api/v1"
        self.selected_model: Optional[str] = self._load_saved_model()
        self._cache: List[Dict] = []
        self.session = requests.Session()
        self.session.verify = True
        if self.api_key:
            self.session.headers.update({
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            })

    def _load_saved_model(self) -> Optional[str]:
        if os.path.exists(self.MODELS_FILE):
            try:
                with open(self.MODELS_FILE, "r", encoding="utf-8") as f:
                    return json.load(f).get("model")
            except (OSError, json.JSONDecodeError) as e:
                logger.debug(f"Failed to load saved model: {e}")
        return None

    def save_model(self, model_id: str) -> None:
        self.selected_model = model_id
        os.makedirs(os.path.dirname(self.MODELS_FILE), exist_ok=True)
        with open(self.MODELS_FILE, "w", encoding="utf-8") as f:
            json.dump({"model": model_id}, f)

    def fetch_curated_models(self) -> List[Dict]:
        if self._cache:
            return self._cache
        if not self.api_key:
            return []
        try:
            r = self.session.get(f"{self.base_url}/models", timeout=15)
            if r.status_code == 200:
                data = r.json()
                free = [
                    m for m in data.get("data", [])
                    if m.get("pricing", {}).get("prompt", "0") == "0"
                ]
                free.sort(key=lambda x: x.get("context_length", 0), reverse=True)
                self._cache = free[:15]
                return self._cache
        except requests.RequestException as e:
            logger.error(f"Failed to fetch models: {e}")
        return []

    # OpenRouter hard limit for most models; stay safely under to avoid 400s
    _MAX_PROMPT_CHARS = 12_000

    @staticmethod
    def _sanitize_prompt(prompt: str, max_chars: int = _MAX_PROMPT_CHARS) -> str:
        """Sanitize prompt before sending to OpenRouter.

        - Remove non-printable / control characters (causes 400 from some models)
        - Truncate to max_chars so the total token count stays within model context
        """
        # Strip control chars except ordinary whitespace (\t \n \r)
        cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', prompt)
        if len(cleaned) > max_chars:
            cleaned = cleaned[:max_chars] + "\n...[truncated]"
        return cleaned

    def complete(self, prompt: str, max_tokens: int = 500) -> str:
        if not self.api_key or not self.selected_model:
            return "[AI Offline]"
        sanitized = self._sanitize_prompt(prompt)
        payload = {
            "model": self.selected_model,
            "messages": [{"role": "user", "content": sanitized}],
            "max_tokens": max_tokens,
        }
        try:
            r = self.session.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                timeout=60,
            )
            if r.status_code == 200:
                try:
                    return r.json()["choices"][0]["message"]["content"]
                except (KeyError, IndexError, ValueError) as e:
                    logger.error(f"AI response parse error: {e} — body: {r.text[:200]}")
                    return f"[Error: bad response shape]"
            # Log actionable detail for 400 Bad Request (most common misconfiguration)
            err_detail = ""
            try:
                err_detail = r.json().get("error", {}).get("message", r.text[:150])
            except (ValueError, AttributeError):
                err_detail = r.text[:150]
            logger.warning(f"AI API error {r.status_code}: {err_detail}")
            return f"[API Error {r.status_code}]"
        except requests.RequestException as e:
            logger.error(f"AI completion failed: {e}")
            return f"[Error: {str(e)[:100]}]"


def select_model_interactive(ai_client: AIClient) -> bool:
    """Interactive model selection flow (returns True if model saved)."""
    if not ai_client.api_key:
        return False
    models = ai_client.fetch_curated_models()
    if not models:
        return False
    from core.ui import ui_model_selection_menu  # deferred to avoid circular
    chosen = ui_model_selection_menu(models)
    if chosen:
        ai_client.save_model(chosen)
        return True
    return False


# ---------------------------------------------------------------------------
# IntelMiner — target scoring and program ranking
# ---------------------------------------------------------------------------
class IntelMiner:
    """Score and rank bug bounty programs by potential reward."""

    CACHE_FILE = "recon/intel_cache.json"
    CACHE_TTL = 3600  # 1 hour

    def __init__(self, api_client: AIClient) -> None:
        self.client = api_client
        self.max_subs: int = self._detect_memory_limit()

    def _detect_memory_limit(self) -> int:
        """Adaptive subdomain limit based on available RAM."""
        try:
            if _HAS_PSUTIL:
                import psutil
                mb = psutil.virtual_memory().available // (1024 * 1024)
            else:
                with open("/proc/meminfo", "r") as f:
                    m = {
                        l.split()[0].rstrip(":"): int(l.split()[1])
                        for l in f if len(l.split()) >= 2
                    }
                mb = m.get("MemAvailable", 0) // 1024
            return 100 if mb < 3000 else (1000 if mb < 6000 else 2000)
        except (OSError, KeyError, ZeroDivisionError):
            return 200

    def _score(self, handle: str, domain: str, metadata: Optional[Dict] = None) -> int:
        meta = metadata or {}
        s = 10

        if meta.get("crit_scopes", 0) > 0:
            s += 30
        if meta.get("bounty_scopes", 0) > 2:
            s += 20
        if meta.get("triage_active"):
            s += 5

        t = f"{handle.lower()} {domain.lower()}"

        # Tier 1: Fintech / Crypto
        if any(x in t for x in [
            "coinbase", "crypto", "blockchain", "trading", "exchange", "defi",
            "wallet", "bank", "financial", "capital", "payment", "stripe", "plaid",
            "mercury", "paypal", "wise",
        ]):
            s += 70
        # Tier 2: Big Tech / Cloud / Social
        elif any(x in t for x in [
            "google", "microsoft", "apple", "amazon", "meta", "facebook", "cloudflare",
            "akamai", "fastly", "github", "gitlab", "atlassian", "uber", "airbnb",
            "spotify", "netflix", "salesforce", "oracle", "sap", "adobe", "snowflake",
            "datadog", "cloud", "aws", "azure", "gcp", "att", "verizon", "vodafone",
            "linkedin", "twitter", " x ", "slack", "tinder", "discord", "snapchat",
            "telegram",
        ]):
            s += 50
        # Tier 3: Healthcare / Finance / Gov
        elif any(x in t for x in [
            "equifax", "experian", "transunion", "goldman", "mckinsey", "medical",
            "health", "gov", "insurance", "telecom", "booking", "yelp", "mapbox",
            "grab", "shopify", "flipkart", "olx",
        ]):
            s += 35
        # Tier 4: CMS / DevOps
        elif any(x in t for x in [
            "wordpress", "woocommerce", "drupal", "joomla", "magento", "prestashop",
            "docker", "kubernetes", "jenkins", "git",
        ]):
            s += 20

        # Penalties
        if any(x in t for x in ["security", "hackerone", "bugcrowd", "intigriti"]):
            s -= 30
        if any(x in t for x in ["google", "microsoft"]) and self.max_subs < 500:
            s -= 20

        return max(0, min(s, 99))

    def _hot_score(self, prog: Dict) -> int:
        if not prog.get("offers_bounty") and not prog.get("offers_bounties"):
            return 0
        s = 50
        if prog.get("triage_active"):
            s += 30
        bs = prog.get("bounty_scopes", 0)
        s += 10 if bs >= 10 else (7 if bs >= 5 else (4 if bs >= 2 else 0))
        if prog.get("crit_scopes", 0) > 0:
            s += 5
        if len(prog.get("domains", [])) >= 50:
            s += 5
        return min(s, 100)

    def rank_programs_for_list(self, programs: List[Dict]) -> List[Dict]:
        """Rank programs by bounty potential. Returns cached result if fresh."""
        if os.path.exists(self.CACHE_FILE):
            age = time.time() - os.path.getmtime(self.CACHE_FILE)
            if age < self.CACHE_TTL:
                try:
                    with open(self.CACHE_FILE, "r", encoding="utf-8") as f:
                        return json.load(f)
                except (OSError, json.JSONDecodeError):
                    pass

        paid = [p for p in programs if p.get("offers_bounty") or p.get("offers_bounties")]
        for p in paid:
            p["hot_score"] = self._hot_score(p)
            p["score"] = self._score(
                p.get("handle", ""),
                (p.get("domains") or ["unknown.com"])[0],
                p,
            )

        ranked = sorted(paid, key=lambda x: (x.get("hot_score", 0), x.get("score", 0)), reverse=True)

        try:
            os.makedirs(os.path.dirname(self.CACHE_FILE) or ".", exist_ok=True)
            with open(self.CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(ranked, f)
        except OSError:
            pass

        return ranked

    def load_cached_programs(self) -> List[Dict]:
        """Load ranked programs from cache (returns [] if expired or missing)."""
        if not os.path.exists(self.CACHE_FILE):
            return []
        age = time.time() - os.path.getmtime(self.CACHE_FILE)
        if age >= self.CACHE_TTL:
            return []
        try:
            with open(self.CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return []
