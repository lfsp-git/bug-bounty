"""
Bounty Program Scorer - Prioritizes targets by likelihood of finding vulnerabilities

Scoring strategy (based on data actually available from bbscope/APIs):
1. Wildcard scope   (35%) — *.domain.com = full attack surface
2. Domain breadth   (25%) — more unique domains = more endpoints to probe
3. Target quality   (25%) — TLD/brand signals + bounty eligibility metadata
4. Platform signal  (15%) — h1/it/bc have different historical finding densities

All scores are 0-100. Final score ≥ 60 triggers AI validation.
"""

import re
import time
from typing import Dict, List, Tuple

# TLDs / patterns that correlate with higher vuln density (tech companies,
# funded startups, fintech) vs. low-value noise.
_HIGH_VALUE_TLDS  = {".io", ".ai", ".app", ".dev", ".finance", ".financial",
                     ".money", ".pay", ".bank", ".crypto", ".security"}
_MID_VALUE_TLDS   = {".com", ".net", ".co", ".cloud", ".tech", ".digital"}
_LOW_VALUE_TLDS   = {".gov", ".mil", ".edu", ".org", ".info", ".biz", ".site",
                     ".online", ".click", ".xyz"}

# Platform historical finding densities (normalised 0-100).
_PLATFORM_SCORE = {"h1": 75, "bc": 60, "it": 65, "ywh": 55, "hf": 50}
_PLATFORM_DEFAULT = 55


class BountyScorer:
    """Scores bounty programs for hunt priority using signals available at runtime."""

    WEIGHTS = {
        "wildcard":  0.35,
        "breadth":   0.25,
        "quality":   0.25,
        "platform":  0.15,
    }

    # ── Public API ────────────────────────────────────────────────────────────

    @classmethod
    def score_program(cls, program: Dict, current_timestamp: float = None) -> Tuple[float, Dict]:
        """Score a single program dict.

        Expected keys (all optional — sensible defaults used when absent):
            handle / original_handle : raw target string e.g. "*.example.com"
            domains                  : list of cleaned domain strings
            platform                 : "h1", "bc", "it", …
            offers_bounty            : bool
            bounty_scopes            : int — number of in-scope bounty-eligible assets
            crit_scopes              : int — number of critical-severity scopes

        Legacy keys still accepted for backwards-compat:
            created_at, bounty_range, scope_size, last_found
        """
        breakdown: Dict = {}

        raw_handle = program.get("original_handle") or program.get("handle", "")
        domains: List[str] = program.get("domains") or []
        platform = str(program.get("platform", "unknown")).lower()

        # 1. WILDCARD SCORE (0-100)
        wildcard_score = cls._score_wildcard(raw_handle, domains)
        breakdown["wildcard"] = {"score": wildcard_score, "handle": raw_handle}

        # 2. BREADTH SCORE (0-100)
        breadth_score = cls._score_breadth(domains, program)
        breakdown["breadth"] = {"score": breadth_score, "domain_count": len(domains)}

        # 3. QUALITY SCORE (0-100)
        quality_score = cls._score_quality(domains, program)
        breakdown["quality"] = {"score": quality_score}

        # 4. PLATFORM SCORE (0-100)
        platform_score = _PLATFORM_SCORE.get(platform, _PLATFORM_DEFAULT)
        breakdown["platform"] = {"score": platform_score, "platform": platform}

        # WEIGHTED TOTAL
        total = (
            wildcard_score  * cls.WEIGHTS["wildcard"] +
            breadth_score   * cls.WEIGHTS["breadth"] +
            quality_score   * cls.WEIGHTS["quality"] +
            platform_score  * cls.WEIGHTS["platform"]
        )
        breakdown["total"] = round(total, 1)
        return total, breakdown

    @classmethod
    def rank_programs(cls, programs: List[Dict], top_n: int = None) -> List[Tuple[str, float, Dict]]:
        """Rank a list of programs by score (highest first)."""
        scored = []
        for program in programs:
            handle = program.get("handle", "unknown")
            score, breakdown = cls.score_program(program)
            scored.append((handle, score, breakdown))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_n] if top_n else scored

    @classmethod
    def format_score_report(cls, handle: str, score: float, breakdown: Dict) -> str:
        w = breakdown.get("wildcard", {})
        b = breakdown.get("breadth", {})
        q = breakdown.get("quality", {})
        p = breakdown.get("platform", {})
        return (
            f"Program: {handle} | Total: {score:.1f}/100\n"
            f"  Wildcard: {w.get('score',0):.0f}/100  "
            f"Breadth: {b.get('score',0):.0f}/100 ({b.get('domain_count',0)} domains)  "
            f"Quality: {q.get('score',0):.0f}/100  "
            f"Platform: {p.get('score',0):.0f}/100 ({p.get('platform','?')})"
        )

    # ── Scoring sub-methods ───────────────────────────────────────────────────

    @classmethod
    def _score_wildcard(cls, raw_handle: str, domains: List[str]) -> float:
        """High score when scope is wildcard (*.domain.com).

        Wildcards expose the full subdomain space — they dramatically increase
        the probability of finding something interesting.
        """
        handle_lc = raw_handle.lower()
        # Full wildcard like *.example.com
        if handle_lc.startswith("*.") or " *." in handle_lc:
            return 100.0
        # Multiple wildcards in a comma-joined scope string
        wildcard_count = handle_lc.count("*")
        if wildcard_count >= 3:
            return 90.0
        if wildcard_count == 2:
            return 80.0
        if wildcard_count == 1:
            return 70.0
        # No wildcard but multiple domains suggest wide scope
        if len(domains) >= 5:
            return 55.0
        if len(domains) >= 2:
            return 45.0
        return 30.0

    @classmethod
    def _score_breadth(cls, domains: List[str], program: Dict) -> float:
        """More domains = more attack surface, but with diminishing returns.

        Uses scope metadata from H1 API when available (bounty_scopes / crit_scopes).
        Falls back to legacy scope_size field or domain list length.
        """
        # Prefer API-provided metadata
        bounty_scopes = program.get("bounty_scopes", 0) or 0
        crit_scopes   = program.get("crit_scopes", 0) or 0
        scope_size    = program.get("scope_size") or len(domains) or 1

        # Boost for critical-severity scopes
        crit_bonus = min(20, crit_scopes * 4)

        if scope_size >= 500 or bounty_scopes >= 50:
            base = 90
        elif scope_size >= 100 or bounty_scopes >= 20:
            base = 75
        elif scope_size >= 20 or bounty_scopes >= 5:
            base = 55
        elif scope_size >= 5:
            base = 40
        else:
            base = 25

        return min(100, base + crit_bonus)

    @classmethod
    def _score_quality(cls, domains: List[str], program: Dict) -> float:
        """Estimate target quality from TLD patterns and bounty metadata."""
        offers_bounty = program.get("offers_bounty", True)
        bounty_range  = program.get("bounty_range")

        # Programs that don't pay bounties are low priority
        if offers_bounty is False:
            return 20.0

        # Use explicit bounty range if provided (legacy / H1 API data)
        if isinstance(bounty_range, (list, tuple)) and len(bounty_range) >= 1:
            try:
                min_b = float(bounty_range[0]) if bounty_range[0] else 0
                if min_b >= 5000:   return 100.0
                if min_b >= 1000:   return 85.0
                if min_b >= 500:    return 70.0
                if min_b >= 100:    return 55.0
            except (TypeError, ValueError):
                pass

        # Infer from TLD signals
        all_domains = " ".join(domains).lower()
        tld_score = _PLATFORM_DEFAULT  # neutral baseline

        for tld in _HIGH_VALUE_TLDS:
            if tld in all_domains:
                tld_score = max(tld_score, 80)
                break
        for tld in _MID_VALUE_TLDS:
            if tld in all_domains:
                tld_score = max(tld_score, 65)
                break
        for tld in _LOW_VALUE_TLDS:
            if tld in all_domains:
                tld_score = min(tld_score, 40)

        # Fintech / security company names in domain → higher value
        high_value_patterns = re.compile(
            r"(pay|bank|finance|capital|crypto|wallet|vault|auth|sso|"
            r"api|admin|dashboard|portal|internal|corp|sec|scan|bug)", re.I
        )
        if any(high_value_patterns.search(d) for d in domains):
            tld_score = min(100, tld_score + 10)

        return float(tld_score)


# ── Backwards-compat aliases ──────────────────────────────────────────────────
class BountyRange:
    CRITICAL = 4; HIGH = 3; MEDIUM = 2; LOW = 1

class ProgramScope:
    HUGE = 4; LARGE = 3; MEDIUM = 2; SMALL = 1

class BountyPlatform:
    HACKERONE = "h1"; BUGCROWD = "bc"; INTIGRITI = "it"
    YESWEHACK = "ywh"; HACKFARM = "hf"


# Example / manual test
if __name__ == "__main__":
    import time as _time
    _now = _time.time()
    programs = [
        {"handle": "wildcard_fintech", "original_handle": "*.payments.io",
         "domains": ["payments.io"], "platform": "h1", "offers_bounty": True},
        {"handle": "multi_domain_corp", "original_handle": "bigcorp.com",
         "domains": ["bigcorp.com", "api.bigcorp.com", "auth.bigcorp.com",
                     "admin.bigcorp.com", "dev.bigcorp.com", "pay.bigcorp.com"],
         "platform": "h1", "bounty_scopes": 30, "crit_scopes": 5},
        {"handle": "tiny_site_xyz", "original_handle": "tinysite.xyz",
         "domains": ["tinysite.xyz"], "platform": "bc", "offers_bounty": True},
        {"handle": "old_gov", "original_handle": "agency.gov",
         "domains": ["agency.gov"], "platform": "unknown", "offers_bounty": False},
    ]
    ranked = BountyScorer.rank_programs(programs)
    print("📊 BOUNTY RANKING\n" + "=" * 70)
    for i, (handle, score, bd) in enumerate(ranked, 1):
        print(f"\n{i}. {BountyScorer.format_score_report(handle, score, bd)}")
