"""Unified intelligence/scoring access layer."""

from __future__ import annotations

from typing import Any, Dict, Tuple

from core.ai import AIClient, IntelMiner, select_model_interactive
from core.bounty_scorer import BountyScorer
from core.heuristic_agent import ReActHeuristicAgent


def score_program(program: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
    """Centralized program scoring entry point."""
    return BountyScorer.score_program(program)


def score_watchdog_target(target: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
    """Score watchdog target dicts using the same centralized scorer."""
    domains = target.get("domains") or []
    program_data = {
        "original_handle": target.get("original_handle", ""),
        "handle": target.get("handle", "unknown"),
        "platform": target.get("platform", "unknown"),
        "domains": domains,
        "offers_bounty": target.get("offers_bounty", True),
        "bounty_scopes": target.get("bounty_scopes", 0),
        "crit_scopes": target.get("crit_scopes", 0),
        "created_at": target.get("created_at"),
        "bounty_range": target.get("bounty_range", (100, 1000)),
        "scope_size": target.get("scope_size") or len(domains) or 1,
        "last_found": target.get("last_found"),
    }
    return score_program(program_data)

