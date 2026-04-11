"""
Bounty Program Scorer - Prioritizes targets by likelihood of finding vulnerabilities

Scoring Metrics:
1. Recency (weight: 40%) - New programs = higher priority
2. Budget/Bounty Range (weight: 30%) - Higher bounties = better ROI
3. Program Scope (weight: 20%) - Larger scope = more attack surface
4. Previous Finding Rate (weight: 10%) - Historical success predictor
"""

import time
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
from enum import Enum

class BountyPlatform(Enum):
    """Supported bounty platforms"""
    HACKERONE = "h1"
    BUGCROWD = "bc"
    INTIGRITI = "it"
    YESWEHACK = "ywh"
    HACKFARM = "hf"

class ProgramScope(Enum):
    """Scope size categories"""
    HUGE = 4       # 1000+ subdomains (vhx.tv, nordvpn, etc)
    LARGE = 3      # 100-1000 subs
    MEDIUM = 2     # 10-100 subs
    SMALL = 1      # <10 subs

class BountyRange(Enum):
    """Bounty reward levels"""
    CRITICAL = 4   # $5000+
    HIGH = 3       # $1000-5000
    MEDIUM = 2     # $100-1000
    LOW = 1        # <$100

class BountyScorer:
    """Scores bounty programs for hunt priority"""
    
    # Default scoring weights (can be tuned)
    WEIGHTS = {
        'recency': 0.40,      # New programs = most important
        'budget': 0.30,       # Budget matters
        'scope': 0.20,        # Scope affects ROI
        'finding_rate': 0.10  # Historical data
    }
    
    # Historical finding rates by platform/scope
    FINDING_RATES = {
        ('h1', 'huge'): 0.08,    # HackerOne huge scope: 8% chance of finding something
        ('h1', 'large'): 0.12,
        ('h1', 'medium'): 0.15,
        ('h1', 'small'): 0.10,
        ('bc', 'huge'): 0.06,    # Bugcrowd typically harder
        ('bc', 'large'): 0.10,
        ('bc', 'medium'): 0.12,
        ('bc', 'small'): 0.08,
        ('it', 'huge'): 0.07,    # Intigriti mid-range
        ('it', 'large'): 0.11,
        ('it', 'medium'): 0.13,
        ('it', 'small'): 0.09,
    }
    
    @classmethod
    def score_program(cls, program: Dict, current_timestamp: float = None) -> Tuple[float, Dict]:
        """
        Score a single bounty program.
        
        Args:
            program: Dict with keys:
                - 'handle': program identifier
                - 'platform': 'h1', 'bc', 'it', etc
                - 'created_at': Unix timestamp (seconds)
                - 'bounty_range': min-max tuple e.g. (100, 5000)
                - 'scope_size': estimated subdomain count
                - 'last_found': Unix timestamp of last finding (optional)
            - current_timestamp: Override current time (for testing)
        
        Returns:
            (total_score, breakdown_dict)
        """
        if current_timestamp is None:
            current_timestamp = time.time()
        
        breakdown = {}
        
        # 1. RECENCY SCORE (0-100)
        # Programs < 1 week old: 100 points
        # Programs < 1 month old: 80 points
        # Programs < 3 months old: 60 points
        # Programs > 3 months old: 40 points (decay)
        created_at = program.get('created_at')
        if not isinstance(created_at, (int, float)):
            created_at = current_timestamp
        days_old = (current_timestamp - created_at) / 86400
        
        if days_old < 7:
            recency_score = 100  # Fresh programs get maximum
        elif days_old < 30:
            recency_score = 80
        elif days_old < 90:
            recency_score = 60
        else:
            recency_score = 40 + max(0, 20 * (1 - (days_old - 90) / 180))  # Gradual decay
        
        breakdown['recency'] = {
            'score': recency_score,
            'days_old': days_old,
            'reason': f"Program {days_old:.0f} days old"
        }
        
        # 2. BUDGET SCORE (0-100)
        # Based on bounty range (min bounty used as proxy)
        bounty_range = program.get('bounty_range') or (0, 1000)
        min_bounty = bounty_range[0] if isinstance(bounty_range, (tuple, list)) and len(bounty_range) > 0 else 0
        
        if min_bounty >= 5000:
            budget_score = 100
            budget_tier = "CRITICAL"
        elif min_bounty >= 1000:
            budget_score = 75
            budget_tier = "HIGH"
        elif min_bounty >= 100:
            budget_score = 50
            budget_tier = "MEDIUM"
        else:
            budget_score = 25
            budget_tier = "LOW"
        
        breakdown['budget'] = {
            'score': budget_score,
            'min_bounty': min_bounty,
            'tier': budget_tier
        }
        
        # 3. SCOPE SCORE (0-100)
        # Larger scope = more attack surface
        scope_size = program.get('scope_size') or 100
        
        if scope_size >= 1000:
            scope_score = 90
            scope_tier = "HUGE"
        elif scope_size >= 100:
            scope_score = 70
            scope_tier = "LARGE"
        elif scope_size >= 10:
            scope_score = 50
            scope_tier = "MEDIUM"
        else:
            scope_score = 30
            scope_tier = "SMALL"
        
        breakdown['scope'] = {
            'score': scope_score,
            'subdomain_count': scope_size,
            'tier': scope_tier
        }
        
        # 4. FINDING RATE SCORE (0-100)
        # Historical success rate based on platform + scope
        platform = program.get('platform', 'h1').lower()
        scope_key = scope_tier.lower()
        
        finding_rate = cls.FINDING_RATES.get((platform, scope_key), 0.10)
        finding_rate_score = finding_rate * 100  # Convert to 0-100 scale
        
        # Boost if we've found something before
        last_found = program.get('last_found', None)
        if last_found:
            hours_since_find = (current_timestamp - last_found) / 3600
            if hours_since_find < 24:  # Found something recently
                finding_rate_score = min(100, finding_rate_score * 1.5)
        
        breakdown['finding_rate'] = {
            'score': finding_rate_score,
            'historical_rate': finding_rate,
            'platform': platform
        }
        
        # TOTAL SCORE (weighted average)
        total_score = (
            recency_score * cls.WEIGHTS['recency'] +
            budget_score * cls.WEIGHTS['budget'] +
            scope_score * cls.WEIGHTS['scope'] +
            finding_rate_score * cls.WEIGHTS['finding_rate']
        )
        
        breakdown['total'] = total_score
        
        return total_score, breakdown
    
    @classmethod
    def rank_programs(cls, programs: List[Dict], top_n: int = None) -> List[Tuple[str, float, Dict]]:
        """
        Rank multiple programs by score.
        
        Returns:
            List of (handle, total_score, breakdown) sorted by score descending
        """
        scored = []
        
        for program in programs:
            handle = program.get('handle', 'unknown')
            score, breakdown = cls.score_program(program)
            scored.append((handle, score, breakdown))
        
        # Sort by score descending
        scored.sort(key=lambda x: x[1], reverse=True)
        
        if top_n:
            scored = scored[:top_n]
        
        return scored
    
    @classmethod
    def format_score_report(cls, handle: str, score: float, breakdown: Dict) -> str:
        """Human-readable score report"""
        r = breakdown.get('recency', {})
        b = breakdown.get('budget', {})
        s = breakdown.get('scope', {})
        f = breakdown.get('finding_rate', {})
        
        return f"""
Program: {handle} | Total Score: {score:.1f}/100

Recency:      {r.get('score', 0):.0f}/100  ({r.get('reason', 'unknown')})
Budget:       {b.get('score', 0):.0f}/100  ({b.get('tier', 'unknown')} tier - ${b.get('min_bounty', 0)})
Scope:        {s.get('score', 0):.0f}/100  ({s.get('tier', 'unknown')} - {s.get('subdomain_count', 0)} subs)
Finding Rate: {f.get('score', 0):.0f}/100  ({f.get('platform', 'unknown')} platform, {f.get('historical_rate', 0):.1%} historical)
""".strip()


# Example usage
if __name__ == "__main__":
    # Test scoring
    now = time.time()
    
    programs = [
        {
            'handle': 'acme_new',
            'platform': 'h1',
            'created_at': now - 86400 * 2,  # 2 days old (FRESH)
            'bounty_range': (500, 5000),
            'scope_size': 250,
        },
        {
            'handle': 'oldcorp_established',
            'platform': 'bc',
            'created_at': now - 86400 * 180,  # 6 months old
            'bounty_range': (100, 1000),
            'scope_size': 50,
        },
        {
            'handle': 'megacompany_huge',
            'platform': 'h1',
            'created_at': now - 86400 * 30,  # 1 month old
            'bounty_range': (1000, 10000),
            'scope_size': 2000,
        },
    ]
    
    ranked = BountyScorer.rank_programs(programs)
    
    print("📊 BOUNTY PROGRAM RANKING\n" + "=" * 70)
    for i, (handle, score, breakdown) in enumerate(ranked, 1):
        print(f"\n{i}. {BountyScorer.format_score_report(handle, score, breakdown)}")
