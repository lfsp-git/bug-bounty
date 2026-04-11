"""Comprehensive tests for core/bounty_scorer.py (full rewrite coverage)."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from core.bounty_scorer import (
    BountyScorer, BountyRange, ProgramScope, BountyPlatform,
    _HIGH_VALUE_TLDS, _LOW_VALUE_TLDS, _PLATFORM_SCORE,
)


# ── Wildcard scoring ──────────────────────────────────────────────────────────

class TestWildcardScoring:
    def test_full_wildcard_prefix_scores_100(self):
        assert BountyScorer._score_wildcard("*.example.com", []) == 100.0

    def test_wildcard_anywhere_in_handle_scores_100(self):
        # " *." triggers the "full wildcard" condition
        assert BountyScorer._score_wildcard("scope.com *.api.corp.com", []) == 100.0

    def test_three_stars_scores_90(self):
        # 3 wildcards but none triggers the "*." or " *." prefix conditions
        assert BountyScorer._score_wildcard("a*b.com c*d.com e*f.com", []) == 90.0

    def test_two_stars_scores_80(self):
        # 2 wildcards, none at start or after space with dot
        assert BountyScorer._score_wildcard("a*b.com c*d.com", []) == 80.0

    def test_one_star_not_at_start_scores_70(self):
        # one wildcard but doesn't start with "*." and no " *."
        assert BountyScorer._score_wildcard("prefix*suffix.example.com", []) == 70.0

    def test_no_wildcard_five_domains_scores_55(self):
        domains = ["a.com", "b.com", "c.com", "d.com", "e.com"]
        assert BountyScorer._score_wildcard("example.com", domains) == 55.0

    def test_no_wildcard_two_domains_scores_45(self):
        assert BountyScorer._score_wildcard("example.com", ["a.com", "b.com"]) == 45.0

    def test_no_wildcard_single_domain_scores_30(self):
        assert BountyScorer._score_wildcard("example.com", ["example.com"]) == 30.0

    def test_empty_handle_and_empty_domains_scores_30(self):
        assert BountyScorer._score_wildcard("", []) == 30.0


# ── Breadth scoring ───────────────────────────────────────────────────────────

class TestBreadthScoring:
    def test_scope_size_500_base_90(self):
        score = BountyScorer._score_breadth([], {"scope_size": 500})
        assert score >= 90

    def test_bounty_scopes_50_base_90(self):
        score = BountyScorer._score_breadth([], {"bounty_scopes": 50})
        assert score >= 90

    def test_scope_size_100_base_75(self):
        score = BountyScorer._score_breadth([], {"scope_size": 100})
        assert score >= 75

    def test_scope_size_20_base_55(self):
        score = BountyScorer._score_breadth([], {"scope_size": 20})
        assert score >= 55

    def test_scope_size_5_base_40(self):
        score = BountyScorer._score_breadth([], {"scope_size": 5})
        assert 35 <= score <= 45

    def test_crit_scopes_5_adds_20(self):
        base = BountyScorer._score_breadth([], {"scope_size": 5})
        boosted = BountyScorer._score_breadth([], {"scope_size": 5, "crit_scopes": 5})
        assert boosted == min(100, base + 20)

    def test_crit_scopes_bonus_capped_at_20(self):
        s100 = BountyScorer._score_breadth([], {"scope_size": 5, "crit_scopes": 100})
        s5 = BountyScorer._score_breadth([], {"scope_size": 5, "crit_scopes": 5})
        assert s100 == s5  # bonus doesn't grow past 20

    def test_domain_list_count_used_as_fallback(self):
        # no scope_size, 5 domains
        score = BountyScorer._score_breadth(["a", "b", "c", "d", "e"], {})
        assert 35 <= score <= 45

    def test_none_crit_scopes_treated_as_zero(self):
        score_none = BountyScorer._score_breadth([], {"scope_size": 20, "crit_scopes": None})
        score_zero = BountyScorer._score_breadth([], {"scope_size": 20, "crit_scopes": 0})
        assert score_none == score_zero


# ── Quality scoring ───────────────────────────────────────────────────────────

class TestQualityScoring:
    def test_no_bounty_returns_20(self):
        assert BountyScorer._score_quality([], {"offers_bounty": False}) == 20.0

    def test_bounty_range_5000_returns_100(self):
        score = BountyScorer._score_quality([], {"bounty_range": [5000, 10000], "offers_bounty": True})
        assert score == 100.0

    def test_bounty_range_1000_returns_85(self):
        score = BountyScorer._score_quality([], {"bounty_range": [1000, 4999]})
        assert score == 85.0

    def test_bounty_range_500_returns_70(self):
        score = BountyScorer._score_quality([], {"bounty_range": [500, 999]})
        assert score == 70.0

    def test_bounty_range_100_returns_55(self):
        score = BountyScorer._score_quality([], {"bounty_range": [100, 499]})
        assert score == 55.0

    def test_high_value_tld_io_scores_ge_80(self):
        score = BountyScorer._score_quality(["payments.io"], {})
        assert score >= 80

    def test_high_value_tld_ai_scores_ge_80(self):
        score = BountyScorer._score_quality(["startup.ai"], {})
        assert score >= 80

    def test_mid_value_tld_com_scores_ge_65(self):
        score = BountyScorer._score_quality(["brand.com"], {})
        assert score >= 65

    def test_low_value_tld_gov_scores_le_40(self):
        score = BountyScorer._score_quality(["agency.gov"], {})
        assert score <= 40

    def test_low_value_tld_edu_scores_le_40(self):
        score = BountyScorer._score_quality(["university.edu"], {})
        assert score <= 40

    def test_high_value_pattern_pay_boosts_score(self):
        base = BountyScorer._score_quality(["brand.com"], {})
        with_pay = BountyScorer._score_quality(["pay.brand.com"], {})
        assert with_pay >= base

    def test_high_value_pattern_api_boosts_score(self):
        base = BountyScorer._score_quality(["brand.com"], {})
        with_api = BountyScorer._score_quality(["api.brand.com"], {})
        assert with_api >= base

    def test_high_value_pattern_admin_boosts_score(self):
        score = BountyScorer._score_quality(["admin.company.com"], {})
        assert score >= 65

    def test_malformed_bounty_range_falls_back_to_tld(self):
        # bounty_range exists but value is None → falls through to TLD logic
        score = BountyScorer._score_quality(["service.io"], {"bounty_range": [None, None]})
        assert score >= 80  # .io TLD kicks in

    def test_empty_domains_returns_platform_default(self):
        from core.bounty_scorer import _PLATFORM_DEFAULT
        score = BountyScorer._score_quality([], {})
        assert score == float(_PLATFORM_DEFAULT)


# ── Platform scoring ──────────────────────────────────────────────────────────

class TestPlatformScoring:
    @pytest.mark.parametrize("platform,expected", [
        ("h1", 75), ("bc", 60), ("it", 65), ("ywh", 55), ("hf", 50),
    ])
    def test_known_platforms(self, platform, expected):
        _, bd = BountyScorer.score_program({"handle": "x", "platform": platform})
        assert bd["platform"]["score"] == expected

    def test_unknown_platform_uses_default_55(self):
        _, bd = BountyScorer.score_program({"handle": "x", "platform": "unknown"})
        assert bd["platform"]["score"] == 55

    def test_platform_case_insensitive(self):
        _, bd_lower = BountyScorer.score_program({"handle": "x", "platform": "H1"})
        assert bd_lower["platform"]["score"] == 75


# ── score_program integration ─────────────────────────────────────────────────

class TestScoreProgram:
    def test_returns_float_and_dict(self):
        score, bd = BountyScorer.score_program({"handle": "test"})
        assert isinstance(score, float)
        assert isinstance(bd, dict)

    def test_breakdown_has_all_keys(self):
        _, bd = BountyScorer.score_program({"handle": "x", "platform": "h1"})
        for key in ("wildcard", "breadth", "quality", "platform", "total"):
            assert key in bd, f"Missing key: {key}"

    def test_total_in_breakdown_matches_return_value(self):
        score, bd = BountyScorer.score_program({"handle": "x", "platform": "h1"})
        assert abs(bd["total"] - round(score, 1)) < 0.05

    def test_wildcard_h1_exceeds_60_threshold(self):
        score, _ = BountyScorer.score_program({
            "handle": "wildcard_fintech",
            "original_handle": "*.payments.io",
            "domains": ["payments.io"],
            "platform": "h1",
            "offers_bounty": True,
        })
        assert score >= 60, f"Wildcard H1 program should score ≥ 60, got {score:.1f}"

    def test_gov_no_bounty_below_60_threshold(self):
        score, _ = BountyScorer.score_program({
            "handle": "gov_agency",
            "original_handle": "agency.gov",
            "domains": ["agency.gov"],
            "platform": "unknown",
            "offers_bounty": False,
        })
        assert score < 60, f"Gov no-bounty program should score < 60, got {score:.1f}"

    def test_score_bounded_0_to_100(self):
        for program in [
            {"handle": "a", "original_handle": "*.io", "domains": ["pay.io"],
             "platform": "h1", "bounty_scopes": 999, "crit_scopes": 999,
             "offers_bounty": True, "bounty_range": [99999]},
            {"handle": "b", "original_handle": "x.xyz", "domains": ["x.xyz"],
             "platform": "unknown", "offers_bounty": False},
        ]:
            score, _ = BountyScorer.score_program(program)
            assert 0 <= score <= 100, f"Score out of range: {score}"

    def test_weights_sum_to_exactly_1(self):
        total = sum(BountyScorer.WEIGHTS.values())
        assert abs(total - 1.0) < 1e-9

    def test_empty_program_does_not_crash(self):
        score, bd = BountyScorer.score_program({})
        assert isinstance(score, float)


# ── rank_programs ─────────────────────────────────────────────────────────────

class TestRankPrograms:
    def _wildcard_h1(self, handle):
        return {"handle": handle, "original_handle": f"*.{handle}.io",
                "domains": [f"{handle}.io"], "platform": "h1", "offers_bounty": True}

    def _gov_no_bounty(self, handle):
        return {"handle": handle, "original_handle": f"{handle}.gov",
                "domains": [f"{handle}.gov"], "platform": "unknown", "offers_bounty": False}

    def test_high_score_first(self):
        programs = [self._gov_no_bounty("low"), self._wildcard_h1("high")]
        ranked = BountyScorer.rank_programs(programs)
        assert ranked[0][0] == "high"

    def test_top_n_limits_results(self):
        programs = [{"handle": f"p{i}"} for i in range(10)]
        assert len(BountyScorer.rank_programs(programs, top_n=3)) == 3

    def test_top_n_none_returns_all(self):
        programs = [{"handle": f"p{i}"} for i in range(5)]
        assert len(BountyScorer.rank_programs(programs)) == 5

    def test_empty_list_returns_empty(self):
        assert BountyScorer.rank_programs([]) == []

    def test_returns_tuples_of_handle_score_breakdown(self):
        ranked = BountyScorer.rank_programs([{"handle": "test", "platform": "h1"}])
        assert len(ranked) == 1
        handle, score, bd = ranked[0]
        assert handle == "test"
        assert isinstance(score, float)
        assert isinstance(bd, dict)


# ── format_score_report ───────────────────────────────────────────────────────

class TestFormatScoreReport:
    def _sample_bd(self):
        return {
            "wildcard": {"score": 100, "handle": "*.example.io"},
            "breadth": {"score": 75, "domain_count": 10},
            "quality": {"score": 80},
            "platform": {"score": 75, "platform": "h1"},
        }

    def test_contains_handle_and_score(self):
        report = BountyScorer.format_score_report("my_program", 82.5, self._sample_bd())
        assert "my_program" in report
        assert "82.5" in report

    def test_contains_all_components(self):
        report = BountyScorer.format_score_report("x", 50.0, self._sample_bd())
        for label in ("Wildcard", "Breadth", "Quality", "Platform"):
            assert label in report

    def test_missing_breakdown_keys_dont_crash(self):
        report = BountyScorer.format_score_report("x", 42.0, {})
        assert "x" in report


# ── Backwards-compat aliases ──────────────────────────────────────────────────

class TestBackwardsCompatAliases:
    def test_bounty_range_constants(self):
        assert BountyRange.CRITICAL == 4
        assert BountyRange.HIGH == 3
        assert BountyRange.MEDIUM == 2
        assert BountyRange.LOW == 1

    def test_program_scope_constants(self):
        assert ProgramScope.HUGE == 4
        assert ProgramScope.LARGE == 3
        assert ProgramScope.MEDIUM == 2
        assert ProgramScope.SMALL == 1

    def test_bounty_platform_constants(self):
        assert BountyPlatform.HACKERONE == "h1"
        assert BountyPlatform.BUGCROWD == "bc"
        assert BountyPlatform.INTIGRITI == "it"
