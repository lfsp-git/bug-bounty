"""
Test Hunt3r improvements (Phase 2 + Phase 1a/1b + Phase 4)

Tests:
1. Tech detection accuracy (correct tech identified)
2. Nuclei tag generation (appropriate tags for tech stack)
3. Bounty scoring (new programs prioritized)
4. Timeout reduction (faster execution)
"""

import sys
import os
import time
import tempfile
import json

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from recon.tech_detector import TechDetector
from core.bounty_scorer import BountyScorer

def test_tech_detection():
    """Test tech detection from URLs"""
    print("\n" + "=" * 70)
    print("TEST 1: Tech Detection from URLs")
    print("=" * 70)
    
    test_cases = [
        {
            'urls': [
                'https://example.com/wp-admin',
                'https://example.com/wp-content/themes/twentytwentyone/',
                'https://example.com/wp-json/wp/v2/posts'
            ],
            'expected': 'wordpress',
            'description': 'WordPress detection'
        },
        {
            'urls': [
                'https://api.example.com/actuator/health',
                'https://api.example.com/actuator/env',
                'https://springapi.example.com/v1/users'
            ],
            'expected': 'spring',
            'description': 'Spring Boot detection'
        },
        {
            'urls': [
                'https://example.com/graphql',
                'https://api.example.com/query',
                '__typename'
            ],
            'expected': 'graphql',
            'description': 'GraphQL detection'
        },
        {
            'urls': [
                'https://example.com/api/v1/users',
                'https://example.com/api/v2/posts',
                'https://api.example.com/endpoint'
            ],
            'expected': 'rest',
            'description': 'REST API detection'
        },
    ]
    
    passed = 0
    for test_case in test_cases:
        detected = TechDetector.detect_from_urls(test_case['urls'])
        has_expected = test_case['expected'] in detected
        
        status = "✅ PASS" if has_expected else "❌ FAIL"
        print(f"{status} | {test_case['description']}")
        print(f"     Expected: {test_case['expected']}, Got: {detected}")
        
        if has_expected:
            passed += 1
    
    print(f"\nResult: {passed}/{len(test_cases)} passed")
    assert passed == len(test_cases)

def test_nuclei_tag_generation():
    """Test tag generation matches tech stack"""
    print("\n" + "=" * 70)
    print("TEST 2: Nuclei Tag Generation")
    print("=" * 70)
    
    test_cases = [
        {
            'tech_stack': {'wordpress', 'apache', 'php'},
            'must_include': ['wordpress', 'apache', 'php', 'sqli', 'xss'],
            'description': 'Apache + PHP + WordPress stack'
        },
        {
            'tech_stack': {'spring', 'java'},
            'must_include': ['spring', 'java', 'actuator', 'cve'],
            'description': 'Spring Boot stack'
        },
        {
            'tech_stack': {'nginx', 'django', 'python'},
            'must_include': ['django', 'sqli', 'ssti'],
            'description': 'Nginx + Django stack'
        },
    ]
    
    passed = 0
    for test_case in test_cases:
        tag_string, tag_list = TechDetector.get_nuclei_tags(test_case['tech_stack'])
        
        # Check if all required tags are present
        all_present = all(tag in tag_string for tag in test_case['must_include'])
        
        status = "✅ PASS" if all_present else "❌ FAIL"
        print(f"{status} | {test_case['description']}")
        print(f"     Tags: {tag_string}")
        
        if all_present:
            passed += 1
    
    print(f"\nResult: {passed}/{len(test_cases)} passed")
    assert passed == len(test_cases)

def test_bounty_scoring():
    """Test bounty program scoring"""
    print("\n" + "=" * 70)
    print("TEST 3: Bounty Program Scoring")
    print("=" * 70)
    
    now = time.time()
    
    programs = [
        {
            'handle': 'brand_new',
            'platform': 'h1',
            'created_at': now - 86400,  # 1 day old
            'bounty_range': (500, 5000),
            'scope_size': 500,
        },
        {
            'handle': 'old_program',
            'platform': 'h1',
            'created_at': now - 86400 * 365,  # 1 year old
            'bounty_range': (100, 1000),
            'scope_size': 50,
        },
        {
            'handle': 'mega_bounty',
            'platform': 'h1',
            'created_at': now - 86400 * 30,  # 1 month old
            'bounty_range': (5000, 50000),
            'scope_size': 2000,
        },
    ]
    
    ranked = BountyScorer.rank_programs(programs)
    
    print("Ranked programs (by priority):")
    for i, (handle, score, breakdown) in enumerate(ranked, 1):
        print(f"{i}. {handle}: {score:.0f}/100")
    
    # Validate that new program is higher priority than old
    # (unless mega bounty compensates)
    brand_new_idx = next(i for i, (h, _, _) in enumerate(ranked) if h == 'brand_new')
    old_idx = next(i for i, (h, _, _) in enumerate(ranked) if h == 'old_program')
    
    passed = brand_new_idx < old_idx  # New should come before old
    
    status = "✅ PASS" if passed else "❌ FAIL"
    print(f"\n{status} | New programs prioritized over old")
    
    assert passed

def test_timeout_config():
    """Verify timeout reduction"""
    print("\n" + "=" * 70)
    print("TEST 4: Nuclei Timeout Configuration")
    print("=" * 70)
    
    with open('recon/engines.py', 'r') as f:
        content = f.read()
    
    # Check for timeout setting
    has_2s_timeout = '"-timeout", "2"' in content
    old_5s_timeout = '"-timeout", "5"' in content
    
    status = "✅ PASS" if (has_2s_timeout and not old_5s_timeout) else "❌ FAIL"
    print(f"{status} | Timeout set to 2 seconds (was 5)")
    
    if has_2s_timeout:
        print("  Expected impact: ~40% speedup for responsive targets")
    
    assert has_2s_timeout and not old_5s_timeout

def test_adaptive_nuclei_timeout_override():
    """Verify run_nuclei supports adaptive timeout override parameter."""
    with open('recon/engines.py', 'r') as f:
        content = f.read()
    has_param = 'timeout_override=None' in content
    has_usage = 'timeout_override' in content and 'get_tool_timeout("nuclei")' in content
    assert has_param and has_usage

def test_smart_tag_integration():
    """Verify smart tags are integrated in scanner"""
    print("\n" + "=" * 70)
    print("TEST 5: Smart Tag Integration in Scanner")
    print("=" * 70)
    
    with open('core/scanner.py', 'r') as f:
        content = f.read()
    
    # Check for integration points
    has_import = 'from recon.tech_detector import TechDetector' in content
    has_method = 'def _get_smart_nuclei_tags' in content
    has_call = '_get_smart_nuclei_tags(recon_input, katana_file)' in content
    
    all_integrated = has_import and has_method and has_call
    
    status = "✅ PASS" if all_integrated else "❌ FAIL"
    print(f"{status} | Smart tags integrated into scanner")
    
    if has_import:
        print("  ✓ TechDetector imported")
    if has_method:
        print("  ✓ _get_smart_nuclei_tags method added")
    if has_call:
        print("  ✓ Called before Nuclei execution")
    
    assert all_integrated

def run_all_tests():
    """Run all tests and report"""
    print("\n" + "=" * 70)
    print("🧪 HUNT3R IMPROVEMENTS TEST SUITE")
    print("=" * 70)
    
    def _run_test(fn):
        try:
            fn()
            return True
        except AssertionError:
            return False

    results = {
        'Tech Detection': _run_test(test_tech_detection),
        'Nuclei Tag Gen': _run_test(test_nuclei_tag_generation),
        'Bounty Scoring': _run_test(test_bounty_scoring),
        'Timeout Config': _run_test(test_timeout_config),
        'Smart Tag Inte': _run_test(test_smart_tag_integration),
    }
    
    print("\n" + "=" * 70)
    print("📊 TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅" if result else "❌"
        print(f"{status} {test_name}")
    
    print(f"\nTotal: {passed}/{total} passed")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED! Hunt3r improvements verified.")
        return True
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Review output above.")
        return False

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
