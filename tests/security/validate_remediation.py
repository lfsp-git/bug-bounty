#!/usr/bin/env python3
"""
Quick security validation tests for Hunt3r-v1 remediation.
Run this to verify critical security fixes are in place.
"""

import subprocess
import sys
import os

def test_no_shell_true():
    """Verify no shell=True in subprocess calls."""
    result = subprocess.run(
        ['grep', '-r', 'shell=True', 'core/', 'recon/', '--include=*.py'],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        lines = result.stdout.strip().split('\n')
        print(f"❌ FAIL: Found {len(lines)} shell=True instances:")
        for line in lines[:5]:
            print(f"   {line}")
        return False
    print("✅ PASS: No shell=True in subprocess calls")
    return True


def test_constants_exist():
    """Verify core/constants.py exists."""
    if os.path.exists('core/constants.py'):
        print("✅ PASS: core/constants.py created")
        return True
    print("❌ FAIL: core/constants.py missing")
    return False


def test_validation_module_exists():
    """Verify core/validation.py exists."""
    if os.path.exists('core/validation.py'):
        print("✅ PASS: core/validation.py created")
        return True
    print("❌ FAIL: core/validation.py missing")
    return False


def test_logging_module_exists():
    """Verify core/logging_utils.py exists."""
    if os.path.exists('core/logging_utils.py'):
        print("✅ PASS: core/logging_utils.py created")
        return True
    print("❌ FAIL: core/logging_utils.py missing")
    return False


def test_env_example_exists():
    """Verify .env.example exists and .env is in .gitignore."""
    if not os.path.exists('.env.example'):
        print("❌ FAIL: .env.example missing")
        return False
    
    with open('.gitignore', 'r') as f:
        gitignore = f.read()
    
    if '.env' not in gitignore:
        print("❌ FAIL: .env not in .gitignore")
        return False
    
    print("✅ PASS: .env.example created and .env in .gitignore")
    return True


def test_no_bare_excepts():
    """Verify no bare except clauses in critical files."""
    critical_files = [
        'core/updater.py',
        'core/fp_filter.py',
        'core/escalator.py'
    ]
    
    found_issues = False
    for file in critical_files:
        # Look for bare except: (not except Exception:)
        result = subprocess.run(
            ['grep', '-n', r'except:\s*$', file],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"❌ FAIL: Bare except: in {file}")
            for line in result.stdout.strip().split('\n'):
                print(f"   {line}")
            found_issues = True
    
    if not found_issues:
        print("✅ PASS: No bare except: clauses")
        return True
    return False


def test_ssl_verification():
    """Verify SSL verification is explicit."""
    files_to_check = [
        ('core/ai_client.py', 'verify=True'),
        ('recon/platforms.py', 'verify=True'),
    ]
    
    for filepath, pattern in files_to_check:
        with open(filepath, 'r') as f:
            content = f.read()
        if pattern not in content:
            print(f"❌ FAIL: {pattern} not found in {filepath}")
            return False
    
    print("✅ PASS: SSL verification explicit in ai_client.py and platforms.py")
    return True


def main():
    print("\n" + "="*70)
    print("HUNT3R-V1: SECURITY VALIDATION TESTS")
    print("="*70 + "\n")
    
    tests = [
        ("No shell=True in subprocess", test_no_shell_true),
        ("Constants module exists", test_constants_exist),
        ("Validation module exists", test_validation_module_exists),
        ("Logging module exists", test_logging_module_exists),
        (".env protection", test_env_example_exists),
        ("No bare except clauses", test_no_bare_excepts),
        ("SSL verification explicit", test_ssl_verification),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            passed = test_func()
            results.append((name, passed))
        except Exception as e:
            print(f"❌ ERROR: {name} - {e}")
            results.append((name, False))
        print()
    
    # Summary
    print("="*70)
    print("SUMMARY")
    print("="*70)
    passed = sum(1 for _, p in results if p)
    total = len(results)
    print(f"\nTests Passed: {passed}/{total}")
    
    if passed == total:
        print("\n✅ ALL SECURITY CHECKS PASSED!")
        print("Code is ready for merge.\n")
        return 0
    else:
        print(f"\n❌ {total - passed} test(s) failed.")
        print("Please review and fix above issues.\n")
        return 1


if __name__ == '__main__':
    sys.exit(main())
