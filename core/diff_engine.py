"""
Recon Diff Engine — Compare consecutive scans and detect asset changes.
Saves baselines and reports deltas: new domains, removed domains, new endpoints.
"""

import os
import json
import time
import logging

_BASELINE_DIR = "recon/baselines"


class ReconDiff:
    """Compare scan results against stored baselines."""

    @classmethod
    def _baseline_path(cls, handle):
        os.makedirs(_BASELINE_DIR, exist_ok=True)
        return os.path.join(_BASELINE_DIR, f"{handle}.json")

    @classmethod
    def load_baseline(cls, handle):
        """Load previous scan baseline. Returns dict or None."""
        path = cls._baseline_path(handle)
        if not os.path.exists(path):
            return None
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"DiffEngine: Error loading baseline for {handle}: {e}")
            return None

    @classmethod
    def save_baseline(cls, handle, data):
        """Save current scan as new baseline."""
        path = cls._baseline_path(handle)
        os.makedirs(_BASELINE_DIR, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(data, f)

    @classmethod
    def compute_diff(cls, handle, new_subdomains, new_endpoints, new_js_secrets=None):
        """
        Compare against baseline. Returns dict with deltas.

        Args:
            handle: Target handle
            new_subdomains: set of current subdomains
            new_endpoints: set of current endpoints
            new_js_secrets: set of JS secret identifiers (type:source combos)

        Returns:
            dict with added_subs, removed_subs, added_endpoints, removed_endpoints,
            added_js_secrets, and has_changes flag
        """
        baseline = cls.load_baseline(handle)

        result = {
            'added_subs': set(),
            'removed_subs': set(),
            'added_endpoints': set(),
            'removed_endpoints': set(),
            'added_js_secrets': set(),
            'has_changes': False,
        }

        if baseline is None:
            # First scan — no diff possible
            result['has_changes'] = False
            return result

        old_subs = set(baseline.get('subdomains', []))
        old_endpoints = set(baseline.get('endpoints', []))
        old_secrets = set(baseline.get('js_secrets', []))

        result['added_subs'] = new_subdomains - old_subs
        result['removed_subs'] = old_subs - new_subdomains
        result['added_endpoints'] = new_endpoints - old_endpoints
        result['removed_endpoints'] = old_endpoints - new_endpoints
        if new_js_secrets:
            result['added_js_secrets'] = new_js_secrets - old_secrets

        result['has_changes'] = bool(
            result['added_subs'] or
            result['added_endpoints'] or
            result['added_js_secrets']
        )

        return result

    @classmethod
    def build_baseline_data(cls, subdomains, endpoints, js_secrets=None):
        """Build a baseline data dict from current scan results."""
        data = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'subdomains': sorted(subdomains),
            'endpoints': sorted(endpoints),
            'js_secrets': sorted(js_secrets) if js_secrets else [],
        }
        return data
