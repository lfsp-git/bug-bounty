"""
JS Hunter — Extract hidden endpoints, API keys, and secrets from JavaScript files.
Zero external dependencies. Pure regex pattern matching.

REGRA: Scan apenas em .js, .mjs, .ts. Noise blacklist para docs/examples.
"""

import re
import os
import time
import logging
import json
from urllib.parse import urlparse


class JSHunter:
    """Extract secrets, endpoints, and API keys from JavaScript files ONLY."""

    # Only valid JS extensions accepted
    VALID_EXTENSIONS = {'.js', '.mjs', '.ts'}

    # Ignore values containing these noise markers (docs, examples, CDNs)
    NOISE_BLACKLIST = [
        '/doc/', '/docs/', '/documentation/', '/blog/', '/changelog',
        'schema.org', 'w3.org', 'example.com', 'example.org',
        '/news/', '/about/', '/privacy', '/terms',
        '/cdn-cgi/', '/wp-content/themes/', '/wp-includes/',
        'developer.mozilla.org', 'cdnjs.cloudflare.com',
        'unpkg.com', 'cdn.jsdelivr.net', 'stackpath.bootstrapcdn.com',
    ]

    PATTERNS = {
        'aws_access_key': re.compile(r'(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}'),
        'aws_secret_key': re.compile(r'(?i)aws[_-]?secret[_-]?(?:access)?[_-]?key["\'\s:=]+([A-Za-z0-9/+=]{40})'),
        'generic_api_key': re.compile(r'(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']'),
        'auth_token': re.compile(r'(?i)(?:auth|access|bearer)\s*(?:token)?\s*[:=]\s*["\']([A-Za-z0-9_\-.]{20,})["\']'),
        'private_key': re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
        'password_or_secret': re.compile(r'(?i)(?:password|passwd|secret|secret_key|signing_key)\s*[:=]\s*["\']([^"\']{4,})["\']'),
        'slack_webhook': re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),
        'discord_webhook': re.compile(r'https://(?:canary\.|ptb\.)?discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]+'),
        'interactsh': re.compile(r'https?://[A-Za-z0-9_-]+\.interact\.sh'),
        'generic_url_param': re.compile(r'(?i)[\'"`](https?://[^\'"`]+/(?:api|v\d+|graphql|admin|auth|internal|debug|config|settings|internal)[^\'"`]*)[\'"`]'),
        'firebase_db': re.compile(r'(?i)firebaseio\.com'),
        'google_api': re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        'stripe_key': re.compile(r'(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}'),
        'jwt_token': re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
    }

    @classmethod
    def _is_valid_js(cls, url_or_path):
        """Return True only for .js, .mjs, or .ts files."""
        u = url_or_path.lower()
        # Strip query params for extension check
        base = u.split('?')[0]
        return any(base.endswith(ext) for ext in cls.VALID_EXTENSIONS)

    @classmethod
    def _is_noisy(cls, value):
        """Return True if value matches documentation/noise URLs."""
        vl = value.lower()
        return any(n in vl for n in cls.NOISE_BLACKLIST)

    @classmethod
    def scan_url(cls, url, timeout=30):
        """Fetch a .js file and extract secrets."""
        if not cls._is_valid_js(url):
            return []
        try:
            import requests
            resp = requests.get(url, timeout=timeout, allow_redirects=True,
                                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
            if resp.status_code >= 400:
                return []
            return cls._scan_content(resp.text, url)
        except Exception as e:
            logging.warning(f"JS Hunter error fetching {url}: {e}")
            return []

    @classmethod
    def scan_file(cls, path):
        """Scan a local .js file for secrets."""
        if not cls._is_valid_js(path):
            return []
        try:
            with open(path, 'r', errors='ignore') as f:
                content = f.read()
            return cls._scan_content(content, path)
        except Exception as e:
            logging.warning(f"JS Hunter error reading {path}: {e}")
            return []

    @classmethod
    def _scan_content(cls, content, source):
        """Extract all pattern matches from raw JS content."""
        findings = []
        seen = set()

        for pattern_name, regex in cls.PATTERNS.items():
            for match in regex.finditer(content):
                val = match.group(0).strip()
                if val in seen:
                    continue
                if len(val) > 500:
                    continue
                # Noise filter: skip doc/example URLs
                if cls._is_noisy(val):
                    continue
                seen.add(val)
                findings.append({
                    'type': pattern_name,
                    'value': val[:200],
                    'source': source,
                    'url': source if source.startswith('http') else '',
                })

        return findings

    @classmethod
    def extract_js_urls(cls, httpx_urls_file):
        """Extract .js/.mjs/.ts URLs from HTTPX output."""
        if not os.path.exists(httpx_urls_file):
            return []

        js_urls = []
        with open(httpx_urls_file, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if cls._is_valid_js(line):
                    js_urls.append(line)

        return js_urls

    @classmethod
    def scan_all(cls, httpx_urls_file, output_file, target_score=0):
        """Scan all .js files from HTTPX output and save findings."""
        js_urls = cls.extract_js_urls(httpx_urls_file)
        if not js_urls:
            return [], 0

        all_findings = []
        scanned = 0
        rate_limit = 0.1  # 10 req/s

        for url in js_urls:
            time.sleep(rate_limit)
            findings = cls.scan_url(url, timeout=30)
            if findings:
                all_findings.extend(findings)
            scanned += 1

        # Save findings
        if all_findings:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, 'w', encoding='utf-8') as f:
                for finding in all_findings:
                    f.write(json.dumps(finding) + '\n')

        return all_findings, scanned
