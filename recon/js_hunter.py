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
        # CDN/library/3rd-party public service URLs — never secrets
        'github.com', 'gitlab.com', 'bitbucket.org',
        'reactrouter.com', 'react.dev', 'vuejs.org', 'angular.io',
        'optimizely.com', 'segment.com', 'amplitude.com', 'mixpanel.com',
        'js.stripe.com', 'stripe.com/v3',
        'recaptcha', 'google.com/recaptcha', 'google-analytics.com',
        'googletagmanager.com',
        'sentry.io', 'rollbar.com', 'bugsnag.com',
        'intercom.io', 'zendesk.com', 'freshdesk.com',
        'cloudfront.net', 'azureedge.net',
        'outgrow.co', 'outgrow.com',
        'countrystatecity.in',
        'airtable.com/v0.3', 'airtable.com/developers',
    ]

    PATTERNS = {
        'aws_access_key': re.compile(r'(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}'),
        'aws_secret_key': re.compile(r'(?i)aws[_-]?secret[_-]?(?:access)?[_-]?key["\'\s:=]+([A-Za-z0-9/+=]{40})'),
        'generic_api_key': re.compile(r'(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']'),
        'auth_token': re.compile(r'(?i)(?:auth|access|bearer)\s*(?:token)?\s*[:=]\s*["\']([A-Za-z0-9_\-.]{32,})["\']'),
        'private_key': re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
        'password_or_secret': re.compile(r'(?i)(?:password|passwd|secret_key|signing_key)\s*[:=]\s*["\']([^"\']{8,})["\']'),
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

    # FP patterns (class-level to avoid re-compiling per call)
    _FP_PASSWORD_VALUE = re.compile(
        r'^(?:'
        r'/[a-zA-Z0-9/_\-]*'
        r'|%[a-z_]+%'
        r'|(?:password|secret|token|key|placeholder|hint|enter|'
        r'forgot(?:_?password)?|change.?password|reset.?password|'
        r'current.?password|missing|incorrect|invalid|required|'
        r'confirm(?:_?password)?|new(?:_?password)?|old(?:_?password)?)'
        r'|[A-Z][a-zA-Z]+(?:Password|Secret|Token|Key)'
        r')$',
        re.IGNORECASE,
    )

    _CDN_URL_DOMAINS = re.compile(
        r'(?:github\.com|gitlab\.com|reactrouter\.com|optimizely\.com|'
        r'segment\.com|js\.stripe\.com|stripe\.com/v3|'
        r'google\.com|googleapis\.com|sentry\.io|rollbar\.com|'
        r'intercom\.io|cloudfront\.net|azureedge\.net|'
        r'outgrow\.co|outgrow\.com|countrystatecity\.in|'
        r'airtable\.com/v0|airtable\.com/developers)',
        re.IGNORECASE,
    )

    @classmethod
    def _is_fp(cls, pattern_name: str, captured: str) -> bool:
        """Return True if this match is a deterministic false positive."""
        val = captured.strip().strip('"\'`')

        if pattern_name == 'password_or_secret':
            if cls._FP_PASSWORD_VALUE.match(val):
                return True
            if val.startswith('/') or val.startswith('http'):
                return True
            # CamelCase single word = React component / route name
            if re.match(r'^[A-Z][a-zA-Z]+$', val) and len(val) < 40:
                return True
            # snake_case identifier = i18n/translation key (e.g. current_password_missing)
            if re.match(r'^[a-z][a-z0-9_]*$', val) and len(val) < 60:
                return True
            # camelCase identifier without digits = JS variable name
            if re.match(r'^[a-z][a-zA-Z]+$', val) and len(val) < 40:
                return True

        elif pattern_name == 'auth_token':
            if re.match(r'^[a-z][a-z0-9_]*$', val) or len(val) < 32:
                return True

        elif pattern_name == 'generic_url_param':
            if cls._CDN_URL_DOMAINS.search(val):
                return True
            if '?' not in val and not re.search(
                r'(?:token|key|secret|auth|api_?key|password)=', val, re.I
            ):
                return True

        elif pattern_name == 'generic_api_key':
            if not re.search(r'\d', val):
                return True

        return False

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
        seen = set()  # dedup by (type, captured_value)

        for pattern_name, regex in cls.PATTERNS.items():
            for match in regex.finditer(content):
                raw = match.group(0).strip()
                captured = match.group(1).strip() if match.lastindex else raw

                if len(raw) > 500:
                    continue
                if cls._is_noisy(raw):
                    continue
                if cls._is_fp(pattern_name, captured):
                    continue

                dedup_key = (pattern_name, captured[:100])
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                findings.append({
                    'type': pattern_name,
                    'value': raw[:200],
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
