"""Hunt3r ReAct Heuristic Agent (v1.1-OVERLORD)

Implements a minimal ReAct (Reason → Act → Observe) loop on top of the
existing AIClient (OpenRouter) — no LangChain needed.

Pipeline position: after JS Hunter, before Nuclei.

Loop:
  THOUGHT  — LLM reasons about which endpoints are worth probing
  ACTION   — Agent probes each INJECT decision with parameter manipulation
  OBSERVE  — Compares baseline vs manipulated responses for anomalies
  FINDING  — Writes confirmed anomalies to findings_file (Nuclei JSONL schema)

All failures are non-fatal: exceptions are caught and logged, execution
always continues to the Nuclei phase.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tuning knobs (env-configurable)
# ---------------------------------------------------------------------------
_MAX_ENDPOINTS_PER_CALL: int = int(os.getenv("REACT_MAX_ENDPOINTS", "15"))
_MAX_PROBES: int = int(os.getenv("REACT_MAX_PROBES", "30"))
_SIZE_DIFF_THRESHOLD: int = int(os.getenv("REACT_SIZE_DIFF", "80"))
_PROBE_TIMEOUT: float = float(os.getenv("REACT_PROBE_TIMEOUT", "8"))
_MAX_RETRIES: int = 3
_BASE_RETRY_DELAY: float = 3.0

# Patterns that indicate potentially interesting endpoints
_INTERESTING_RX: List[re.Pattern] = [
    re.compile(r'[?&](id|user_?id|account_?id|order_?id|doc_?id|record_?id|item_?id|uid|uuid|guid|pid|cid|tid|eid|fid)=[\w-]+', re.I),
    re.compile(r'/(?:users?|accounts?|orders?|docs?|records?|items?|profiles?)/[\w-]+/?(?:\?|$)', re.I),
    re.compile(r'/(?:api|v\d+)/[\w/-]+/[\d]+/?', re.I),
    re.compile(r'[?&](?:role|type|access|permission|privilege|group|tier)=', re.I),
    re.compile(r'/(?:admin|dashboard|backoffice|internal|manage|control)', re.I),
    re.compile(r'/[\w-]+/[\d]{1,10}(?:/[\w-]*)?(?:\?.*)?$', re.I),
]

# Skip static/irrelevant extensions
_SKIP_EXT_RX = re.compile(
    r'\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|json|xml|txt|pdf|zip|gz|tar|mp4|mp3|wav|webm)(?:\?|$)',
    re.I,
)


def _is_interesting(url: str) -> bool:
    if _SKIP_EXT_RX.search(url):
        return False
    return any(rx.search(url) for rx in _INTERESTING_RX)


def _safe_read_lines(filepath: str) -> List[str]:
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
            return [line.strip() for line in fh if line.strip()]
    except OSError:
        return []


def _safe_read_jsonl(filepath: str) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        items.append(obj)
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    return items


# ---------------------------------------------------------------------------
# LLM call with exponential backoff on 429
# ---------------------------------------------------------------------------

def _call_llm_with_retry(ai_client: Any, prompt: str, max_tokens: int = 800) -> str:
    """Call AIClient.complete() with exponential backoff on rate-limit (429).

    Returns the raw response string or "[AI Offline]" on unrecoverable failure.
    """
    delay = _BASE_RETRY_DELAY
    last_err = ""
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            resp = ai_client.complete(prompt, max_tokens=max_tokens)
            # OpenRouter embeds "429" in error strings when rate-limited
            if "429" in resp or "rate limit" in resp.lower():
                if attempt < _MAX_RETRIES:
                    logger.warning(
                        "ReAct: rate limit hit (attempt %d/%d), sleeping %.1fs",
                        attempt, _MAX_RETRIES, delay,
                    )
                    time.sleep(delay)
                    delay = min(delay * 2.0, 60.0)
                    continue
            return resp
        except Exception as exc:
            last_err = str(exc)
            if attempt < _MAX_RETRIES:
                logger.debug("ReAct: LLM call error (attempt %d): %s", attempt, last_err[:80])
                time.sleep(delay)
                delay = min(delay * 2.0, 60.0)
            else:
                logger.warning("ReAct: LLM exhausted retries: %s", last_err[:120])
    return "[AI Offline]"


# ---------------------------------------------------------------------------
# Probe helpers
# ---------------------------------------------------------------------------

def _build_probe_urls(endpoint: str, params: Dict[str, str]) -> List[str]:
    """Construct manipulated URLs from the LLM-suggested params.

    For each numeric ID found either in the path or query string, generate
    ±1 variants.  Additional manipulation params from the LLM are merged in.
    """
    try:
        parsed = urlparse(endpoint)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        probes = []

        # Merge LLM-suggested params into existing query string
        merged = {k: [v] for k, v in params.items()}
        merged.update(qs)

        # Mutate numeric query params by ±1
        for key, vals in list(merged.items()):
            raw = vals[0] if vals else ""
            if raw.isdigit():
                n = int(raw)
                for mutated in {str(max(0, n - 1)), str(n + 1), "0", "1", "9999"}:
                    if mutated != raw:
                        mutated_qs = dict(merged)
                        mutated_qs[key] = [mutated]
                        flat = {k: v[0] for k, v in mutated_qs.items()}
                        new_parsed = parsed._replace(query=urlencode(flat))
                        probes.append(urlunparse(new_parsed))

        # Mutate numeric path segment (e.g. /users/123 → /users/124)
        path_parts = parsed.path.split("/")
        for i, part in enumerate(path_parts):
            if part.isdigit():
                n = int(part)
                for mutated in {str(max(0, n - 1)), str(n + 1), "0", "1"}:
                    if mutated != part:
                        new_parts = list(path_parts)
                        new_parts[i] = mutated
                        new_path = "/".join(new_parts)
                        flat_qs = {k: v[0] for k, v in qs.items()}
                        new_parsed = parsed._replace(path=new_path, query=urlencode(flat_qs) if flat_qs else "")
                        probes.append(urlunparse(new_parsed))

        return list(dict.fromkeys(probes))[:6]  # cap at 6 per endpoint
    except Exception as e:
        logger.debug("ReAct: failed to build probe URLs for %s: %s", endpoint, e)
        return []


def _build_bac_headers() -> List[Dict[str, str]]:
    """Common Broken Access Control bypass header sets to rotate through."""
    return [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {},  # baseline: no extra headers
    ]


def _probe_endpoint(
    client: httpx.Client,
    baseline_url: str,
    probe_url: str,
    extra_headers: Dict[str, str],
) -> Optional[Dict[str, Any]]:
    """Fetch baseline and probe URLs; return finding dict if anomaly detected."""
    try:
        b_resp = client.get(baseline_url, headers=extra_headers, follow_redirects=True)
        p_resp = client.get(probe_url, headers=extra_headers, follow_redirects=True)

        b_status, p_status = b_resp.status_code, p_resp.status_code
        b_len, p_len = len(b_resp.content), len(p_resp.content)
        size_diff = abs(b_len - p_len)

        # Anomaly signals:
        # 1. Was 403/401/404, now 200 → likely access bypass
        # 2. Same 200 but response body significantly different → different record (IDOR)
        anomaly = False
        reason = ""
        severity = "medium"

        if b_status in (401, 403, 404) and p_status == 200 and p_len > 50:
            anomaly = True
            reason = f"Access bypass: {b_status}→{p_status}"
            severity = "high"
        elif b_status == 200 and p_status == 200 and size_diff >= _SIZE_DIFF_THRESHOLD:
            anomaly = True
            reason = f"Different response body (IDOR?): size_diff={size_diff}"
            severity = "medium"

        if anomaly:
            return {
                "template-id": "llm-heuristic-idor-bac",
                "template-url": "https://hunt3r.local/llm-heuristic",
                "info": {
                    "name": "LLM Heuristic — IDOR / Broken Access Control",
                    "severity": severity,
                    "description": reason,
                    "tags": ["idor", "auth-bypass", "llm-heuristic"],
                },
                "host": baseline_url,
                "matched-at": probe_url,
                "severity": severity,
                "extracted-results": [
                    f"baseline={baseline_url}",
                    f"probe={probe_url}",
                    f"status_diff={b_status}→{p_status}",
                    f"size_diff={size_diff}",
                    f"reason={reason}",
                ],
                "_hunt3r_source": "llm_heuristic_agent",
            }
    except (httpx.HTTPError, httpx.TimeoutException) as e:
        logger.debug("ReAct: probe request failed for %s: %s", probe_url, e)
    except Exception as e:
        logger.debug("ReAct: unexpected probe error for %s: %s", probe_url, e)
    return None


# ---------------------------------------------------------------------------
# ReAct Agent
# ---------------------------------------------------------------------------

class ReActHeuristicAgent:
    """ReAct-style LLM agent: Thought → Action → Observe → Finding."""

    def __init__(self, ai_client: Any, target: Dict[str, Any]) -> None:
        self.ai = ai_client
        self.target = target
        self.handle = target.get("handle", "unknown")

    # -- Thought step --------------------------------------------------------

    def _sample_endpoints(self, url_files: List[str]) -> List[str]:
        """Collect and sample the most interesting endpoints from crawl output."""
        seen: set = set()
        interesting: List[str] = []
        all_urls: List[str] = []
        for fp in url_files:
            all_urls.extend(_safe_read_lines(fp))

        for url in all_urls:
            if url in seen:
                continue
            seen.add(url)
            if _is_interesting(url):
                interesting.append(url)

        # Sort by complexity (more path segments + params = higher priority)
        def _priority(u: str) -> int:
            p = urlparse(u)
            seg_count = len([s for s in p.path.split("/") if s])
            param_count = len(parse_qs(p.query))
            has_numeric = bool(re.search(r'/\d+|[?&]\w+=\d+', u))
            return seg_count + param_count * 2 + (3 if has_numeric else 0)

        interesting.sort(key=_priority, reverse=True)
        return interesting[:_MAX_ENDPOINTS_PER_CALL]

    def _build_react_prompt(
        self, endpoints: List[str], js_secrets: List[Dict[str, Any]]
    ) -> str:
        ep_block = "\n".join(f"  {i + 1}. {u}" for i, u in enumerate(endpoints))

        secrets_ctx = ""
        if js_secrets:
            sample = js_secrets[:5]
            secrets_ctx = "\nJS Secrets found (context only — do not probe these URLs):\n"
            secrets_ctx += "\n".join(
                f"  - [{s.get('type', '?')}] {s.get('url', '')}" for s in sample
            )

        return f"""You are a senior application security engineer performing a ReAct analysis.

THOUGHT: Examine each endpoint below for potential IDOR (Insecure Direct Object Reference) or Broken Access Control (BAC) vulnerabilities. Consider: numeric IDs that could be incremented, role-based paths, versioned APIs, and endpoints that normally require authorization.

ACTION DECISION: For each endpoint, respond INJECT (worth probing) or DISCARD (safe to skip).

OBSERVATION FORMAT: Return ONLY a JSON array, no markdown fences, no explanation outside the JSON:
[
  {{
    "endpoint": "<original URL>",
    "action": "INJECT",
    "reason": "<one sentence why>",
    "params": {{"param_name": "test_value"}},
    "headers": {{"X-Optional-Header": "value"}}
  }},
  {{
    "endpoint": "<original URL>",
    "action": "DISCARD",
    "reason": "<one sentence why>"
  }}
]

RULES:
- INJECT only when you identify: numeric IDs (?id=N, /resource/N), UUIDs, role-gated paths (/admin, /internal, /dashboard), object references that differ per user
- DISCARD: static assets, login/logout endpoints, search forms with no object reference
- For INJECT: set params to the most likely IDOR mutation (e.g. id=1, id=0, role=admin)
- Maximum 10 INJECT decisions total
- Respond with valid JSON only
{secrets_ctx}
Endpoints to analyze:
{ep_block}"""

    def _parse_llm_decision(self, response: str) -> List[Dict[str, Any]]:
        """Extract the JSON array from the LLM response (handles markdown fences)."""
        # Strip markdown code fences if present
        cleaned = re.sub(r"```(?:json)?\s*", "", response).strip().rstrip("`").strip()
        # Find first [ … ] block
        m = re.search(r"\[.*\]", cleaned, re.DOTALL)
        if not m:
            logger.debug("ReAct: no JSON array found in LLM response: %s", response[:200])
            return []
        try:
            decisions = json.loads(m.group(0))
            if not isinstance(decisions, list):
                return []
            return [
                d for d in decisions
                if isinstance(d, dict) and d.get("endpoint") and d.get("action")
            ]
        except json.JSONDecodeError as e:
            logger.debug("ReAct: JSON parse error: %s — snippet: %s", e, cleaned[:200])
            return []

    # -- Action + Observe step -----------------------------------------------

    def _run_probes(
        self,
        decisions: List[Dict[str, Any]],
        findings_file: str,
    ) -> int:
        """Execute HTTP probes for INJECT decisions. Returns count of new findings."""
        inject_decisions = [d for d in decisions if d.get("action", "").upper() == "INJECT"]
        if not inject_decisions:
            return 0

        new_findings = 0
        probes_sent = 0
        bac_header_sets = _build_bac_headers()

        headers_base = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "application/json, text/html, */*",
        }

        with httpx.Client(
            timeout=_PROBE_TIMEOUT,
            follow_redirects=True,
            verify=False,
            headers=headers_base,
        ) as client:
            for decision in inject_decisions:
                if probes_sent >= _MAX_PROBES:
                    logger.debug("ReAct: MAX_PROBES (%d) reached, stopping.", _MAX_PROBES)
                    break

                endpoint = decision.get("endpoint", "")
                if not endpoint.startswith(("http://", "https://")):
                    continue

                params = decision.get("params") or {}
                extra_headers = decision.get("headers") or {}
                probe_urls = _build_probe_urls(endpoint, params)

                for probe_url in probe_urls:
                    if probes_sent >= _MAX_PROBES:
                        break
                    probes_sent += 1

                    # Try BAC header bypass variants
                    for hdr_set in bac_header_sets[:2]:  # cap: 2 header variants per probe
                        merged_headers = {**extra_headers, **hdr_set}
                        finding = _probe_endpoint(client, endpoint, probe_url, merged_headers)
                        if finding:
                            finding["_llm_reason"] = decision.get("reason", "")
                            self._append_finding(findings_file, finding)
                            new_findings += 1
                            logger.info(
                                "ReAct: finding at %s (%s)",
                                probe_url,
                                finding.get("severity"),
                            )
                            break  # Don't re-probe same URL with more headers

        return new_findings

    @staticmethod
    def _append_finding(findings_file: str, finding: Dict[str, Any]) -> None:
        try:
            os.makedirs(os.path.dirname(findings_file) or ".", exist_ok=True)
            with open(findings_file, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(finding) + "\n")
        except OSError as e:
            logger.warning("ReAct: failed to write finding: %s", e)

    # -- Public entry point --------------------------------------------------

    def run(
        self,
        url_files: List[str],
        js_secrets_file: str,
        findings_file: str,
    ) -> Dict[str, Any]:
        """Execute the full ReAct loop.

        Args:
            url_files:       List of file paths containing crawled URLs
                             (combined_urls, katana output, httpx output, urlfinder).
            js_secrets_file: Path to JS Hunter JSONL output (context for LLM).
            findings_file:   Path to append new findings (Nuclei JSONL schema).

        Returns:
            {endpoints_sampled, endpoints_injected, endpoints_discarded,
             probes_sent, findings_added, ok}
        """
        result: Dict[str, Any] = {
            "endpoints_sampled": 0,
            "endpoints_injected": 0,
            "endpoints_discarded": 0,
            "probes_sent": 0,
            "findings_added": 0,
            "ok": False,
        }

        if not self.ai.api_key or not self.ai.selected_model:
            logger.info("ReAct: AI offline, skipping heuristic analysis.")
            return result

        try:
            # --- THOUGHT: sample interesting endpoints ---
            endpoints = self._sample_endpoints(url_files)
            result["endpoints_sampled"] = len(endpoints)

            if not endpoints:
                logger.info("ReAct: no interesting endpoints found.")
                result["ok"] = True
                return result

            js_secrets = _safe_read_jsonl(js_secrets_file) if os.path.exists(js_secrets_file) else []
            prompt = self._build_react_prompt(endpoints, js_secrets)

            # --- THOUGHT: call LLM ---
            logger.info("ReAct: calling LLM for %d endpoints (target=%s)", len(endpoints), self.handle)
            llm_response = _call_llm_with_retry(self.ai, prompt, max_tokens=1000)

            if "[AI Offline]" in llm_response or "[API Error" in llm_response:
                logger.warning("ReAct: LLM unavailable (%s), skipping.", llm_response[:60])
                return result

            decisions = self._parse_llm_decision(llm_response)
            if not decisions:
                logger.info("ReAct: no actionable decisions from LLM.")
                result["ok"] = True
                return result

            inject_count = sum(1 for d in decisions if d.get("action", "").upper() == "INJECT")
            discard_count = len(decisions) - inject_count
            result["endpoints_injected"] = inject_count
            result["endpoints_discarded"] = discard_count

            logger.info(
                "ReAct: LLM decided INJECT=%d DISCARD=%d (target=%s)",
                inject_count, discard_count, self.handle,
            )

            # --- ACTION + OBSERVE: probe and collect ---
            new_findings = self._run_probes(decisions, findings_file)
            result["findings_added"] = new_findings
            result["ok"] = True

        except KeyboardInterrupt:
            raise
        except Exception as exc:
            logger.warning("ReAct: unexpected error in heuristic agent: %s", exc)
            result["ok"] = False

        return result
