import os, subprocess, shlex, re, io, shutil, sys, threading, json, time
import logging
from typing import List
from core.ui import ui_log, Colors
from core.config import get_tool_timeout, NUCLEI_RATE_LIMIT, NUCLEI_CONCURRENCY  # Centralized config
from recon.tool_discovery import find_tool

PDTM = os.environ.get("HUNT3R_PDTM_PATH", os.path.expanduser("~/.pdtm/go/bin/"))

def apply_sniper_filter(inp, outp):
    deny = [r'\.ns\.cloudflare\.com$', r'\.secondary\.cloudflare\.com$', r'^cf-\d{1,3}-', r'^ssl\d+\.cloudflare\.com$']
    rx = re.compile('|'.join(deny))
    juicy = []
    if not os.path.exists(inp): return inp
    with open(inp, 'r', encoding='utf-8', errors='ignore') as f:
        for l in f:
            t = l.strip()
            if t and not rx.search(t): juicy.append(t)
    os.makedirs(os.path.dirname(outp), exist_ok=True)
    with open(outp, 'w', encoding='utf-8') as f: f.write('\n'.join(juicy))
    return outp

def run_cmd(cmd_list, label, outp, stats_pipe=None, timeout_override=None):
    """Execute external command safely.
    Skips execution in non-interactive environments (no TERM or not a TTY) and if binary missing.
    Creates an empty output file to keep pipeline functional.
    """
    os.makedirs(os.path.dirname(outp), exist_ok=True)
    # Skip execution only when explicitly disabled or in test context.
    # Watchdog/service mode may run without a TTY and still must execute tools.
    if os.getenv("HUNT3R_DISABLE_TOOL_EXECUTION") == "1" or os.getenv("PYTEST_CURRENT_TEST"):
        ui_log("ENGINE_SKIP", f"Skipping {label} execution in non-interactive mode.", Colors.WARNING)
        open(outp, 'w').close()
        return
    # Determine if we need to capture stderr to a stats file
    stderr_dest = open(stats_pipe, 'w') if isinstance(stats_pipe, str) else subprocess.DEVNULL
    # Verify the executable exists and is executable
    exe_path = cmd_list[0]
    exe_exists = os.path.isfile(exe_path) and os.access(exe_path, os.X_OK)
    # If not found at the exact path, try to locate it in the system PATH using its basename
    if not exe_exists:
        exe_exists = shutil.which(os.path.basename(exe_path)) is not None
    if not exe_exists:
        ui_log("ENGINE_WARN", f"Binary not found for {label}: {exe_path}. Skipping execution.", Colors.WARNING)
        open(outp, 'w').close()
        if isinstance(stderr_dest, io.IOBase):
            stderr_dest.close()
        return
    # If no explicit stats pipe, capture stderr to a temp file so errors are visible
    tmp_stderr = None
    if stderr_dest is subprocess.DEVNULL:
        import tempfile
        tmp_stderr = tempfile.NamedTemporaryFile(mode='w', suffix=f'_{label.lower()}_stderr.log',
                                                  delete=False, encoding='utf-8')
        stderr_dest = tmp_stderr
    # Truncate output file before running to prevent tools from appending to stale data
    open(outp, 'w').close()
    try:
        # Use timeout from centralized config
        effective_timeout = timeout_override if timeout_override is not None else get_tool_timeout(label)
        subprocess.run(cmd_list, stdout=subprocess.DEVNULL, stderr=stderr_dest, check=False, timeout=effective_timeout)
    except subprocess.TimeoutExpired:
        ui_log("ENGINE_WARN", f"Timeout executing {label} after {effective_timeout}s. Skipping.", Colors.WARNING)
    except Exception as e:
        ui_log("ENGINE_ERR", f"Falha em {label}: {str(e)[:50]}", Colors.ERROR)
    finally:
        if isinstance(stderr_dest, io.IOBase):
            stderr_dest.close()
        # Log stderr only if it contains actual error messages (filter banners/ASCII art)
        if tmp_stderr:
            _ERR_KW = ('error', 'fail', 'fatal', 'panic', 'could not', 'unable', 'denied', 'refused', 'exception')
            try:
                with open(tmp_stderr.name, 'r', encoding='utf-8', errors='ignore') as ef:
                    err_txt = ef.read(500).strip()
                if err_txt:
                    if any(kw in err_txt.lower() for kw in _ERR_KW):
                        ui_log("ENGINE_WARN", f"{label} stderr: {err_txt[:120]}", Colors.WARNING)
                    else:
                        logging.debug(f"{label} stderr (info): {err_txt[:200]}")
                os.unlink(tmp_stderr.name)
            except OSError:
                pass

def run_subfinder(input_file, output_file, rate_limit=100):
    run_cmd([find_tool("subfinder"), "-dL", input_file, "-o", output_file, "-silent", f"-rate-limit={rate_limit}"], "Subfinder", output_file)

def run_dnsx(input_file, output_file, rate_limit=100):
    # Note: no -resp flag — keeps output as plain hostnames so HTTPX can consume it directly
    run_cmd([find_tool("dnsx"), "-l", input_file, "-o", output_file, "-wd", "-silent", "-a", f"-rate-limit={rate_limit}"], "DNSX", output_file)

# Known placeholder values that must never be treated as real Censys credentials
_CENSYS_PLACEHOLDERS = frozenset({
    "hunt3r", "censys", "your_censys_api_id", "placeholder", "changeme",
    "your_api_id", "your_id", "api_id", "apiid", "test", "example",
    "none", "null", "undefined", "dummy", "fake", "secret",
})

def _is_valid_censys_id(value: str) -> bool:
    """Accept any Censys API token that is not an obvious placeholder.

    Censys v2 supports multiple credential formats:
      - UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
      - Email: user@example.com
      - Short API token: e.g. 'Pu1KHr6r' (≥ 6 printable non-whitespace chars)

    All are accepted as long as the value is not in the known-placeholder list.
    """
    if not value or len(value) < 6:
        return False
    if value.lower() in _CENSYS_PLACEHOLDERS:
        return False
    # Must be printable chars without whitespace
    import re as _re
    return bool(_re.match(r'^[\S]+$', value))

def _sync_uncover_providers() -> List[str]:
    """Sync .env API keys into uncover provider-config.yaml.

    Returns the list of enabled provider names so run_uncover can pass -e flags.
    Censys is skipped when CENSYS_API_ID looks like an obvious placeholder.

    Accepted formats for CENSYS_API_ID:
      - Standard UUID (hex+dashes, 32-36 chars)
      - Email address
      - Short alphanumeric API token (≥ 6 printable chars, not a known placeholder)
    """
    cfg_path = os.path.expanduser("~/.config/uncover/provider-config.yaml")
    os.makedirs(os.path.dirname(cfg_path), exist_ok=True)

    shodan_key  = os.getenv("SHODAN_API_KEY", "").strip()
    chaos_key   = os.getenv("CHAOS_KEY", "").strip()
    censys_id   = os.getenv("CENSYS_API_ID", "").strip()
    censys_sec  = os.getenv("CENSYS_API_SECRET", "").strip()

    censys_valid = _is_valid_censys_id(censys_id) and bool(censys_sec)

    lines = []
    enabled = []
    if shodan_key:
        lines.append(f"shodan:\n  - {shodan_key}")
        enabled.append("shodan")
    if censys_valid:
        lines.append(f"censys:\n  - {censys_id}:{censys_sec}")
        enabled.append("censys")
    else:
        if censys_id:
            logging.warning(
                f"Censys CENSYS_API_ID='{censys_id}' looks like a placeholder or is too short "
                "(min 6 chars). Censys disabled — set your real API token in .env."
            )

    if lines:
        try:
            with open(cfg_path, "w") as f:
                f.write("\n".join(lines) + "\n")
        except OSError as e:
            logging.warning(f"Could not write uncover provider config: {e}")

    return enabled

def run_uncover(domains, output_file):
    if not domains:
        return
    providers = _sync_uncover_providers()
    if not providers:
        logging.warning("run_uncover: no valid API keys configured (Shodan/Censys). Skipping.")
        open(output_file, "w").close()
        return
    cmd = [find_tool("uncover"), "-q", ",".join(domains),
           "-o", output_file, "-silent",
           "-e", ",".join(providers)]
    run_cmd(cmd, "Uncover", output_file)

def run_httpx(input_file, output_file, rate_limit=100):
    # Adaptive timeout: base 180s + 0.5s per host above 100, max 900s
    host_count = 0
    if os.path.exists(input_file):
        try:
            with open(input_file) as _f:
                host_count = sum(1 for l in _f if l.strip())
        except OSError:
            pass
    adaptive_timeout = min(180 + max(0, host_count - 100) // 2, 900)
    # -random-agent is default true; -ua is not a valid flag (caused 0-second silent exit)
    run_cmd([find_tool("httpx"), "-l", input_file, "-o", output_file, "-silent", "-rate-limit", str(rate_limit)], "HTTPX", output_file, timeout_override=adaptive_timeout)

def run_katana_surgical(input_file, output_file, rate_limit=100):
    """Crawling com URLs do HTTPX.

    Timeout adaptativo: 300s para ≤30 URLs, +6s por URL adicional,
    máx 900s — evita timeout em alvos grandes sem travar para sempre.
    """
    endpoint_count = 0
    if os.path.exists(input_file):
        try:
            with open(input_file) as _f:
                endpoint_count = sum(1 for l in _f if l.strip())
        except OSError:
            pass

    base_timeout = 300
    per_url_extra = max(0, endpoint_count - 30) * 6
    adaptive_timeout = min(base_timeout + per_url_extra, 900)

    cmd = [find_tool("katana"), "-list", input_file, "-o", output_file, "-silent",
           f"-rate-limit={rate_limit}", "-timeout", "15", "-depth", "2",
           "-crawl-duration", str(adaptive_timeout)]
    run_cmd(cmd, "Katana", output_file)

def run_nuclei(
    input_file,
    output_file,
    tags="",
    stats_pipe=None,
    rate_limit=None,
    progress_callback=None,
    custom_templates=None,
    timeout_override=None,
):
    """Run Nuclei with -stats -sj for real-time progress via stderr streaming.
    
    Uses Popen instead of run_cmd to parse JSON stats from stderr in real-time.
    No -silent: allows -stats -sj to output progress data.
    Timeout: controlled by config (default 3600s — vulns at any cost).
    custom_templates: list of template file paths or directories to include
    """
    if rate_limit is None:
        rate_limit = NUCLEI_RATE_LIMIT
    exe = find_tool("nuclei")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    # Skip only when explicitly disabled or in test context.
    if os.getenv("HUNT3R_DISABLE_TOOL_EXECUTION") == "1" or os.getenv("PYTEST_CURRENT_TEST"):
        ui_log("ENGINE_SKIP", "Skipping Nuclei in non-interactive mode.", Colors.WARNING)
        open(output_file, 'w').close()
        return

    # Verify binary
    exe_exists = os.path.isfile(exe) and os.access(exe, os.X_OK)
    if not exe_exists:
        exe_exists = shutil.which(os.path.basename(exe)) is not None
    if not exe_exists:
        ui_log("ENGINE_WARN", "Binary not found: nuclei. Skipping.", Colors.WARNING)
        open(output_file, 'w').close()
        return

    # Verify nuclei templates exist; if not, auto-download and skip this run if still missing.
    templates_dir = os.path.expanduser("~/nuclei-templates")
    if not os.path.isdir(templates_dir):
        ui_log("ENGINE_WARN", "Nuclei templates not found. Downloading via 'nuclei -update-templates'...", Colors.WARNING)
        try:
            subprocess.run([exe, "-update-templates"], timeout=300, capture_output=True)
        except (OSError, subprocess.TimeoutExpired) as e:
            logging.warning(f"Nuclei template download failed: {e}")
        if not os.path.isdir(templates_dir):
            ui_log("ENGINE_WARN", "Nuclei templates still missing after update. Skipping scan.", Colors.WARNING)
            open(output_file, 'w').close()
            return
        ui_log("ENGINE_WARN", "Nuclei templates downloaded. Proceeding.", Colors.SUCCESS)

    # Truncate output file
    open(output_file, 'w').close()

    # -duc: skip update check. -stats -sj: JSON stats to stderr.
    # -j: JSONL output format (required for _safe_read_jsonl parsing).
    # -rl: rate limit. -c: concurrency. -timeout 5: per-request HTTP cap.
    # -severity: critical/high/medium only.
    cmd = [exe, "-l", input_file, "-o", output_file,
           "-duc", "-j", "-stats", "-sj", "-rl", str(rate_limit), "-c", str(NUCLEI_CONCURRENCY),
           "-timeout", "5", "-severity", "critical,high,medium"]
    if tags:
        cmd.extend(["-tags", tags])
    if custom_templates:
        # -t: template files or directories to run (not -td which means template-display)
        for template_path in custom_templates:
            cmd.extend(["-t", template_path])

    timeout = int(timeout_override) if isinstance(timeout_override, (int, float)) and timeout_override > 0 else get_tool_timeout("nuclei")

    proc = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                text=True, bufsize=1)

        # Nuclei banner lines to suppress from logs (ASCII art + boilerplate)
        _BANNER_SKIP = re.compile(
            r'^\s*(?:__|____|\s*/\s*|\\|_/|nuclei.*v[\d.]+|projectdiscovery\.io|'
            r'Use.*flag.*for.*help|Could not|Warning|Warn:)',
            re.IGNORECASE,
        )
        _ERROR_KW = ('error', 'fail', 'fatal', 'panic', 'could not', 'unable', 'denied',
                     'refused', 'exception', 'invalid', 'not found')

        def _read_stderr():
            stderr = proc.stderr
            if stderr is None:
                return
            try:
                for line in stderr:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith('{'):
                        try:
                            stats = json.loads(line)
                            if progress_callback:
                                progress_callback(stats)
                        except (json.JSONDecodeError, ValueError):
                            pass
                    else:
                        # Only log actionable lines (errors/warnings) — suppress banner/boilerplate
                        if not _BANNER_SKIP.match(line):
                            ll = line.lower()
                            if any(kw in ll for kw in _ERROR_KW):
                                logging.warning(f"Nuclei: {line[:200]}")
                            else:
                                logging.debug(f"Nuclei: {line[:200]}")
            except (OSError, ValueError):
                pass
            finally:
                try:
                    stderr.close()
                except OSError:
                    pass

        reader = threading.Thread(target=_read_stderr, daemon=True)
        reader.start()

        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            ui_log("ENGINE_WARN", f"Timeout executing Nuclei after {timeout}s.", Colors.WARNING)

        reader.join(timeout=2)

        # Crash detection: returncode != 0 means Nuclei exited abnormally.
        # returncode 1 with empty output = tags matched 0 templates (silent failure).
        rc = proc.returncode if proc else None
        if rc not in (None, 0):
            output_empty = not os.path.exists(output_file) or os.path.getsize(output_file) == 0
            if output_empty:
                msg = f"Nuclei exited with code {rc} and produced no output (tags may have matched 0 templates)"
                ui_log("ENGINE_WARN", msg, Colors.WARNING)
                raise RuntimeError(msg)
            else:
                ui_log("ENGINE_WARN", f"Nuclei exited with code {rc} but output exists — partial results.", Colors.WARNING)
    except KeyboardInterrupt:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        raise
    except Exception as e:
        ui_log("ENGINE_ERR", f"Nuclei failed: {str(e)[:50]}", Colors.ERROR)
        raise

SECRET_SEVERITY = {
    'aws_access_key': 'critical', 'aws_secret_key': 'critical', 'private_key': 'critical',
    'password_or_secret': 'high', 'stripe_key': 'high', 'slack_webhook': 'high', 'discord_webhook': 'high',
    'generic_api_key': 'medium', 'auth_token': 'medium', 'jwt_token': 'medium',
    'firebase_db': 'medium', 'google_api': 'medium',
    'interactsh': 'low', 'generic_url_param': 'low',
}

def run_js_hunter(katana_file, output_file):
    """Extrai segredos de arquivos JavaScript encontrados pelo Katana.
    Output: JSONL with {type, value, source, url, severity} per line.
    """
    ui_log("JS Hunter", "Analisando arquivos JS em busca de segredos...", Colors.INFO)
    
    # Truncate output at start (consistent with all other tools)
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    open(output_file, 'w').close()
    
    secrets_found = []
    
    if not os.path.exists(katana_file):
        ui_log("JS Hunter", "Nenhum arquivo JS encontrado (Katana output ausente)", Colors.WARNING)
        return
    
    from recon.js_hunter import JSHunter
    
    # Deduplicate JS URLs before scanning (Katana often outputs duplicate lines)
    seen_urls: set = set()
    js_urls = []
    with open(katana_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            url = line.strip()
            if not url:
                continue
            if url.endswith(('.js', '.mjs', '.ts')) and url not in seen_urls:
                seen_urls.add(url)
                js_urls.append(url)

    for url in js_urls:
        time.sleep(0.05)  # 20 req/s max per worker — avoid hammering hosts
        try:
            extracted = JSHunter.scan_url(url)
            for secret in extracted:
                stype = secret.get('type', 'unknown')
                secrets_found.append({
                    'type': stype,
                    'value': secret.get('value', ''),
                    'source': url,
                    'url': url,
                    'severity': SECRET_SEVERITY.get(stype, 'low'),
                })
        except Exception as e:
            logging.debug(f"Failed to extract secrets from {url}: {e}")
    
    # Write results as JSONL (compatible with notifier + reporter)
    with open(output_file, 'w', encoding='utf-8') as f:
        for secret in secrets_found:
            f.write(json.dumps(secret) + '\n')
    
    ui_log("JS Hunter", f"Encontrados {len(secrets_found)} potenciais segredos", Colors.WARNING if secrets_found else Colors.SUCCESS)
