import os, subprocess, shlex, re, io, shutil, sys, threading, json
import logging
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

def run_cmd(cmd_list, label, outp, stats_pipe=None):
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
        subprocess.run(cmd_list, stdout=subprocess.DEVNULL, stderr=stderr_dest, check=False, timeout=get_tool_timeout(label))
    except subprocess.TimeoutExpired:
        ui_log("ENGINE_WARN", f"Timeout executing {label} after {get_tool_timeout(label)}s. Skipping.", Colors.WARNING)
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

def run_uncover(domains, output_file):
    if not domains: return
    run_cmd([find_tool("uncover"), "-q", ",".join(domains), "-o", output_file, "-silent"], "Uncover", output_file)

def run_httpx(input_file, output_file, rate_limit=100):
    # -random-agent is default true; -ua is not a valid flag (caused 0-second silent exit)
    run_cmd([find_tool("httpx"), "-l", input_file, "-o", output_file, "-silent", "-rate-limit", str(rate_limit)], "HTTPX", output_file)

def run_katana_surgical(input_file, output_file, rate_limit=100):
    """Crawling com URLs do HTTPX. -timeout limita por-request para evitar travamentos."""
    cmd = [find_tool("katana"), "-list", input_file, "-o", output_file, "-silent",
           f"-rate-limit={rate_limit}", "-timeout", "15", "-depth", "2"]
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
        # Add custom template directories/files
        for template_path in custom_templates:
            cmd.extend(["-td", template_path])

    timeout = int(timeout_override) if isinstance(timeout_override, (int, float)) and timeout_override > 0 else get_tool_timeout("nuclei")

    proc = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                text=True, bufsize=1)

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
                        # Log non-JSON lines (errors, template loading, etc.)
                        logging.info(f"Nuclei: {line[:200]}")
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
    
    with open(katana_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            url = line.strip()
            if not url:
                continue
            if url.endswith(('.js', '.mjs', '.ts')):
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
