import os, subprocess, shlex, re, io, shutil, sys
import logging
from core.ui import ui_log, Colors
from core.config import get_tool_timeout  # Centralized timeouts
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
    # Skip execution when not in a proper terminal (e.g., during automated tests)
    if not os.getenv('TERM') or not sys.stdout.isatty():
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
        # Log any stderr output from the tool (helps diagnose silent failures)
        if tmp_stderr:
            try:
                with open(tmp_stderr.name, 'r', encoding='utf-8', errors='ignore') as ef:
                    err_txt = ef.read(500).strip()
                if err_txt:
                    ui_log("ENGINE_WARN", f"{label} stderr: {err_txt[:120]}", Colors.WARNING)
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

def run_nuclei(input_file, output_file, tags="", stats_pipe=None, rate_limit=50):
    # -duc: skip update check. -timeout 5: per-request HTTP cap.
    # -c 25: limit concurrency to prevent hangs on slow targets.
    # -severity: limit to critical/high/medium only (avoids thousands of info/low templates).
    # No -stats/-sj: those conflict with -silent and output is discarded anyway.
    cmd = [find_tool("nuclei"), "-l", input_file, "-o", output_file,
           "-duc", "-silent", "-rl", str(rate_limit), "-c", "25",
           "-timeout", "5", "-severity", "critical,high,medium"]
    if tags:
        cmd.extend(["-tags", tags])
    run_cmd(cmd, "Nuclei", output_file, stats_pipe=stats_pipe)

def run_js_hunter(katana_file, output_file):
    """Extrai segredos de arquivos JavaScript encontrados pelo Katana."""
    ui_log("JS Hunter", "Analisando arquivos JS em busca de segredos...", Colors.INFO)
    
    secrets_found = []
    
    if not os.path.exists(katana_file):
        ui_log("JS Hunter", "Nenhum arquivo JS encontrado (Katana output ausente)", Colors.WARNING)
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        open(output_file, 'w').close()
        return
    
    with open(katana_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Check if line is a URL to a JS file
            if line.endswith('.js'):
                # Use JSHunter to extract real secrets from JS files
                try:
                    from recon.js_hunter import JSHunter
                    hunter = JSHunter()
                    extracted = hunter.extract(line)
                    for secret in extracted:
                        secrets_found.append({
                            'type': secret.get('type', 'Unknown'),
                            'value': secret.get('secret', ''),
                            'url': line,
                            'confidence': secret.get('confidence', 0.9)
                        })
                except Exception as e:
                    logging.debug(f"Failed to extract secrets from {line}: {e}")
    
    # Write results
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        for secret in secrets_found:
            f.write(f"{secret['type']}: {secret['value']} (encontrado em {secret['url']})\n")
    
    ui_log("JS Hunter", f"Encontrados {len(secrets_found)} potenciais segredos", Colors.WARNING if secrets_found else Colors.SUCCESS)