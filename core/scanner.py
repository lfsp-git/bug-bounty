from __future__ import annotations
import os, sys, time, threading, math, json, logging
from typing import Dict, List, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from core.ai import IntelMiner

# UI Imports
from core.ui import (
    ui_mission_header, ui_log, ui_update_status, ui_scan_summary,
    ui_mission_footer, Colors, _live_view_data, _live_view_lock, ui_set_mission_meta
)

# Engine Imports
from recon.engines import (
    run_subfinder, run_dnsx, run_uncover, run_nuclei, 
    run_httpx, run_katana_surgical, run_js_hunter, 
    apply_sniper_filter
)

# AI Imports
from core.ai import AIClient

# Diff Engine
from core.storage import ReconDiff

# Rate limiting
from core.config import get_rate_limiter, RATE_LIMIT, REQUESTS_PER_SECOND, MAX_SUBS_PER_TARGET, NUCLEI_RATE_LIMIT

# Notification & Reporting
from core.notifier import NotificationDispatcher
from core.reporter import BugBountyReporter

_CACHE_TIMES = "recon/tool_times.json"

def count_lines(filepath: str) -> int:
    """Count lines safely with context manager to prevent file descriptor leaks"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return sum(1 for _ in f)
    except FileNotFoundError:
        return 0

def _load_tool_times() -> Dict[str, Any]:
    if os.path.exists(_CACHE_TIMES):
        try:
            with open(_CACHE_TIMES, 'r') as f: return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logging.warning(f"Failed to load tool times cache: {e}")
    return {}

def _record_tool_time(label: str, elapsed: float):
    data = _load_tool_times()
    key = label.split(' [')[0]
    history = data.get(key, [])
    if not isinstance(history, list): history = []
    history.append(elapsed)
    data[key] = history[-5:]
    try:
        with open(_CACHE_TIMES, 'w') as f: json.dump(data, f)
    except (IOError, TypeError) as e:
        logging.warning(f"Failed to save tool times: {e}")

def _run_with_progress(label, fn, live_tail_pipe=None, extra_stats_fn=None):
    """Execute tool with progress spinner. Returns True on success, False on error."""
    start_time = time.time()
    stop_event = threading.Event()
    history = _load_tool_times().get(label, [])
    avg_time = sum(history)/len(history) if history else 0
    
    def _spinner():
        idx, chars = 0, ['-', '\\', '|', '/']
        while not stop_event.is_set():
            elapsed = time.time() - start_time
            eta = f" | ETA: {int(avg_time - elapsed)}s" if avg_time > elapsed else ""
            extra = extra_stats_fn() if extra_stats_fn else ""
            ui_update_status(label, f"{chars[idx % 4]} {int(elapsed)}s{eta}{extra}")
            idx += 1
            time.sleep(0.2)

    t = threading.Thread(target=_spinner); t.start()
    success = False
    try:
        fn()  # Execute tool
        elapsed_total = time.time() - start_time
        _record_tool_time(label, elapsed_total)
        ui_log(label, f"Done in {int(elapsed_total)}s", Colors.DIM)
        success = True
    except KeyboardInterrupt:
        stop_event.set()
        t.join(timeout=0.5)
        raise  # propagate cleanly so watchdog/scanner can handle it
    except Exception as e:
        elapsed_total = time.time() - start_time
        logging.warning(f"{label} failed after {int(elapsed_total)}s: {str(e)[:60]}")
        ui_log(label, f"Error (continuing): {str(e)[:40]}", Colors.WARNING)
    finally:
        stop_event.set()
        if t.is_alive():
            t.join(timeout=2.0)  # give spinner up to 2s to exit cleanly (was 0.5)
    return success

def _count_lines(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as fh:
            return sum(1 for _ in fh)
    except (FileNotFoundError, IOError) as e:
        logging.debug(f"Cannot count lines in {filepath}: {e}")
        return 0

def _tool_start(name: str, input_count: int = 0):
    """Mark tool as running in live view with start_time, historical ETA, and input count."""
    history = _load_tool_times().get(name, [])
    avg = sum(history) / len(history) if history else 60.0
    with _live_view_lock:
        _live_view_data[name]["status"] = "running"
        _live_view_data[name]["start_time"] = time.time()
        _live_view_data[name]["eta"] = avg
        _live_view_data[name]["input_count"] = input_count

def _tool_done(name: str, count_key: str, count_file: str = ""):
    """Mark tool as finished in live view and update count from file."""
    count = _count_lines(count_file) if count_file and os.path.exists(count_file) else 0
    with _live_view_lock:
        _live_view_data[name]["status"] = "finished"
        _live_view_data[name]["start_time"] = None
        _live_view_data[name][count_key] = count

def _tool_error(name: str):
    """Mark tool as error in live view."""
    with _live_view_lock:
        _live_view_data[name]["status"] = "error"
        _live_view_data[name]["start_time"] = None

def _nuclei_progress_callback(stats):
    """Update live view with Nuclei stats from -sj JSON output."""
    with _live_view_lock:
        d = _live_view_data["Nuclei"]
        d["requests_done"] = stats.get("requests", stats.get("sent", 0))
        d["requests_total"] = stats.get("total", 0)
        d["rps"] = stats.get("rps", 0)
        d["matched"] = stats.get("matched", 0)

def _nuclei_extra_stats() -> str:
    """Return real-time Nuclei stats string for spinner display."""
    with _live_view_lock:
        d = _live_view_data["Nuclei"]
        rps = d.get("rps", 0)
        done = d.get("requests_done", 0)
        total = d.get("requests_total", 0)
        matched = d.get("matched", 0)
    if total > 0:
        return f" | Req/s {rps} | {done}/{total} | {matched} hits"
    return ""

def _count_findings(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as fh:
            return sum(1 for _ in fh)
    except (FileNotFoundError, IOError) as e:
        logging.debug(f"Cannot count findings in {filepath}: {e}")
        return 0


class MissionRunner:
    """Handles a single mission lifecycle: prepare, run vulnerability phase, and finalize."""
    def __init__(self, target_data, stats_pipe=None, config=None):
        self.target = target_data
        self.stats_pipe = stats_pipe
        self.config = config or {}

    def _run_recon_phase(self, paths, domains):
        """Executa a fase de reconhecimento: subfinder, dnsx, uncover, httpx."""
        # Cria arquivo com domínios iniciais
        dom_file = paths["dom"]
        os.makedirs(os.path.dirname(dom_file), exist_ok=True)
        with open(dom_file, 'w') as f:
            for d in domains:
                f.write(d + '\n')
        
        # Subfinder: encontra subdomínios
        sub_file = paths["sub"]
        limiter = get_rate_limiter(REQUESTS_PER_SECOND)
        limiter.wait_and_record(self.target.get('handle', 'unknown'))
        _tool_start("Subfinder", input_count=count_lines(dom_file))
        ok = _run_with_progress("Subfinder", lambda: run_subfinder(dom_file, sub_file, rate_limit=RATE_LIMIT))
        _tool_done("Subfinder", "subs", sub_file) if ok else _tool_error("Subfinder")
        
        # DNSX: valida subdomínios e obtém IPs
        live_file = paths["live"]
        unv_file = paths["unv"]
        limiter.wait_and_record(self.target.get('handle', 'unknown'))
        _tool_start("DNSX", input_count=count_lines(sub_file))
        ok = _run_with_progress("DNSX", lambda: run_dnsx(sub_file, live_file, rate_limit=RATE_LIMIT))
        _tool_done("DNSX", "live", live_file) if ok else _tool_error("DNSX")
        
        # Uncover: detecta takeover potentials
        limiter.wait_and_record(self.target.get('handle', 'unknown'))
        uncover_file = paths["sub"] + ".uncover"
        _tool_start("Uncover")
        ok = _run_with_progress("Uncover", lambda: run_uncover(domains, uncover_file))
        _tool_done("Uncover", "takeovers", uncover_file) if ok else _tool_error("Uncover")
        
        # HTTPX: descobre endpoints (output = full URLs with protocol)
        httpx_file = paths["live"] + ".httpx"
        limiter.wait_and_record(self.target.get('handle', 'unknown'))
        _tool_start("HTTPX", input_count=count_lines(live_file))
        ok = _run_with_progress("HTTPX", lambda: run_httpx(live_file, httpx_file, rate_limit=RATE_LIMIT))
        _tool_done("HTTPX", "endpoints", httpx_file) if ok else _tool_error("HTTPX")
        
        # Para obter não resolvidos, comparar com a lista de subdomínios
        if os.path.exists(sub_file) and os.path.exists(live_file):
            with open(sub_file, 'r') as f_sub, open(live_file, 'r') as f_live:
                subs = set(line.strip() for line in f_sub if line.strip())
                lives = set(line.strip() for line in f_live if line.strip())
            unv = subs - lives
            with open(unv_file, 'w') as f_unv:
                for u in unv:
                    f_unv.write(u + '\n')

    def _run_tactical_phase(self, paths):
        """Executa a fase tática: Katana, JS Hunter, Nuclei."""
        live_file = paths["live"]
        if not os.path.exists(live_file) or os.path.getsize(live_file) == 0:
            ui_log("INFO", "Nenhum subdomínio vivo. Pulando fase tática.", Colors.WARNING)
            return
        
        limiter = get_rate_limiter(REQUESTS_PER_SECOND)
        
        # Use HTTPX output (full URLs) as Katana/Nuclei input when available
        httpx_file = paths["live"] + ".httpx"
        has_httpx = os.path.exists(httpx_file) and os.path.getsize(httpx_file) > 0
        recon_input = httpx_file if has_httpx else live_file
        
        # Katana: crawling inteligente com URLs do HTTPX
        katana_file = paths["live"] + ".katana"
        limiter.wait_and_record(self.target.get('handle', 'unknown'))
        _tool_start("Katana", input_count=count_lines(recon_input))
        ok = _run_with_progress("Katana", lambda: run_katana_surgical(recon_input, katana_file, rate_limit=RATE_LIMIT))
        _tool_done("Katana", "crawled", katana_file) if ok else _tool_error("Katana")
        
        # JS Hunter: extrai segredos de arquivos JavaScript
        js_secrets_file = paths["live"] + ".js_secrets"
        limiter.wait_and_record(self.target.get('handle', 'unknown'))
        _tool_start("JS Hunter")
        ok = _run_with_progress("JS Hunter", lambda: run_js_hunter(katana_file, js_secrets_file))
        _tool_done("JS Hunter", "secrets", js_secrets_file) if ok else _tool_error("JS Hunter")
        
        # Nuclei: scanning de vulnerabilidades com URLs do HTTPX
        findings_file = paths["fin"]
        limiter.wait_and_record(self.target.get('handle', 'unknown'))
        _tool_start("Nuclei", input_count=count_lines(recon_input))
        ok = _run_with_progress("Nuclei", lambda: run_nuclei(
            recon_input, findings_file, tags="cve,misconfig,takeover",
            rate_limit=NUCLEI_RATE_LIMIT, progress_callback=_nuclei_progress_callback),
            extra_stats_fn=_nuclei_extra_stats)
        _tool_done("Nuclei", "vulns", findings_file) if ok else _tool_error("Nuclei")
        
        # Consolidar filtragem e validação em um passo único
        if os.path.exists(findings_file):
            self._filter_and_validate_findings(findings_file)

    def _run_vulnerability_phase(self, paths):
        # Aplica filtro sniper
        ns = paths.get("live", "")
        if not os.path.exists(ns) or os.path.getsize(ns) == 0:
            return

        ns_clean = f"{ns}_clean"
        apply_sniper_filter(ns, ns_clean)
        ns = ns_clean

        sub_count = count_lines(ns)
        if sub_count > MAX_SUBS_PER_TARGET:
            ui_log("GUARD", f"Alvo abusivo ({sub_count} subs). Truncando lista", Colors.WARNING)
            logging.warning(f"Subdomain truncation for {self.target.get('handle', 'unknown')}: {sub_count} subs → {MAX_SUBS_PER_TARGET} subs (lost {sub_count - MAX_SUBS_PER_TARGET})")
            t_ns = f"{ns}_truncated"
            with open(ns, 'r') as f, open(t_ns, 'w') as o:
                for i, l in enumerate(f):
                    if i >= MAX_SUBS_PER_TARGET: break
                    o.write(l)
            ns = t_ns

        # Executa fase tática
        self._run_tactical_phase(paths)
    
    def _filter_and_validate_findings(self, findings_file):
        """Single consolidation point: FP filtering + AI validation"""
        from core.filter import FalsePositiveKiller
        
        # Step 1: Apply FalsePositiveKiller (in-place)
        FalsePositiveKiller.sanitize_findings(findings_file)
        
        # Step 2: AI validation only if score warrants it
        if self.target.get('score', 0) >= 80:
            self._validate_findings_with_ai(findings_file)
        else:
            ui_log("AI VALIDATION", "Score < 80. Pulando validação com IA.", Colors.INFO)
    
    def _validate_findings_with_ai(self, findings_file):
        """Usa IA para validar vulnerabilidades críticas/high."""
        ai_client = AIClient()
        if not ai_client.api_key or not ai_client.selected_model:
            ui_log("AI VALIDATION", "IA offline. Pulando validação.", Colors.WARNING)
            return
        
        if not os.path.exists(findings_file) or os.path.getsize(findings_file) == 0:
            ui_log("AI VALIDATION", "Sem findings para validar.", Colors.INFO)
            return
        
        ui_log("AI VALIDATION", "Validando vulnerabilidades críticas com IA...", Colors.INFO)
        
        validated_findings = []
        critical_keywords = ['critical', 'high', 'rce', 'sql', 'xss', 'xxe', 'misconfig', 'takeover']
        
        try:
            with open(findings_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:  # Skip empty lines
                        continue
                    
                    try:
                        vuln = json.loads(line)
                    except json.JSONDecodeError as e:
                        logging.warning(f"Skipping malformed JSONL in {findings_file}: {e}")
                        continue
                    
                    template_id = vuln.get('template-id', '').lower()
                    host = vuln.get('host', '')
                    
                    # Only validate critical/high findings
                    is_critical = any(keyword in template_id for keyword in critical_keywords)
                    
                    if is_critical:
                        prompt = f"""Analyze: Is this a real vulnerability?
                            
Target: {host}
Template: {template_id}
Respond only: VALID or INVALID"""
                        response = ai_client.complete(prompt, max_tokens=10)
                        
                        if 'VALID' in response.upper():
                            validated_findings.append(line)
                        else:
                            ui_log("AI VALIDATION", f"Rejected: {host} ({template_id})", Colors.WARNING)
                    else:
                        validated_findings.append(line)
            
            # Rewrite file with validated findings
            with open(findings_file, 'w', encoding='utf-8') as f:
                for finding in validated_findings:
                    f.write(finding + '\n')
            
            ui_log("AI VALIDATION", "Validation complete.", Colors.SUCCESS)
        except Exception as e:
            ui_log("AI VALIDATION", f"Validation failed: {str(e)[:50]}", Colors.ERROR)

    def _notify_and_report(self, paths: dict, results: dict):
        """Send notifications and generate bug bounty report after scan."""
        h = self.target.get('handle', 'unknown')
        findings_path = paths["fin"]
        js_secrets_path = paths["live"] + ".js_secrets"

        # 1. Notify via Telegram (Critical/High/Medium) and Discord (Low/Info)
        try:
            NotificationDispatcher.alert_nuclei(findings_path, h)
        except Exception as e:
            logging.warning(f"Notification failed: {e}")

        # 2. Alert JS secrets to Telegram
        try:
            NotificationDispatcher.alert_js_secrets(js_secrets_path, h)
        except Exception as e:
            logging.warning(f"JS secrets notification failed: {e}")

        # 3. Generate bug bounty report (Markdown, ready for submission)
        try:
            reporter = BugBountyReporter(h)
            report_path = reporter.generate(
                findings_path=findings_path,
                js_secrets_path=js_secrets_path,
                subdomains_count=results.get('subdomains', 0),
                endpoints_count=results.get('endpoints', 0),
            )
            if report_path:
                ui_log("REPORT", f"Bug bounty report: {report_path}", Colors.SUCCESS)
        except Exception as e:
            logging.warning(f"Report generation failed: {e}")

    def run(self):
        h = self.target.get('handle', 'unknown')
        target_dir = f"recon/baselines/{h}"
        paths = {k: f"{target_dir}/{k}.txt" for k in ["dom", "sub", "live", "unv"]}
        paths["fin"] = f"{target_dir}/findings.jsonl"
        os.makedirs(target_dir, exist_ok=True)

        ui_mission_header(h, self.target.get('score', 0))
        ui_set_mission_meta(self.target.get('original_handle', h))
        try:
            self._run_recon_phase(paths, self.target.get('domains', []))
            self._run_vulnerability_phase(paths)
        except KeyboardInterrupt:
            ui_log("MISSION", "Interrompido pelo usuario (CTRL+C)", Colors.WARNING)
            ui_mission_footer()
            raise
        
        # Coleta resultados para diff engine (lock protects concurrent live_view reads)
        with _live_view_lock:
            results = {
                'target': self.target.get('handle', 'unknown'),
                'score': self.target.get('score', 0),
                'subdomains': _live_view_data["Subfinder"]["subs"],
                'alive': _live_view_data["DNSX"]["live"],
                'endpoints': _live_view_data["HTTPX"]["endpoints"],
                'js_secrets': _live_view_data["JS Hunter"]["secrets"],
                'vulns': _live_view_data["Nuclei"]["vulns"],
            }
        # Stop live view FIRST so its thread doesn't race with ui_scan_summary prints
        ui_mission_footer()
        ui_scan_summary(results)
        
        # Salva baseline para diff engine
        ReconDiff.save_baseline(h, results)

        # Notifica e gera relatório (EXCALIBUR pipeline final step)
        self._notify_and_report(paths, results)

        return results


class ProOrchestrator:
    """Coordinator that manages missions using MissionRunner.

    Backwards-compatible start_mission: accepts either a single target_data dict
    or the legacy signature (handle, domains, db_path, score).
    """
    def __init__(self, config):
        self.config = config
        self.intel: IntelMiner | None = None

    def _ensure_intel(self):
        """Lazily initialize IntelMiner (requires AIClient)."""
        if self.intel is None:
            from core.ai import AIClient, IntelMiner
            self.intel = IntelMiner(AIClient())

    def start_mission(self, *args, stats_pipe=None):
        """Start a mission.

        Usage:
          start_mission(target_data_dict, stats_pipe=None)
        or
          start_mission(handle, domains, db_path, score, stats_pipe=None)
        """
        # Accept new dict-based API
        if len(args) == 1 and isinstance(args[0], dict):
            target = args[0]
        # Accept legacy positional API for backward compatibility
        elif len(args) >= 4:
            handle, domains, db_path, score = args[:4]
            target = {
                'handle': handle,
                'domains': domains,
                'score': score,
                'db_path': db_path,
                'original_handle': handle
            }
        else:
            raise TypeError("start_mission expects either (target_data_dict[, stats_pipe]) or (handle, domains, db_path, score[, stats_pipe])")

        runner = MissionRunner(target, stats_pipe, config=self.config)
        runner.run()