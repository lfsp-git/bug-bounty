import os, sys, time, threading, math, json, logging
from typing import Dict, List, Any

# UI Imports
from core.ui_manager import (
    ui_mission_header, ui_log, ui_update_status, ui_scan_summary, 
    ui_mission_footer, Colors, _live_view_data, _live_view_lock
)

# Engine Imports
from recon.engines import (
    run_subfinder, run_dnsx, run_uncover, run_nuclei, 
    run_httpx, run_katana_surgical, run_js_hunter, 
    apply_sniper_filter
)

# AI Imports
from core.ai_client import AIClient

# Diff Engine
from core.diff_engine import ReconDiff

# Rate limiting from config (default 50)
RATE_LIMIT = 50

MAX_SUBS_PER_TARGET = 2000 
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

def _run_with_progress(label, fn, live_tail_pipe=None):
    start_time = time.time()
    stop_event = threading.Event()
    history = _load_tool_times().get(label, [])
    avg_time = sum(history)/len(history) if history else 0
    
    def _spinner():
        idx, chars = 0, ['-', '\\', '|', '/']
        while not stop_event.is_set():
            elapsed = time.time() - start_time
            eta = f" | ETA: {int(avg_time - elapsed)}s" if avg_time > elapsed else ""
            ui_update_status(label, f"{chars[idx % 4]} {int(elapsed)}s{eta}")
            idx += 1
            time.sleep(0.2)

    t = threading.Thread(target=_spinner); t.start()
    try:
        fn()
    finally:
        stop_event.set(); t.join()
        elapsed_total = time.time() - start_time
        _record_tool_time(label, elapsed_total)
        ui_log(label, f"Done in {int(elapsed_total)}s", Colors.DIM)

def _count_lines(filepath):
    try:
        return sum(1 for _ in open(filepath, 'r', encoding='utf-8', errors='ignore'))
    except (FileNotFoundError, IOError) as e:
        logging.debug(f"Cannot count lines in {filepath}: {e}")
        return 0

def _count_findings(filepath):
    try:
        return sum(1 for _ in open(filepath, 'r', encoding='utf-8', errors='ignore'))
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
        with _live_view_lock:
            _live_view_data["Subfinder"]["status"] = "running"
        _run_with_progress("Subfinder", lambda: run_subfinder(dom_file, sub_file, rate_limit=RATE_LIMIT))
        with _live_view_lock:
            _live_view_data["Subfinder"]["status"] = "idle"
            _live_view_data["Subfinder"]["subs"] = _count_lines(sub_file) if os.path.exists(sub_file) else 0
        
        # DNSX: valida subdomínios e obtém IPs
        live_file = paths["live"]
        unv_file = paths["unv"]
        with _live_view_lock:
            _live_view_data["DNSX"]["status"] = "running"
        _run_with_progress("DNSX", lambda: run_dnsx(sub_file, live_file, rate_limit=RATE_LIMIT))
        with _live_view_lock:
            _live_view_data["DNSX"]["status"] = "idle"
            _live_view_data["DNSX"]["live"] = _count_lines(live_file) if os.path.exists(live_file) else 0
        
        # Uncover: detecta takeover potentials
        with _live_view_lock:
            _live_view_data["Uncover"]["status"] = "running"
        uncover_file = paths["sub"] + ".uncover"
        _run_with_progress("Uncover", lambda: run_uncover(domains, uncover_file))
        with _live_view_lock:
            _live_view_data["Uncover"]["status"] = "idle"
            _live_view_data["Uncover"]["takeovers"] = _count_lines(uncover_file) if os.path.exists(uncover_file) else 0
        
        # HTTPX: descobre endpoints
        httpx_file = paths["live"] + ".httpx"
        with _live_view_lock:
            _live_view_data["HTTPX"]["status"] = "running"
        _run_with_progress("HTTPX", lambda: run_httpx(live_file, httpx_file, rate_limit=RATE_LIMIT))
        with _live_view_lock:
            _live_view_data["HTTPX"]["status"] = "idle"
            _live_view_data["HTTPX"]["endpoints"] = _count_lines(httpx_file) if os.path.exists(httpx_file) else 0
        
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
        """Executa a fase tática: HTTPX, Katana, JS Hunter, Nuclei."""
        live_file = paths["live"]
        if not os.path.exists(live_file) or os.path.getsize(live_file) == 0:
            ui_log("INFO", "Nenhum subdomínio vivo. Pulando fase tática.", Colors.WARNING)
            return
        
        # Katana: crawling inteligente
        katana_file = paths["live"] + ".katana"
        with _live_view_lock:
            _live_view_data["Katana"]["status"] = "running"
        _run_with_progress("Katana", lambda: run_katana_surgical(live_file, katana_file, rate_limit=RATE_LIMIT))
        with _live_view_lock:
            _live_view_data["Katana"]["status"] = "idle"
            _live_view_data["Katana"]["crawled"] = _count_lines(katana_file) if os.path.exists(katana_file) else 0
        
        # JS Hunter: extrai segredos de arquivos JavaScript
        js_secrets_file = paths["live"] + ".js_secrets"
        with _live_view_lock:
            _live_view_data["JS Hunter"]["status"] = "running"
        _run_with_progress("JS Hunter", lambda: run_js_hunter(katana_file, js_secrets_file))
        with _live_view_lock:
            _live_view_data["JS Hunter"]["status"] = "idle"
            _live_view_data["JS Hunter"]["secrets"] = _count_lines(js_secrets_file) if os.path.exists(js_secrets_file) else 0
        
        # Nuclei: scanning de vulnerabilidades
        findings_file = paths["fin"]
        with _live_view_lock:
            _live_view_data["Nuclei"]["status"] = "running"
        _run_with_progress("Nuclei", lambda: run_nuclei(live_file, findings_file, "cve,misconfig,takeover", self.stats_pipe))
        with _live_view_lock:
            _live_view_data["Nuclei"]["status"] = "idle"
            _live_view_data["Nuclei"]["vulns"] = _count_findings(findings_file) if os.path.exists(findings_file) else 0
        
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
        from core.fp_filter import FalsePositiveKiller
        
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
                    
                    except json.JSONDecodeError:
                        ui_log("AI VALIDATION", f"Malformed JSON line, skipping", Colors.WARNING)
                        continue
                    except Exception as e:
                        ui_log("AI VALIDATION", f"Error: {str(e)[:40]}", Colors.ERROR)
                        validated_findings.append(line)  # Fallback: keep finding
            
            # Rewrite file with validated findings
            with open(findings_file, 'w', encoding='utf-8') as f:
                for finding in validated_findings:
                    f.write(finding + '\n')
            
            ui_log("AI VALIDATION", "Validation complete.", Colors.SUCCESS)
        except Exception as e:
            ui_log("AI VALIDATION", f"Validation failed: {str(e)[:50]}", Colors.ERROR)

    def run(self):
        h = self.target.get('handle', 'unknown')
        paths = {k: f"recon/baselines/{h}_{k}.txt" for k in ["dom", "sub", "live", "unv"]}
        paths["fin"] = f"recon/baselines/{h}_findings.jsonl"

        ui_mission_header(h, self.target.get('score', 0))
        self._run_recon_phase(paths, self.target.get('domains', []))
        self._run_vulnerability_phase(paths)
        
        # Coleta resultados para diff engine
        results = {
            'subdomains': _live_view_data["Subfinder"]["subs"],
            'endpoints': _live_view_data["HTTPX"]["endpoints"],
            'js_secrets': _live_view_data["JS Hunter"]["secrets"],
            'vulns': _live_view_data["Nuclei"]["vulns"],
        }
        ui_scan_summary(results)
        ui_mission_footer()
        
        # Salva baseline para diff engine
        from core.diff_engine import ReconDiff
        ReconDiff.save_baseline(h, results)
        return results


class ProOrchestrator:
    """Coordinator that manages missions using MissionRunner.

    Backwards-compatible start_mission: accepts either a single target_data dict
    or the legacy signature (handle, domains, db_path, score).
    """
    def __init__(self, config):
        self.config = config

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