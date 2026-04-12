from __future__ import annotations
import os, sys, time, threading, math, json, logging
from typing import Dict, List, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from core.intel import IntelMiner

# UI Imports
from core.ui import (
    ui_mission_header, ui_log, ui_update_status, ui_scan_summary,
    ui_mission_footer, Colors, _live_view_data, _live_view_lock, ui_set_mission_meta,
    _get_current_worker, ui_worker_tool_started, ui_worker_tool_finished,
    ui_worker_tool_cached, ui_worker_tool_error, ui_worker_nuclei_update,
    set_worker_context,
)

# Engine Imports
from recon.tools import (
    run_subfinder, run_dnsx, run_uncover, run_nuclei, 
    run_httpx, run_katana_surgical, run_js_hunter, 
    run_naabu, run_urlfinder,
    apply_sniper_filter
)

# Tech Detection
from recon.tech_detector import TechDetector

# Custom Templates
from recon.custom_templates import load_custom_templates, get_custom_template_tags

# AI Imports
from core.intel import AIClient

# ReAct Heuristic Agent
from core.heuristic_agent import ReActHeuristicAgent

# Diff Engine
from core.state import ReconDiff

# Rate limiting
from core.config import get_rate_limiter, RATE_LIMIT, REQUESTS_PER_SECOND, MAX_SUBS_PER_TARGET, NUCLEI_RATE_LIMIT

# Notification & Reporting
from core.output import NotificationDispatcher, BugBountyReporter

_CACHE_TIMES = "recon/tool_times.json"
_RECORD_TOOL_TIMES = True  # Can be disabled in watchdog mode to prevent cache modification
_NUCLEI_TIMEOUT_LIVE_HOST_THRESHOLD = 400
_NUCLEI_TIMEOUT_LARGE_SCAN = 5400
# When stealth dir mode is active (valid_tdirs non-empty), template dirs contain
# HOST-level checks (misconfiguration, exposures, takeovers, default-logins).
# Running them against thousands of crawled URLs creates duplicate checks and
# explodes request counts. Cap: use HTTPX live hosts when URL count exceeds this.
_NUCLEI_STEALTH_URL_THRESHOLD = int(os.getenv("NUCLEI_STEALTH_URL_THRESHOLD", "100"))

def _get_worker_id() -> str:
    """Get current worker ID from thread-local (set by watchdog.py)."""
    from core.ui import _get_current_worker
    return _get_current_worker()

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
    if not _RECORD_TOOL_TIMES:
        return  # Skip recording in watchdog mode
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
    worker_id = _get_current_worker()
    history = _load_tool_times().get(label, [])
    avg_time = sum(history)/len(history) if history else 0
    
    def _spinner():
        set_worker_context(worker_id)
        idx, chars = 0, ['-', '\\', '|', '/']
        while not stop_event.is_set():
            elapsed = time.time() - start_time
            eta = f" | ETA: {int(avg_time - elapsed)}s" if avg_time > elapsed else ""
            extra = extra_stats_fn() if extra_stats_fn else ""
            ui_update_status(label, f"{chars[idx % 4]} {int(elapsed)}s{eta}{extra}")
            idx += 1
            time.sleep(1.0)

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


def _phase_duration(phase_result: Dict[str, Any]) -> float:
    counts = phase_result.get("counts", {})
    started = counts.get("_started_at")
    ended = counts.get("_ended_at")
    if isinstance(started, (int, float)) and isinstance(ended, (int, float)) and ended >= started:
        return ended - started
    return 0.0


def _build_results_snapshot(
    target: Dict[str, Any],
    recon_result: Dict[str, Any],
    vuln_result: Dict[str, Any],
) -> Dict[str, Any]:
    """Build per-mission result metrics from phase results (thread-safe, no shared UI state)."""
    recon_counts = recon_result.get("counts", {})
    vuln_counts = vuln_result.get("counts", {})
    return {
        "target": target.get("handle", "unknown"),
        "score": target.get("score", 0),
        "subdomains": int(recon_counts.get("subdomains", 0) or 0),
        "alive": int(recon_counts.get("alive", 0) or 0),
        "open_ports": int(recon_counts.get("open_ports", 0) or 0),
        "endpoints": int(recon_counts.get("httpx_urls", 0) or 0),
        "hist_urls": int(vuln_counts.get("hist_urls", 0) or 0),
        "js_secrets": int(vuln_counts.get("js_secrets", 0) or 0),
        "vulns": int(vuln_counts.get("findings", 0) or 0),
        "phase_results": {
            "recon": recon_result,
            "vulnerability": vuln_result,
        },
    }

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
    avg = sum(history) / len(history) if history else 0.0
    with _live_view_lock:
        _live_view_data[name]["status"] = "running"
        _live_view_data[name]["start_time"] = time.time()
        _live_view_data[name]["eta"] = avg
        _live_view_data[name]["input_count"] = input_count
    # Route to per-worker UI
    ui_worker_tool_started(_get_current_worker(), name, input_count, avg)

def _tool_done(name: str, count_key: str, count_file: str = ""):
    """Mark tool as finished in live view and update count from file."""
    count = _count_lines(count_file) if count_file and os.path.exists(count_file) else 0
    with _live_view_lock:
        start_t = _live_view_data[name].get("start_time")
        elapsed = time.time() - start_t if start_t else 0.0
        _live_view_data[name]["status"] = "finished"
        _live_view_data[name]["start_time"] = None
        _live_view_data[name][count_key] = count
    # Route to per-worker UI
    ui_worker_tool_finished(_get_current_worker(), name, count, elapsed)

def _tool_cached(name: str, count_key: str, count_file: str = ""):
    """Mark tool as served from cache in live view."""
    count = _count_lines(count_file) if count_file and os.path.exists(count_file) else 0
    with _live_view_lock:
        _live_view_data[name]["status"] = "cached"
        _live_view_data[name]["start_time"] = None
        _live_view_data[name][count_key] = count
    # Route to per-worker UI
    ui_worker_tool_cached(_get_current_worker(), name, count)

def _tool_error(name: str):
    """Mark tool as error in live view."""
    with _live_view_lock:
        _live_view_data[name]["status"] = "error"
        _live_view_data[name]["start_time"] = None
    # Route to per-worker UI
    ui_worker_tool_error(_get_current_worker(), name)

def _nuclei_progress_callback(stats):
    """Update live view with Nuclei stats from -sj JSON output."""
    def _to_int(val):
        try: return int(val or 0)
        except (TypeError, ValueError): return 0
    def _to_float(val):
        try: return float(val or 0)
        except (TypeError, ValueError): return 0.0
    done  = _to_int(stats.get("requests", stats.get("sent", 0)))
    total = _to_int(stats.get("total", 0))
    rps   = _to_float(stats.get("rps", 0))
    matched = _to_int(stats.get("matched", 0))
    with _live_view_lock:
        d = _live_view_data["Nuclei"]
        d["requests_done"]  = done
        d["requests_total"] = total
        d["rps"]     = rps
        d["matched"] = matched
    # Route to per-worker UI
    ui_worker_nuclei_update(_get_current_worker(), done, total, rps, matched)

def _nuclei_extra_stats() -> str:
    """Return real-time Nuclei stats string for spinner display."""
    with _live_view_lock:
        d = _live_view_data["Nuclei"]
        rps = d.get("rps", 0)
        done = d.get("requests_done", 0)
        total = d.get("requests_total", 0)
        matched = d.get("matched", 0)
    if isinstance(total, (int, float)) and total > 0:
        return f" | Req/s {rps} | {done}/{total} | {matched} hits"
    return ""

def _count_findings(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as fh:
            return sum(1 for _ in fh)
    except (FileNotFoundError, IOError) as e:
        logging.debug(f"Cannot count findings in {filepath}: {e}")
        return 0

_CACHE_TTL = 3600  # 1 hour
_DISABLE_RUNTIME_CACHE = False

def _is_cache_valid(filepath: str) -> bool:
    """Return True if filepath exists, is non-empty, and was modified within _CACHE_TTL seconds."""
    if _DISABLE_RUNTIME_CACHE:
        return False
    try:
        if not os.path.exists(filepath): return False
        if os.path.getsize(filepath) == 0: return False
        return (time.time() - os.path.getmtime(filepath)) < _CACHE_TTL
    except OSError:
        return False

def _auto_cleanup(target_dir: str):
    """Delete stale recon files (>1h) for this target and old snapshots."""
    cutoff = time.time() - _CACHE_TTL
    for directory in (target_dir, "logs/snapshots"):
        if not os.path.isdir(directory):
            continue
        for fname in os.listdir(directory):
            fp = os.path.join(directory, fname)
            try:
                if os.path.isfile(fp) and os.path.getmtime(fp) < cutoff:
                    os.unlink(fp)
                    logging.debug(f"Auto-cleanup: removed {fp}")
            except OSError:
                pass


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
                    payload = json.loads(line)
                    if isinstance(payload, dict):
                        items.append(payload)
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []
    return items


class MissionRunner:
    """Handles a single mission lifecycle: prepare, run vulnerability phase, and finalize."""
    def __init__(self, target_data, stats_pipe=None, config=None, custom_template_paths=None):
        self.target = target_data
        self.stats_pipe = stats_pipe
        self.config = config or {}
        self.custom_template_paths = custom_template_paths or []

    def _build_phase_result(self, phase: str) -> Dict[str, Any]:
        return {
            "phase": phase,
            "ok": True,
            "errors": [],
            "counts": {},
            "paths": {},
        }

    def _run_recon_phase(self, paths, domains):
        """Executa a fase de reconhecimento: subfinder, dnsx, uncover, httpx."""
        phase_result = self._build_phase_result("recon")
        phase_started = time.time()
        dom_file = paths["dom"]
        os.makedirs(os.path.dirname(dom_file), exist_ok=True)
        with open(dom_file, 'w') as f:
            for d in domains:
                f.write(d + '\n')

        limiter = get_rate_limiter(REQUESTS_PER_SECOND)
        is_ip_mode = self.target.get('scope_type') == 'ip'

        if is_ip_mode:
            # IP/CIDR targets: skip Subfinder/DNSX/Uncover entirely.
            # Run naabu to discover all open web ports before HTTPX.
            sub_file = paths["sub"]
            live_file = paths["live"]
            unv_file = paths["unv"]
            import shutil
            shutil.copy(dom_file, sub_file)
            open(unv_file, 'w').close()
            ui_log("RECON", f"Modo IP: pulando Subfinder/DNSX/Uncover ({count_lines(dom_file)} IPs)", Colors.INFO)

            # Naabu: port-scan IPs to discover all open web ports
            naabu_file = paths["sub"] + ".naabu"
            if _is_cache_valid(naabu_file):
                ui_log("Naabu", f"[Cache] {_count_lines(naabu_file)} ports", Colors.DIM)
                _tool_cached("Naabu", "ports", naabu_file)
                shutil.copy(naabu_file, live_file)
            else:
                limiter.wait_and_record(self.target.get('handle', 'unknown'))
                _tool_start("Naabu", input_count=count_lines(dom_file))
                ok = _run_with_progress("Naabu", lambda: run_naabu(dom_file, naabu_file))
                if ok and _count_lines(naabu_file) > 0:
                    _tool_done("Naabu", "ports", naabu_file)
                    shutil.copy(naabu_file, live_file)
                else:
                    _tool_error("Naabu")
                    # Fallback: raw IPs are still valid HTTPX input on port 80
                    shutil.copy(dom_file, live_file)
        else:
            sub_file = paths["sub"]
            live_file = paths["live"]
            unv_file = paths["unv"]

            # Subfinder
            if _is_cache_valid(sub_file):
                ui_log("Subfinder", f"[Cache] {_count_lines(sub_file)} subs", Colors.DIM)
                _tool_cached("Subfinder", "subs", sub_file)
            else:
                limiter.wait_and_record(self.target.get('handle', 'unknown'))
                _tool_start("Subfinder", input_count=count_lines(dom_file))
                ok = _run_with_progress("Subfinder", lambda: run_subfinder(dom_file, sub_file, rate_limit=RATE_LIMIT))
                if ok:
                    _tool_done("Subfinder", "subs", sub_file)
                else:
                    _tool_error("Subfinder")
                    phase_result["ok"] = False
                    phase_result["errors"].append("Subfinder failed")

            # DNSX
            if _is_cache_valid(live_file):
                ui_log("DNSX", f"[Cache] {_count_lines(live_file)} live", Colors.DIM)
                _tool_cached("DNSX", "live", live_file)
            else:
                limiter.wait_and_record(self.target.get('handle', 'unknown'))
                _tool_start("DNSX", input_count=count_lines(sub_file))
                ok = _run_with_progress("DNSX", lambda: run_dnsx(sub_file, live_file, rate_limit=RATE_LIMIT))
                if ok:
                    _tool_done("DNSX", "live", live_file)
                else:
                    _tool_error("DNSX")
                    phase_result["ok"] = False
                    phase_result["errors"].append("DNSX failed")

            # Uncover
            uncover_file = paths["sub"] + ".uncover"
            if _is_cache_valid(uncover_file):
                ui_log("Uncover", f"[Cache] {_count_lines(uncover_file)} takeovers", Colors.DIM)
                _tool_cached("Uncover", "takeovers", uncover_file)
            else:
                limiter.wait_and_record(self.target.get('handle', 'unknown'))
                _tool_start("Uncover")
                ok = _run_with_progress("Uncover", lambda: run_uncover(domains, uncover_file))
                if ok:
                    _tool_done("Uncover", "takeovers", uncover_file)
                else:
                    _tool_error("Uncover")
                    phase_result["ok"] = False
                    phase_result["errors"].append("Uncover failed")

            # Calcular não resolvidos
            if os.path.exists(sub_file) and os.path.exists(live_file):
                with open(sub_file, 'r') as f_sub, open(live_file, 'r') as f_live:
                    subs = set(line.strip() for line in f_sub if line.strip())
                    lives = set(line.strip() for line in f_live if line.strip())
                unv = subs - lives
                with open(unv_file, 'w') as f_unv:
                    for u in unv:
                        f_unv.write(u + '\n')

        # --- HTTPX (common path for both domain and IP modes) ---
        uncover_file = paths["sub"] + ".uncover"
        httpx_file = paths["live"] + ".httpx"
        # Guard: truncate large DNSX outputs before HTTPX to avoid timeout
        httpx_input = live_file
        live_count = count_lines(live_file) if os.path.exists(live_file) else 0
        if live_count > MAX_SUBS_PER_TARGET:
            ui_log("GUARD", f"Alvo grande ({live_count} hosts). Truncando para HTTPX", Colors.WARNING)
            logging.warning(f"Pre-HTTPX truncation for {self.target.get('handle', 'unknown')}: {live_count} → {MAX_SUBS_PER_TARGET}")
            httpx_input = live_file + ".httpx_guard"
            with open(live_file, 'r') as _f, open(httpx_input, 'w') as _o:
                for _i, _l in enumerate(_f):
                    if _i >= MAX_SUBS_PER_TARGET:
                        break
                    _o.write(_l)
        if _is_cache_valid(httpx_file):
            ui_log("HTTPX", f"[Cache] {_count_lines(httpx_file)} endpoints", Colors.DIM)
            _tool_cached("HTTPX", "endpoints", httpx_file)
        else:
            limiter.wait_and_record(self.target.get('handle', 'unknown'))
            _tool_start("HTTPX", input_count=count_lines(httpx_input))
            ok = _run_with_progress("HTTPX", lambda: run_httpx(httpx_input, httpx_file, rate_limit=RATE_LIMIT))
            if ok:
                _tool_done("HTTPX", "endpoints", httpx_file)
            else:
                _tool_error("HTTPX")
                phase_result["ok"] = False
                phase_result["errors"].append("HTTPX failed")

        phase_result["counts"] = {
            "domains": count_lines(dom_file),
            "subdomains": count_lines(sub_file),
            "alive": count_lines(live_file),
            "open_ports": _count_lines(paths["sub"] + ".naabu") if is_ip_mode else 0,
            "takeovers": count_lines(uncover_file),
            "httpx_urls": count_lines(httpx_file),
            "unresolved": count_lines(unv_file),
            "_started_at": phase_started,
            "_ended_at": time.time(),
        }
        phase_result["paths"] = {
            "dom": dom_file,
            "sub": sub_file,
            "live": live_file,
            "unv": unv_file,
            "uncover": uncover_file,
            "httpx": httpx_file,
        }
        return phase_result

    def _run_tactical_phase(self, paths):
        """Executa a fase tática: Katana, JS Hunter, Nuclei."""
        phase_result = self._build_phase_result("tactical")
        phase_started = time.time()
        live_file = paths["live"]
        if not os.path.exists(live_file) or os.path.getsize(live_file) == 0:
            ui_log("INFO", "Nenhum subdomínio vivo. Pulando fase tática.", Colors.WARNING)
            phase_result["ok"] = True
            phase_result["counts"] = {
                "inputs": 0,
                "katana_urls": 0,
                "hist_urls": 0,
                "js_secrets": 0,
                "findings": 0,
                "_started_at": phase_started,
                "_ended_at": time.time(),
            }
            phase_result["paths"] = {
                "input": live_file,
                "katana": paths["live"] + ".katana",
                "urlfinder": paths["live"] + ".urlfinder",
                "combined_urls": paths["live"] + ".combined_urls",
                "js_secrets": paths["live"] + ".js_secrets",
                "findings": paths["fin"],
            }
            return phase_result
        
        limiter = get_rate_limiter(REQUESTS_PER_SECOND)
        
        # Use HTTPX output (full URLs) as Katana/Nuclei input when available
        httpx_file = paths["live"] + ".httpx"
        has_httpx = os.path.exists(httpx_file) and os.path.getsize(httpx_file) > 0
        recon_input = httpx_file if has_httpx else live_file
        
        # Katana: crawling inteligente com URLs do HTTPX (cached)
        katana_file = paths["live"] + ".katana"
        if _is_cache_valid(katana_file):
            ui_log("Katana", f"[Cache] {_count_lines(katana_file)} URLs", Colors.DIM)
            _tool_cached("Katana", "crawled", katana_file)
        else:
            limiter.wait_and_record(self.target.get('handle', 'unknown'))
            _tool_start("Katana", input_count=count_lines(recon_input))
            ok = _run_with_progress("Katana", lambda: run_katana_surgical(recon_input, katana_file, rate_limit=RATE_LIMIT))
            if ok:
                _tool_done("Katana", "crawled", katana_file)
            else:
                _tool_error("Katana")
                phase_result["ok"] = False
                phase_result["errors"].append("Katana failed")

        # URLFinder: historical/archived URLs to expand attack surface
        # Extracts orphaned endpoints, old API versions, forgotten paths from public archives.
        urlfinder_file = paths["live"] + ".urlfinder"
        dom_file = paths.get("dom", paths["live"].replace("live.txt", "dom.txt"))
        if _is_cache_valid(urlfinder_file):
            ui_log("URLFinder", f"[Cache] {_count_lines(urlfinder_file)} hist URLs", Colors.DIM)
            _tool_cached("URLFinder", "hist_urls", urlfinder_file)
        elif os.path.exists(dom_file) and os.path.getsize(dom_file) > 0:
            limiter.wait_and_record(self.target.get('handle', 'unknown'))
            _tool_start("URLFinder", input_count=count_lines(dom_file))
            ok = _run_with_progress("URLFinder", lambda: run_urlfinder(dom_file, urlfinder_file))
            if ok:
                _tool_done("URLFinder", "hist_urls", urlfinder_file)
            else:
                _tool_error("URLFinder")
                # Non-fatal: proceed without historical URLs
        else:
            open(urlfinder_file, 'w').close()

        # Merge katana + urlfinder into combined URL list (deduped) for broader nuclei coverage
        nuclei_input = recon_input
        combined_file = paths["live"] + ".combined_urls"
        try:
            seen_urls: set = set()
            combined_lines = []
            for src in [recon_input, katana_file, urlfinder_file]:
                if os.path.exists(src):
                    with open(src, 'r', encoding='utf-8', errors='ignore') as _cf:
                        for _line in _cf:
                            url = _line.strip()
                            if url and url not in seen_urls:
                                seen_urls.add(url)
                                combined_lines.append(url)
            if combined_lines:
                with open(combined_file, 'w', encoding='utf-8') as _wf:
                    _wf.write('\n'.join(combined_lines) + '\n')
                nuclei_input = combined_file
                ui_log("MERGE", f"{len(combined_lines)} unique URLs para nuclei", Colors.DIM)
        except OSError as _e:
            logging.warning(f"URL merge failed: {_e}; falling back to recon_input")
            nuclei_input = recon_input
        
        # JS Hunter: extrai segredos de arquivos JavaScript
        js_secrets_file = paths["live"] + ".js_secrets"
        limiter.wait_and_record(self.target.get('handle', 'unknown'))
        # Count .js URLs in katana output for accurate display
        js_input_count = 0
        if os.path.exists(katana_file):
            try:
                with open(katana_file, 'r', encoding='utf-8', errors='ignore') as _jf:
                    js_input_count = sum(1 for l in _jf if l.strip().endswith(('.js', '.mjs', '.ts')))
            except OSError:
                pass
        _tool_start("JS Hunter", input_count=js_input_count)
        ok = _run_with_progress("JS Hunter", lambda: run_js_hunter(katana_file, js_secrets_file))
        if ok:
            _tool_done("JS Hunter", "secrets", js_secrets_file)
        else:
            _tool_error("JS Hunter")
            phase_result["ok"] = False
            phase_result["errors"].append("JS Hunter failed")

        # ── ReAct Heuristic Analysis (LLM) ────────────────────────────────────
        # Runs between JS Hunter and Nuclei. Samples dynamic endpoints, asks the
        # LLM to identify IDOR/BAC candidates, probes them, and appends confirmed
        # anomalies directly to findings_file (pre-populates Nuclei output).
        # Always non-fatal: failure is logged and execution continues to Nuclei.
        findings_file = paths["fin"]
        try:
            react_agent = ReActHeuristicAgent(AIClient(), self.target)
            url_sources = [f for f in [combined_file, katana_file, recon_input, urlfinder_file] if os.path.exists(f)]
            react_result = react_agent.run(
                url_files=url_sources,
                js_secrets_file=js_secrets_file,
                findings_file=findings_file,
            )
            if react_result.get("endpoints_sampled", 0) > 0:
                ui_log(
                    "REACT",
                    f"Sampled {react_result['endpoints_sampled']} | "
                    f"Inject={react_result['endpoints_injected']} "
                    f"Discard={react_result['endpoints_discarded']} | "
                    f"Findings={react_result['findings_added']}",
                    Colors.INFO,
                )
        except KeyboardInterrupt:
            raise
        except Exception as _react_err:
            logging.warning(f"ReAct agent failed (non-fatal): {_react_err}")

        # Smart Nuclei Tag Detection: Extract tech from Katana/HTTPX and select appropriate tags
        nuclei_tags = self._get_smart_nuclei_tags(recon_input, katana_file)
        # Stealth optimization: resolve tech-specific template dirs to narrow scan scope.
        nuclei_template_dirs = self._get_smart_nuclei_template_dirs(recon_input, katana_file)

        # Nuclei: scanning de vulnerabilidades com URLs combinadas (HTTPX + Katana + URLFinder)
        findings_file = paths["fin"]
        limiter.wait_and_record(self.target.get('handle', 'unknown'))
        live_inputs = count_lines(nuclei_input)

        # Stealth dir mode: template dirs contain HOST-level checks (misconfiguration,
        # exposures, takeovers, default-logins). Running against thousands of crawled
        # URLs duplicates those checks per URL and explodes request counts.
        # Cap: when dirs are active and URL count exceeds threshold, use HTTPX live
        # hosts file (3 endpoints) instead — same findings, 99%+ fewer requests.
        nuclei_input_effective = nuclei_input
        if nuclei_template_dirs and live_inputs > _NUCLEI_STEALTH_URL_THRESHOLD:
            host_count = count_lines(recon_input)
            if host_count > 0:
                nuclei_input_effective = recon_input
                ui_log(
                    "NUCLEI",
                    f"Stealth dir mode: {host_count} live hosts "
                    f"(skipping {live_inputs} crawled URLs — dirs are host-level checks)",
                    Colors.DIM,
                )
                live_inputs = host_count

        timeout_override = None
        if live_inputs >= _NUCLEI_TIMEOUT_LIVE_HOST_THRESHOLD:
            timeout_override = _NUCLEI_TIMEOUT_LARGE_SCAN
            ui_log(
                "NUCLEI",
                f"Large target set detected ({live_inputs} hosts), timeout -> {timeout_override}s",
                Colors.WARNING,
            )
        _tool_start("Nuclei", input_count=live_inputs)
        ok = _run_with_progress("Nuclei", lambda: run_nuclei(
            nuclei_input_effective, findings_file, tags=nuclei_tags,
            rate_limit=NUCLEI_RATE_LIMIT, progress_callback=_nuclei_progress_callback,
            custom_templates=self.custom_template_paths, timeout_override=timeout_override,
            template_dirs=nuclei_template_dirs),
            extra_stats_fn=_nuclei_extra_stats)
        if ok:
            _tool_done("Nuclei", "vulns", findings_file)
        else:
            _tool_error("Nuclei")
            phase_result["ok"] = False
            phase_result["errors"].append("Nuclei failed")
        
        # Consolidar filtragem e validação em um passo único
        if os.path.exists(findings_file):
            self._filter_and_validate_findings(findings_file)
        phase_result["counts"] = {
            "inputs": count_lines(recon_input),
            "katana_urls": count_lines(katana_file),
            "hist_urls": _count_lines(urlfinder_file),
            "js_secrets": count_lines(js_secrets_file),
            "findings": _count_findings(findings_file),
            "_started_at": phase_started,
            "_ended_at": time.time(),
        }
        phase_result["paths"] = {
            "input": recon_input,
            "katana": katana_file,
            "urlfinder": urlfinder_file,
            "combined_urls": combined_file,
            "js_secrets": js_secrets_file,
            "findings": findings_file,
        }
        return phase_result

    def _run_vulnerability_phase(self, paths):
        phase_result = self._build_phase_result("vulnerability")
        phase_started = time.time()
        # Aplica filtro sniper
        ns = paths.get("live", "")
        if not os.path.exists(ns) or os.path.getsize(ns) == 0:
            # No live hosts is a valid recon outcome, not a failure
            phase_result["ok"] = True
            phase_result["counts"] = {
                "_started_at": phase_started,
                "_ended_at": time.time(),
            }
            return phase_result

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
        tactical = self._run_tactical_phase(paths)
        phase_result["ok"] = tactical.get("ok", False)
        phase_result["errors"] = tactical.get("errors", [])
        phase_result["counts"] = tactical.get("counts", {})
        phase_result["counts"]["_started_at"] = phase_started
        phase_result["counts"]["_ended_at"] = time.time()
        phase_result["paths"] = tactical.get("paths", {})
        phase_result["paths"]["sniper_input"] = ns
        return phase_result
    
    def _filter_and_validate_findings(self, findings_file):
        """Single consolidation point: FP filtering + AI validation"""
        from core.filter import FalsePositiveKiller
        
        # Step 1: Apply FalsePositiveKiller (in-place)
        FalsePositiveKiller.sanitize_findings(findings_file)
        
        # Step 2: AI validation only if score warrants it
        if self.target.get('score', 0) >= 60:
            self._validate_findings_with_ai(findings_file)
        else:
            ui_log("AI VALIDATION", "Score < 60. Pulando validação com IA.", Colors.INFO)
    
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
        
        validated_findings: List[Dict[str, Any]] = []
        critical_keywords = ['critical', 'high', 'rce', 'sql', 'xss', 'xxe', 'misconfig', 'takeover']
        
        feedback_path = os.path.join(os.path.dirname(os.path.dirname(findings_file)), "data", "findings_feedback.jsonl")
        os.makedirs(os.path.dirname(feedback_path), exist_ok=True)

        try:
            for vuln in _safe_read_jsonl(findings_file):
                template_id = vuln.get('template-id', '').lower()
                host = vuln.get('host', '')
                
                # Only validate critical/high findings
                is_critical = any(keyword in template_id for keyword in critical_keywords)
                
                if is_critical:
                    severity = vuln.get('severity') or vuln.get('info', {}).get('severity', 'unknown')
                    matched_at = vuln.get('matched-at', host)
                    description = vuln.get('info', {}).get('description', '')[:200]
                    extracted = vuln.get('extracted-results', [])
                    extracted_str = ', '.join(str(x) for x in extracted[:3]) if extracted else 'none'

                    prompt = (
                        f"You are a bug bounty triage expert. Analyze this Nuclei finding:\n\n"
                        f"Template: {template_id}\n"
                        f"Severity: {severity}\n"
                        f"Host: {host}\n"
                        f"Matched at: {matched_at}\n"
                        f"Description: {description}\n"
                        f"Extracted: {extracted_str}\n\n"
                        f"Is this a real, exploitable vulnerability or a false positive?\n"
                        f"Respond with exactly one word: VALID or INVALID"
                    )
                    response = ai_client.complete(prompt, max_tokens=10)
                    is_valid = 'VALID' in response.upper()

                    # ML feedback: save label for retraining
                    feedback_entry = {
                        'template_id': template_id,
                        'host': host,
                        'severity': severity,
                        'matched_at': matched_at,
                        'label': 'tp' if is_valid else 'fp',
                        'source': 'ai_validation',
                    }
                    try:
                        with open(feedback_path, 'a', encoding='utf-8') as fb:
                            fb.write(json.dumps(feedback_entry) + '\n')
                    except OSError:
                        pass

                    if is_valid:
                        validated_findings.append(vuln)
                    else:
                        ui_log("AI VALIDATION", f"Rejected: {host} ({template_id})", Colors.WARNING)
                else:
                    validated_findings.append(vuln)
            
            # Rewrite file with validated findings
            with open(findings_file, 'w', encoding='utf-8') as f:
                for finding in validated_findings:
                    f.write(json.dumps(finding) + '\n')
            
            ui_log("AI VALIDATION", "Validation complete.", Colors.SUCCESS)
        except Exception as e:
            ui_log("AI VALIDATION", f"Validation failed: {str(e)[:50]}", Colors.ERROR)

    def _get_smart_nuclei_tags(self, httpx_file: str, katana_file: str) -> str:
        """
        Detect web technologies from URLs and select optimal Nuclei tags.
        
        Reads URLs from HTTPX and Katana outputs, extracts tech stack,
        and returns prioritized Nuclei tag string for vulnerability scanning.
        """
        try:
            tech_stack = set()
            urls = _safe_read_lines(httpx_file) + _safe_read_lines(katana_file)
            
            # Detect technology stack from URLs
            if urls:
                detected_tech = TechDetector.detect_from_urls(urls)
                tech_stack.update(detected_tech)
            
            # Generate optimized Nuclei tags
            if tech_stack:
                tag_string, tag_list = TechDetector.get_nuclei_tags(tech_stack)
                tech_summary = TechDetector.get_tech_summary(tech_stack)
                ui_log("TECH", f"Detected: {tech_summary}", Colors.INFO)
                ui_log("TAGS", f"Using tags: {tag_string[:60]}...", Colors.DIM)
                return tag_string
            
        except Exception as e:
            logging.warning(f"Tech detection failed: {e}")
        
        # Broad fallback: covers the highest-value vuln classes when tech detection yields nothing
        return (
            "cve,misconfig,exposure,takeover,default-credentials,auth-bypass,"
            "sqli,xss,ssrf,rce,lfi,xxe,idor,ssti,cors,open-redirect,"
            "info-disclosure,file-upload,redirect"
        )

    def _get_smart_nuclei_template_dirs(self, httpx_file: str, katana_file: str) -> List[str]:
        """Return tech-specific nuclei-templates subdirectory paths for this target.

        Detects the tech stack from HTTPX + Katana output (same URL corpus used
        for tag detection), then delegates to TechDetector.get_nuclei_template_dirs()
        which maps tech → existing template dirs on disk.

        Returns [] when detection fails or no dirs exist — callers fall back to
        the full-library scan in that case.
        """
        try:
            urls = _safe_read_lines(httpx_file) + _safe_read_lines(katana_file)
            if not urls:
                return []
            tech_stack = TechDetector.detect_from_urls(urls)
            if not tech_stack:
                return []
            dirs = TechDetector.get_nuclei_template_dirs(tech_stack)
            if dirs:
                ui_log(
                    "TECH",
                    f"Stealth: {len(dirs)} template dirs for {TechDetector.get_tech_summary(tech_stack)}",
                    Colors.DIM,
                )
            return dirs
        except Exception as e:
            logging.warning(f"Template dir detection failed: {e}")
            return []

    def _notify_and_report(self, paths: dict, results: dict):
        """Send notifications and generate bug bounty report after scan."""
        h = self.target.get('handle', 'unknown')
        platform = self.target.get('platform', 'unknown')
        findings_path = paths["fin"]
        js_secrets_path = paths["live"] + ".js_secrets"

        # 1. Telegram: Critical/High/Medium vulnerabilities only
        try:
            NotificationDispatcher.alert_nuclei(findings_path, h)
        except Exception as e:
            logging.warning(f"Notification failed: {e}")

        # 2. Telegram: JS secrets (Critical/High/Medium only)
        try:
            NotificationDispatcher.alert_js_secrets(js_secrets_path, h)
        except Exception as e:
            logging.warning(f"JS secrets notification failed: {e}")

        # 3. Discord: scan statistics summary (no individual vulns)
        try:
            NotificationDispatcher.alert_scan_complete(h, platform, results)
        except Exception as e:
            logging.warning(f"Discord scan summary failed: {e}")

        # 4. Generate bug bounty report (Markdown, ready for submission)
        try:
            reporter = BugBountyReporter(h, platform=platform)
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

        # Remove stale files (>1h) for this target and old snapshots
        _auto_cleanup(target_dir)

        ui_mission_header(h, self.target.get('score', 0))
        ui_set_mission_meta(self.target.get('original_handle', h))
        try:
            recon_result = self._run_recon_phase(paths, self.target.get('domains', []))
            vuln_result = self._run_vulnerability_phase(paths)
        except KeyboardInterrupt:
            ui_log("MISSION", "Interrompido pelo usuario (CTRL+C)", Colors.WARNING)
            ui_mission_footer()
            raise
        
        results = _build_results_snapshot(self.target, recon_result, vuln_result)
        phase_errors = recon_result.get("errors", []) + vuln_result.get("errors", [])
        results["errors"] = phase_errors
        results["ok"] = not phase_errors
        results["metrics"] = {
            "phase_duration_seconds": {
                "recon": round(_phase_duration(recon_result), 2),
                "vulnerability": round(_phase_duration(vuln_result), 2),
            },
            "phase_errors_count": {
                "recon": len(recon_result.get("errors", [])),
                "vulnerability": len(vuln_result.get("errors", [])),
            },
        }
        if phase_errors:
            ui_log("MISSION", f"{len(phase_errors)} erro(s) de fase detectados.", Colors.WARNING)
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
        # Initialize custom templates once on startup
        try:
            self.custom_template_paths = load_custom_templates()
        except Exception as e:
            ui_log("ERR", f"Failed to load custom templates: {e}", Colors.WARNING)
            self.custom_template_paths = []

    def _ensure_intel(self):
        """Lazily initialize IntelMiner (requires AIClient)."""
        if self.intel is None:
            from core.intel import AIClient, IntelMiner
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

        runner = MissionRunner(target, stats_pipe, config=self.config, custom_template_paths=self.custom_template_paths)
        return runner.run()
