"""
HUNT3R v1.0-EXCALIBUR — Tactical UI [PREDADOR EDITION]

Watchdog Mode: Rich Live full-screen display
  - Banner with session stats
  - 3 per-worker panels (W1/W2/W3) showing pipeline progress
  - Rolling activity log (last 20 events)

Single Mode: Sequential print with progress spinner
"""

import os
import sys
import time
import re
import json
import atexit
import signal
import threading
import logging
from collections import deque
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text
from rich.rule import Rule
from rich.columns import Columns
from rich.align import Align
from rich.box import ROUNDED

try:
    from colorama import Fore as _Fore, Style as _Style, init as colorama_init
    colorama_init(autoreset=True)
    Fore = _Fore
    Style_colorama = _Style
except ImportError:
    class AnsiFore:
        RED = ''; GREEN = ''; YELLOW = ''; CYAN = ''; MAGENTA = ''; WHITE = ''; BLACK = ''
    class AnsiStyle:
        RESET_ALL = ''; BRIGHT = ''; DIM = ''
    Fore = AnsiFore()
    Style_colorama = AnsiStyle()

class Colors:
    PRIMARY   = "\033[36m"
    SECONDARY = "\033[35m"
    SUCCESS   = "\033[32m"
    WARNING   = "\033[33m"
    ERROR     = "\033[31m"
    INFO      = "\033[37m"
    DIM       = "\033[90m"
    BOLD      = "\033[1m"
    RESET     = "\033[0m"

os.makedirs('logs', exist_ok=True)
from core.logger import setup_logging
setup_logging()
ACTIVITY_LOG_FILE = "activity.log"
_activity_file_lock = threading.Lock()
_cleanup_lock = threading.Lock()
_cleanup_done = False
_interrupt_event = threading.Event()

ANSI_ESCAPE_RE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

def sanitize_input(text: str) -> str:
    clean = ANSI_ESCAPE_RE.sub('', str(text))
    return clean.replace('\n', '').replace('\r', '').strip()

ICONS = {
    "WATCHDOG": "🚨", "PREDADOR": "🦖", "SUBFINDER": "🌐", "DNSX": "🌍",
    "HTTPX": "⚡", "KATANA": "🕷️", "JS HUNTER": "🔑", "NUCLEI": "☢️",
    "IA": "🧠", "RESULTADO": "🏁", "SMART FILTER": "🧃", "UNCOVER": "👁️",
    "ERR": "❌", "ABORTADO": "🛑", "ANOMALIA": "⚠️", "RECON": "🔍",
    "DISK": "💾", "BOUNTY": "💰", "INIT": "🔧", "REPORT": "📄",
    "AI VALIDATION": "🧠", "MODE": "⚙️", "GUARD": "🛡️", "TECH": "⚙️",
    "TAGS": "🏷️", "INFO": "ℹ️", "MISSION": "🎯", "SNAPSHOT": "📸",
    "NUCLEI INFRA": "🏗️", "NUCLEI ENDP": "💉", "NUCLEI DEEP": "🕳️",
    "ESCALATOR": "⛓️", "DIFF NOVO": "✨", "DIFF SECRETS": "🔥",
}

TOOL_ICONS = {
    "Subfinder": "🌐", "DNSX": "🌍", "Uncover": "👁️",
    "HTTPX": "⚡", "Katana": "🕷️", "JS Hunter": "🔑", "Nuclei": "☢️",
}

PIPELINE_TOOLS = ["Subfinder", "DNSX", "Uncover", "HTTPX", "Katana", "JS Hunter", "Nuclei"]

# ─────────────────────────────────────────────────────────────
# Global State
# ─────────────────────────────────────────────────────────────

_console = Console(force_terminal=True)
_stdout_lock = threading.Lock()
_WATCHDOG_MODE = False
_MISSION_START_TIME: Optional[datetime] = None

# Session stats (watchdog)
_session_start = datetime.now()
_cycle_count = 0
_total_scanned = 0
_stats_lock = threading.Lock()

# Thread-local worker context (set by watchdog per thread)
_ui_thread_local = threading.local()

def set_worker_context(worker_id: str):
    """Call from a worker thread to identify itself. Set before any scan work begins."""
    _ui_thread_local.worker_id = worker_id

def _get_current_worker() -> str:
    return getattr(_ui_thread_local, 'worker_id', 'W0')

# Per-worker state (W1, W2, W3)
_WORKER_SLOTS = ["W1", "W2", "W3"]

def _empty_worker(wid: str) -> Dict:
    return {
        'id': wid,
        'status': 'idle',          # idle | running | done | error
        'target': None,
        'idx': 0,
        'total': 0,
        'start_time': None,
        'current_tool': None,
        'tools': {
            t: {'status': 'idle', 'count': 0, 'elapsed': 0.0, 'eta': 0.0, 'start_time': None}
            for t in PIPELINE_TOOLS
        },
        'metrics': {'subs': 0, 'live': 0, 'endpoints': 0, 'secrets': 0, 'vulns': 0},
        'nuclei_req': {'done': 0, 'total': 0, 'rps': 0.0, 'matched': 0},
    }

_workers: Dict[str, Dict] = {k: _empty_worker(k) for k in _WORKER_SLOTS}
_workers_lock = threading.RLock()

# Activity log (rolling, for display + file)
_activity: deque = deque(maxlen=300)
_activity_lock = threading.Lock()

# Legacy live view (backward compat — scanner.py writes here directly)
_live_view_data: Dict[str, Dict[str, Any]] = {}
_live_view_lock = threading.RLock()
_live_view_meta = {"target": "", "current": 0, "total": 0}

def _reset_live_view_data():
    global _live_view_data
    _live_view_data = {
        "Subfinder":  {"status": "idle", "subs": 0,       "start_time": None, "eta": 0, "input_count": 0},
        "DNSX":       {"status": "idle", "live": 0,       "start_time": None, "eta": 0, "input_count": 0},
        "Uncover":    {"status": "idle", "takeovers": 0,  "start_time": None, "eta": 0, "input_count": 0},
        "HTTPX":      {"status": "idle", "endpoints": 0,  "start_time": None, "eta": 0, "input_count": 0},
        "Katana":     {"status": "idle", "crawled": 0,    "start_time": None, "eta": 0, "input_count": 0},
        "JS Hunter":  {"status": "idle", "secrets": 0,    "start_time": None, "eta": 0, "input_count": 0},
        "Nuclei":     {"status": "idle", "vulns": 0,      "start_time": None, "eta": 0, "input_count": 0,
                       "requests_total": 0, "requests_done": 0, "rps": 0, "matched": 0},
    }

_reset_live_view_data()

# Render thread
_render_thread: Optional[threading.Thread] = None
_render_stop = threading.Event()
_live_thread: Optional[threading.Thread] = None  # single-mode legacy
_MIN_FULLSCREEN_COLS = 80
_MIN_FULLSCREEN_LINES = 24

# ─────────────────────────────────────────────────────────────
# Per-Worker API (called by scanner.py via thread-local routing)
# ─────────────────────────────────────────────────────────────

def ui_worker_register(worker_id: str, target: str, idx: int = 0, total: int = 0):
    """Register a worker as active with a new target."""
    with _workers_lock:
        w = _empty_worker(worker_id)
        w.update({'status': 'running', 'target': target, 'idx': idx,
                  'total': total, 'start_time': time.time()})
        _workers[worker_id] = w
    _activity_push(worker_id, "MISSION", f"▶ {target} [{idx}/{total}]", "cyan")

def ui_worker_done(worker_id: str, results: Dict):
    """Mark worker as done after scan completes."""
    with _workers_lock:
        if worker_id in _workers:
            _workers[worker_id]['status'] = 'done'
            _workers[worker_id]['current_tool'] = None
    subs  = results.get('subdomains', 0)
    live  = results.get('alive', 0)
    ep    = results.get('endpoints', 0)
    sec   = results.get('js_secrets', 0) or results.get('secrets', 0)
    vulns = results.get('vulns', 0)
    t     = results.get('target', results.get('handle', '?'))
    color = "bold green" if vulns > 0 else "green"
    _activity_push(worker_id, "RESULTADO",
                   f"✓ {t}  sub:{subs} lv:{live} ep:{ep} sec:{sec} vuln:[bold red]{vulns}[/]" if vulns > 0
                   else f"✓ {t}  sub:{subs} lv:{live} ep:{ep} sec:{sec} vuln:{vulns}", color)
    global _total_scanned
    with _stats_lock:
        _total_scanned += 1

def ui_worker_tool_started(worker_id: str, tool: str, input_count: int = 0, eta: float = 0.0):
    now = time.time()
    with _workers_lock:
        if worker_id not in _workers:
            return
        _workers[worker_id]['current_tool'] = tool
        _workers[worker_id]['tools'][tool].update(
            {'status': 'running', 'start_time': now, 'eta': eta, 'count': input_count})
    _activity_push(worker_id, tool, f"▶ {tool}  ({input_count} inputs)", "yellow")

def ui_worker_tool_finished(worker_id: str, tool: str, count: int = 0, elapsed: float = 0.0):
    with _workers_lock:
        if worker_id not in _workers:
            return
        w = _workers[worker_id]
        w['tools'][tool].update({'status': 'done', 'count': count,
                                 'elapsed': elapsed, 'start_time': None})
        if w['current_tool'] == tool:
            w['current_tool'] = None
        _METRIC = {'Subfinder': 'subs', 'DNSX': 'live', 'HTTPX': 'endpoints',
                   'Katana': 'endpoints', 'JS Hunter': 'secrets', 'Nuclei': 'vulns'}
        if tool in _METRIC:
            w['metrics'][_METRIC[tool]] = count
    color = "bold green" if count > 0 else "green"
    _activity_push(worker_id, tool, f"✓ {tool}  {count} results  ({int(elapsed)}s)", color)

def ui_worker_tool_cached(worker_id: str, tool: str, count: int = 0):
    with _workers_lock:
        if worker_id not in _workers:
            return
        w = _workers[worker_id]
        w['tools'][tool].update({'status': 'cached', 'count': count, 'start_time': None})
        if w['current_tool'] == tool:
            w['current_tool'] = None
    _activity_push(worker_id, tool, f"◈ {tool}  {count} (cache hit)", "cyan")

def ui_worker_tool_error(worker_id: str, tool: str, error: str = ""):
    with _workers_lock:
        if worker_id not in _workers:
            return
        w = _workers[worker_id]
        w['tools'][tool].update({'status': 'error', 'start_time': None})
        if w['current_tool'] == tool:
            w['current_tool'] = None
    _activity_push(worker_id, tool, f"✗ {tool}  {error[:80]}", "red")

def ui_worker_nuclei_update(worker_id: str, done: int, total: int, rps: float, matched: int):
    with _workers_lock:
        if worker_id in _workers:
            _workers[worker_id]['nuclei_req'] = {
                'done': done, 'total': total, 'rps': rps, 'matched': matched}

def ui_cycle_started():
    global _cycle_count
    with _stats_lock:
        _cycle_count += 1

# ─────────────────────────────────────────────────────────────
# Activity Log
# ─────────────────────────────────────────────────────────────

def _activity_push(worker_id: str, module: str, message: str, color: str = "white"):
    ts = datetime.now().strftime("%H:%M:%S")
    with _activity_lock:
        _activity.append((ts, worker_id, module, message, color))
    if _WATCHDOG_MODE:
        try:
            clean_module = sanitize_input(module)
            clean_message = sanitize_input(message)
            with _activity_file_lock:
                with open(ACTIVITY_LOG_FILE, "a", encoding="utf-8") as f:
                    f.write(f"{ts} [{worker_id}] {clean_module:<14} {clean_message}\n")
        except OSError as e:
            logging.error(f"Failed to write activity log file: {e}")
    logging.info(f"[{worker_id}] {module} - {message}")


def _is_transient_status_message(message: str) -> bool:
    msg = sanitize_input(message)
    if not msg:
        return False
    # Spinner frames (e.g. "- 1s | ETA: 10s", "\\ 0s", "| 2s")
    return msg[0] in "-\\|/" and "s" in msg[:8]

# ─────────────────────────────────────────────────────────────
# Snapshot (auto-called on error)
# ─────────────────────────────────────────────────────────────

def ui_snapshot(label: str = "manual", context: str = ""):
    snap = {
        'ts': datetime.now().isoformat(), 'label': label, 'context': context,
        'workers': {}, 'activity': []
    }
    with _workers_lock:
        for wid, ws in _workers.items():
            snap['workers'][wid] = {
                'target': ws.get('target'), 'status': ws.get('status'),
                'current_tool': ws.get('current_tool'), 'metrics': ws.get('metrics'),
                'tools': {t: ws['tools'][t]['status'] for t in PIPELINE_TOOLS},
            }
    with _activity_lock:
        snap['activity'] = [(ts, wid, mod, msg, col)
                            for ts, wid, mod, msg, col in list(_activity)[-30:]]
    snap_path = f"logs/snapshot_{label}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(snap_path, 'w') as f:
            json.dump(snap, f, indent=2, default=str)
        logging.info(f"Snapshot saved: {snap_path}")
    except Exception as e:
        logging.error(f"Snapshot save failed: {e}")

# ─────────────────────────────────────────────────────────────
# Public API (used by scanner.py, main.py, watchdog.py)
# ─────────────────────────────────────────────────────────────

def ui_log(module: str, message: str, color=None):
    """Log a message → activity log + file. In single mode also prints."""
    worker_id = _get_current_worker()
    msg_u = str(module).upper()
    level_color = "white"
    if any(k in msg_u for k in ("ERR", "ERROR", "ABORTADO")):
        level_color = "red"
    elif any(k in msg_u for k in ("WARNING", "WARN", "ANOMALIA", "GUARD")):
        level_color = "yellow"
    elif any(k in msg_u for k in ("RESULTADO", "SUCCESS", "REPORT")):
        level_color = "green"
    elif any(k in msg_u for k in ("WATCHDOG", "MISSION", "MODE")):
        level_color = "cyan"
    _activity_push(worker_id, module, message, level_color)
    if not _WATCHDOG_MODE:
        icon = ICONS.get(module.upper(), ICONS.get(module, "●"))
        ts = datetime.now().strftime("%H:%M:%S")
        with _stdout_lock:
            sys.stdout.write("\r\033[2K")  # clear any in-progress spinner line
            sys.stdout.flush()
            _console.print(f"[dim]{ts}[/dim] {icon} [bold]{module:<12}[/bold] {message}")

def _buffer_append(module: str, message: str):
    ui_log(module, message)

def ui_update_status(step: str, detail: str, color=None):
    if _WATCHDOG_MODE:
        if _is_transient_status_message(detail):
            return
        ui_log(step, detail, color)
        return
    # Non-watchdog: in-place spinner line (overwrite same line, no newline)
    icon = ICONS.get(step.upper(), ICONS.get(step, "●"))
    ts = datetime.now().strftime("%H:%M:%S")
    with _stdout_lock:
        sys.stdout.write(f"\r\033[2K{Colors.DIM}{ts}{Colors.RESET} {icon} {Colors.BOLD}{step:<12}{Colors.RESET} {detail}")
        sys.stdout.flush()

def ui_set_mission_meta(target: str, current: int = 0, total: int = 0):
    _live_view_meta["target"] = target
    _live_view_meta["current"] = current
    _live_view_meta["total"] = total

def ui_banner():
    _console.print(Panel(
        "[bold cyan]HUNT3R v1.0-EXCALIBUR[/bold cyan]\n[dim]Autonomous Bug Bounty Hunter[/dim]",
        border_style="cyan", box=ROUNDED
    ))

def ui_clear():
    if not _WATCHDOG_MODE:
        _console.clear()

def ui_clear_and_banner():
    if not _WATCHDOG_MODE:
        _console.clear()
        _console.print(Panel(
            "[bold cyan]HUNT3R v1.0-EXCALIBUR[/bold cyan]\n[dim]UX/UI PREDADOR - EDITION[/dim]",
            border_style="cyan", box=ROUNDED
        ))

def ui_enable_watchdog_mode():
    """Enable watchdog mode: starts Rich Live full-screen display."""
    global _WATCHDOG_MODE
    _WATCHDOG_MODE = True
    try:
        with _activity_file_lock:
            with open(ACTIVITY_LOG_FILE, "w", encoding="utf-8") as f:
                f.write(f"=== HUNT3R WATCHDOG ACTIVITY START {datetime.now().isoformat()} ===\n")
    except OSError as e:
        logging.error(f"Failed to initialize activity log file: {e}")
    _render_stop.clear()
    rt = threading.Thread(target=_render_loop, daemon=True, name="RenderThread")
    rt.start()
    global _render_thread
    _render_thread = rt

def ui_mission_header(handle: str, score: int = 0):
    global _MISSION_START_TIME
    _MISSION_START_TIME = datetime.now()
    if _WATCHDOG_MODE:
        return  # Worker panels handle display in watchdog mode
    _console.clear()
    _console.print(Panel(
        "[bold cyan]HUNT3R v1.0-EXCALIBUR[/bold cyan]\n[dim]Autonomous Bug Bounty Hunter[/dim]",
        border_style="cyan", box=ROUNDED
    ))
    clean_handle = handle.replace('_', '.').replace('*', '').upper()
    score_color = "green" if score >= 70 else "yellow" if score >= 40 else "dim"
    t = Table(show_header=False, box=ROUNDED, border_style="cyan")
    t.add_row("[bold]🎯 TARGET[/bold]", f"[bold cyan]{clean_handle}[/bold cyan]")
    t.add_row("[bold]📊 SCORE[/bold]", f"[{score_color}]{score}[/{score_color}]")
    _console.print(t)
    _console.print()

def ui_mission_footer(stats: Dict[str, Any] = None):
    if stats is None:
        stats = {}
    if not _WATCHDOG_MODE and _MISSION_START_TIME:
        elapsed = datetime.now() - _MISSION_START_TIME
        mins, secs = divmod(int(elapsed.total_seconds()), 60)
        ui_log("RESULTADO", f"Mission completed (⏱️ {mins:02d}m {secs:02d}s)")

def ui_scan_summary(results: dict):
    global _MISSION_START_TIME
    if _WATCHDOG_MODE:
        # In watchdog mode, ui_worker_done handles the result logging
        return
    _stop_live_view()
    duration_str = ""
    if _MISSION_START_TIME:
        elapsed = datetime.now() - _MISSION_START_TIME
        mins, secs = divmod(int(elapsed.total_seconds()), 60)
        duration_str = f" (⏱️ {mins:02d}m {secs:02d}s)"
    clean_handle = results.get('target', 'UNKNOWN').replace('_', '.').replace('*', '').upper()
    with _stdout_lock:
        st = Table(title=f"RESUMO DA CAÇADA{duration_str}", box=ROUNDED, border_style="magenta")
        st.add_column("Métrica", style="bold cyan")
        st.add_column("Valor", style="green")
        st.add_row("🎯 Alvo", clean_handle)
        st.add_row("📊 Score", str(results.get('score', 0)))
        st.add_row("🌐 Subs Vivos", f"{results.get('alive', 0)} / {results.get('subdomains', 0)}")
        st.add_row("⚡ Endpoints", str(results.get('endpoints', 0)))
        st.add_row("🔑 Secrets", str(results.get('secrets', 0) or results.get('js_secrets', 0)))
        st.add_row("☢️ Vulns", str(results.get('vulns', 0)))
        _console.print(st)

# ─────────────────────────────────────────────────────────────
# Legacy Tool Status API (backward compat — scanner.py still uses these)
# ─────────────────────────────────────────────────────────────

def tool_started(name: str, input_count: int = 0, avg_eta: float = 0):
    with _live_view_lock:
        if name in _live_view_data:
            _live_view_data[name].update(
                {"status": "running", "start_time": time.time(),
                 "eta": avg_eta, "input_count": input_count})

def tool_finished(name: str, result_count: int = 0, result_key: str = ""):
    with _live_view_lock:
        if name in _live_view_data:
            _live_view_data[name].update({"status": "finished", "start_time": None})
            if result_key:
                _live_view_data[name][result_key] = result_count

def tool_cached(name: str, result_count: int = 0, result_key: str = ""):
    with _live_view_lock:
        if name in _live_view_data:
            _live_view_data[name].update({"status": "cached", "start_time": None})
            if result_key:
                _live_view_data[name][result_key] = result_count

def tool_error(name: str):
    with _live_view_lock:
        if name in _live_view_data:
            _live_view_data[name].update({"status": "error", "start_time": None})

def nuclei_update(requests_done: int, requests_total: int, rps: float, matched: int):
    with _live_view_lock:
        _live_view_data["Nuclei"].update({
            "requests_done": requests_done, "requests_total": requests_total,
            "rps": rps, "matched": matched})

# ─────────────────────────────────────────────────────────────
# Rich Live Rendering (Watchdog Mode)
# ─────────────────────────────────────────────────────────────

_STATUS_SYMS = {
    'idle':    ('○', 'dim white'),
    'running': ('◌', 'yellow'),
    'done':    ('✓', 'green'),
    'cached':  ('◈', 'cyan'),
    'error':   ('✗', 'red'),
    'finished': ('✓', 'green'),
}

def _progress_bar(ratio: float, width: int = 10, style: str = "green") -> str:
    filled = int(ratio * width)
    empty = width - filled
    return f"[{style}]{'█' * filled}[/][dim]{'░' * empty}[/]"

def _render_worker_panel(w: Dict) -> Panel:
    now = time.time()
    wid = w['id']
    status = w['status']
    target = w.get('target') or 'IDLE'

    if status == 'idle':
        content = Align(Text("— WAITING —", style="dim white"), "center")
        border = "dim white"
        title = f"[dim]{wid}[/dim]"
        return Panel(content, title=title, border_style=border, box=ROUNDED, padding=(0, 1), height=13)

    clean = target.replace('*', '').replace(':', '').upper()
    if len(clean) > 20:
        clean = clean[:17] + "..."
    idx = w.get('idx', 0)
    total = w.get('total', 0)
    start = w.get('start_time')
    elapsed_s = int(now - start) if start else 0
    m, s = divmod(elapsed_s, 60)
    elapsed_str = f"⏱{m:02d}m{s:02d}s"

    tbl = Table(show_header=False, box=None, padding=(0, 0), expand=True)
    tbl.add_column("s",    width=2,  no_wrap=True)
    tbl.add_column("tool", width=13, no_wrap=True)
    tbl.add_column("bar",  width=12, no_wrap=True)
    tbl.add_column("info", width=8, no_wrap=True, overflow="crop")

    for tool_name in PIPELINE_TOOLS:
        t = w['tools'].get(tool_name, {'status': 'idle', 'count': 0})
        st = t.get('status', 'idle')
        sym, sym_style = _STATUS_SYMS.get(st, _STATUS_SYMS['idle'])

        count = t.get('count', 0)
        t_start = t.get('start_time')
        eta = t.get('eta', 0.0)

        if st == 'running':
            # Nuclei: use request-based ratio
            if tool_name == "Nuclei":
                nq = w.get('nuclei_req', {})
                ntotal = nq.get('total', 0)
                if ntotal > 0:
                    ratio = min(1.0, nq.get('done', 0) / ntotal)
                    rps = nq.get('rps', 0.0)
                    matched = nq.get('matched', 0)
                    ndone = nq.get('done', 0)
                    bar_style = "green" if ratio < 0.7 else "yellow"
                    info_str = f"[dim]{ndone}/{ntotal} {rps:.0f}r/s {matched}↑[/dim]"
                else:
                    sec_e = int(now - t_start) if t_start else 0
                    ratio = 0.0
                    bar_style = "yellow"
                    info_str = f"[dim]{sec_e}s[/dim]"
            elif t_start and eta > 0:
                ratio = min(1.0, (now - t_start) / eta)
                remaining = max(0, int(eta - (now - t_start)))
                bar_style = "green" if ratio < 0.7 else "yellow" if ratio < 0.95 else "red"
                info_str = f"[dim]~{remaining}s[/dim]"
            else:
                sec_e = int(now - t_start) if t_start else 0
                ratio = 0.0
                bar_style = "yellow"
                info_str = f"[dim]{sec_e}s[/dim]"
        elif st in ('done', 'finished'):
            ratio = 1.0
            bar_style = "green"
            info_str = f"[green]{count}[/green]"
        elif st == 'cached':
            ratio = 1.0
            bar_style = "cyan"
            info_str = f"[cyan]{count}[/cyan]"
        elif st == 'error':
            ratio = 1.0
            bar_style = "red"
            info_str = "[red]ERR[/red]"
        else:  # idle
            ratio = 0.0
            bar_style = "dim white"
            info_str = "[dim]—[/dim]"

        bar = _progress_bar(ratio, width=10, style=bar_style)
        tool_style = "bold yellow" if st == 'running' else "dim" if st == 'idle' else "white"
        # Use ASCII-only labels in worker tables to avoid terminal width drift with emoji.
        label_txt = tool_name[:12]
        tbl.add_row(
            f"[{sym_style}]{sym}[/]",
            f"[{tool_style}]{label_txt:<12}[/]",
            bar,
            info_str,
        )

    m_data = w.get('metrics', {})
    vulns = m_data.get('vulns', 0)
    metrics = Text()
    metrics.append(f" SUB:{m_data.get('subs',0):<4}", style="white")
    metrics.append(f" LV:{m_data.get('live',0):<4}", style="green")
    metrics.append(f" EP:{m_data.get('endpoints',0):<4}", style="yellow")
    metrics.append(f" SEC:{m_data.get('secrets',0):<3}", style="magenta")
    metrics.append(f" VN:{vulns}", style="bold red" if vulns > 0 else "dim white")

    content = Group(tbl, Rule(style="dim"), metrics)
    border = "yellow" if status == 'running' else "green" if status == 'done' else "dim"
    title = f"[bold]{wid}[/bold]: [cyan]{clean}[/cyan] [{idx}/{total}] {elapsed_str}"
    return Panel(
        content, title=title, border_style=border, box=ROUNDED,
        padding=(0, 0), height=13, expand=True
    )

def _render_activity_panel(n: int = 18) -> Panel:
    with _activity_lock:
        recent = list(_activity)[-n:]
    log_text = Text()
    for ts, wid, module, message, color in recent:
        log_text.append(f" {ts} ", style="dim")
        log_text.append(f"[{wid}]", style="bold cyan")
        log_text.append(f" {module:<14} ", style="dim white")
        log_text.append(f"{message}\n", style=color)
    if not recent:
        log_text = Text("  — no activity yet —", style="dim", justify="center")
    return Panel(log_text, title="[bold]ACTIVITY LOG[/bold]",
                 border_style="dim white", box=ROUNDED, padding=(0, 1))

def _render_banner() -> Panel:
    now_str = datetime.now().strftime("%H:%M:%S")
    runtime = datetime.now() - _session_start
    h, rem = divmod(int(runtime.total_seconds()), 3600)
    m, s = divmod(rem, 60)
    with _stats_lock:
        scanned = _total_scanned
        cycle = _cycle_count
    with _workers_lock:
        running = sum(1 for w in _workers.values() if w.get('status') == 'running')
        done = sum(1 for w in _workers.values() if w.get('status') == 'done')
        errors = sum(
            1
            for w in _workers.values()
            if any(t.get('status') == 'error' for t in w.get('tools', {}).values())
        )
    title_text = Text(justify="center")
    title_text.append("HUNT3R", style="bold cyan")
    title_text.append(" v1.0-EXCALIBUR  ◆  ", style="dim")
    title_text.append("WATCHDOG PREDADOR", style="bold magenta")
    title_text.append("  ◆  ", style="dim")
    title_text.append("24/7 AUTONOMOUS RECON", style="dim cyan")
    stats_text = Text(justify="center")
    stats_text.append(f"🕒 {now_str}  ", style="white")
    stats_text.append(f"CYCLE {cycle:02d}  ", style="bold cyan")
    stats_text.append(f"Runtime {h:02d}h{m:02d}m{s:02d}s  ", style="dim")
    stats_text.append(f"{scanned} targets scanned  ", style="dim white")
    stats_text.append(f"RUN:{running} ", style="yellow")
    stats_text.append(f"DONE:{done} ", style="green")
    stats_text.append(f"ERR:{errors}", style="bold red" if errors else "dim white")
    return Panel(
        Group(Align(title_text, "center"), Align(stats_text, "center")),
        border_style="cyan", box=ROUNDED, padding=(0, 1))

def _build_watchdog_layout():
    with _workers_lock:
        panels = [_render_worker_panel(dict(
            {**_workers[wid], 'tools': {k: dict(v) for k, v in _workers[wid]['tools'].items()}}
        )) for wid in _WORKER_SLOTS]
    return Group(
        _render_banner(),
        Columns(panels, equal=True, expand=True),
        _render_activity_panel(n=18),
    )


def _can_use_fullscreen_live() -> bool:
    """Guard full-screen mode for very small terminals."""
    try:
        size = os.get_terminal_size()
        return size.columns >= _MIN_FULLSCREEN_COLS and size.lines >= _MIN_FULLSCREEN_LINES
    except OSError:
        return True

def _render_loop():
    console = Console(force_terminal=True)
    retries = 0
    use_fullscreen = _can_use_fullscreen_live()
    if not use_fullscreen:
        logging.warning(
            "Terminal too small for fullscreen Live (%sx%s); using non-fullscreen mode.",
            _MIN_FULLSCREEN_COLS,
            _MIN_FULLSCREEN_LINES,
        )
    while not _render_stop.is_set() and retries < 5:
        try:
            with Live(console=console, refresh_per_second=4, screen=use_fullscreen) as live:
                while not _render_stop.is_set():
                    try:
                        live.update(_build_watchdog_layout())
                    except Exception as e:
                        logging.error(f"Render update error: {e}")
                    time.sleep(0.25)
            break  # clean exit
        except Exception as e:
            logging.error(f"Live display crashed (retry {retries}): {e}")
            retries += 1
            time.sleep(1)

# ─────────────────────────────────────────────────────────────
# Single-Mode Legacy Live View (non-watchdog)
# ─────────────────────────────────────────────────────────────

def _start_live_view():
    pass  # No-op: watchdog uses _render_loop; single mode uses direct prints

def _stop_live_view():
    global _live_thread
    if _live_thread:
        _live_thread.running = False
        _live_thread.join(timeout=2.0)
        _live_thread = None

# ─────────────────────────────────────────────────────────────
# Cleanup
# ─────────────────────────────────────────────────────────────

def _terminal_cleanup():
    global _cleanup_done
    with _cleanup_lock:
        if _cleanup_done:
            return
        _cleanup_done = True
    _render_stop.set()
    if _render_thread and _render_thread.is_alive():
        _render_thread.join(timeout=2.0)
    _stop_live_view()
    try:
        sys.stdout.write("\033[?25h")  # restore cursor
        sys.stdout.flush()
    except OSError:
        pass
    _console.print("[dim]Hunt3r terminated[/dim]")

atexit.register(_terminal_cleanup)

def _sigint_handler(signum, frame):
    _render_stop.set()
    _interrupt_event.set()
    if not sys.is_finalizing():
        raise KeyboardInterrupt


def ui_interrupt_requested() -> bool:
    return _interrupt_event.is_set()

def _sigwinch_handler(signum, frame):
    pass  # Rich Live handles resize internally

signal.signal(signal.SIGINT, _sigint_handler)
signal.signal(signal.SIGWINCH, _sigwinch_handler)

# ─────────────────────────────────────────────────────────────
# Interactive Menus (main.py)
# ─────────────────────────────────────────────────────────────

def ui_model_selection_menu(models: list) -> str:
    print(f"\n\r\033[K  {'─'*56}")
    print(f"\r\033[K  {Colors.BOLD}MODELOS OPENROUTER{Colors.RESET}")
    print(f"\r\033[K  {'─'*56}\n")
    for idx, m in enumerate(models, 1):
        mid = m.get('id', 'unknown')[:42]
        name = m.get('name', mid)[:24]
        print(f"\r\033[K    {Colors.SECONDARY}[{idx:<2}]{Colors.RESET} {Colors.INFO}{name:<26}{Colors.RESET} {Colors.DIM}{mid}{Colors.RESET}")
    print(f"\n\r\033[K  {'─'*56}")
    try:
        return input(f"\r\033[K  {Colors.BOLD}Selecione o modelo (1-{len(models)}): {Colors.RESET}").strip()
    except EOFError:
        return ""

def ui_platform_selection_menu(platforms: list) -> str:
    if not platforms:
        return ''
    print("\n  Plataformas disponíveis:")
    for i, p in enumerate(platforms, 1):
        print(f"   [{i}] {p.get('name', str(p))}")
    try:
        sel = int(input(f"  Selecione (1-{len(platforms)}): ").strip())
    except (EOFError, ValueError, KeyboardInterrupt):
        return ''
    if 1 <= sel <= len(platforms):
        return platforms[sel-1].get('name')
    return ''

def ui_target_selection_list(ranked: list):
    if not ranked:
        print("  (Nenhum alvo)")
        return
    for i, t in enumerate(ranked, 1):
        print(f"  [{i}] {t.get('handle', 'unknown')} (score: {t.get('score', 0)})")

def ui_manual_target_input() -> dict:
    from core.config import validate_and_extract_domain, is_ip_target, expand_cidr
    try:
        dom = input("  Dominio ou IP/CIDR (ex: example.com, 192.168.1.0/24): ").strip()
        if not dom:
            return {}
        if is_ip_target(dom):
            ips = expand_cidr(dom)
            handle = dom.replace('.', '_').replace('/', '_').replace(':', '_')
            return {'domain': dom, 'domains': ips, 'handle': handle, 'score': 30, 'scope_type': 'ip'}
        clean_domain = validate_and_extract_domain(dom)
        if not clean_domain:
            print(f"  {Colors.ERROR}Entrada invalida (dominio, IP ou CIDR esperado).{Colors.RESET}")
            return {}
        handle = clean_domain.replace('.', '_').replace('-', '_')
        return {'domain': clean_domain, 'domains': [clean_domain], 'handle': handle, 'score': 30}
    except Exception as e:
        logging.error(f"Manual target input error: {e}")
        return {}

def ui_custom_targets_list(targets: list) -> dict:
    if not targets:
        return {}
    for i, t in enumerate(targets, 1):
        scope = f" {Colors.DIM}[IP]{Colors.RESET}" if t.get('scope_type') == 'ip' else ""
        print(f"  {Colors.SECONDARY}[{i}]{Colors.RESET} {t.get('domain', t.get('handle', '?'))}{scope}")
    try:
        sel = int(input(f"  Selecione (1-{len(targets)}): ").strip())
        if 1 <= sel <= len(targets):
            return targets[sel-1]
    except (ValueError, EOFError, KeyboardInterrupt):
        pass
    return {}


def ui_main_menu() -> str:
    print(f"  {Colors.BOLD}MENU PRINCIPAL{Colors.RESET}")
    print(f"  {'─'*44}")
    print(f"  {Colors.SECONDARY}[1]{Colors.RESET} {Colors.INFO}Plataformas  {Colors.DIM}(H1 / Intigriti / BC){Colors.RESET}")
    print(f"  {Colors.SECONDARY}[2]{Colors.RESET} {Colors.INFO}Alvo Manual  {Colors.DIM}(dominio, IP ou CIDR){Colors.RESET}")
    print(f"  {Colors.SECONDARY}[3]{Colors.RESET} {Colors.INFO}Selecionar da alvos.txt{Colors.RESET}")
    print(f"  {Colors.SECONDARY}[4]{Colors.RESET} {Colors.WARNING}☠  Cacar TODOS os alvos.txt{Colors.RESET}")
    print(f"  {Colors.SECONDARY}[5]{Colors.RESET} {Colors.DIM}Trocar Modelo de IA{Colors.RESET}")
    print(f"  {'─'*44}")
    print(f"  {Colors.SECONDARY}[0]{Colors.RESET} {Colors.DIM}Sair{Colors.RESET}")
    print(f"  {'─'*44}")
    try:
        return input(f"  {Colors.BOLD}Opcao: {Colors.RESET}").strip()
    except EOFError:
        return ""

__all__ = [
    'ui_log', 'ui_update_status', 'ui_banner', 'ui_clear', 'ui_clear_and_banner',
    'ui_mission_header', 'ui_mission_footer', 'ui_scan_summary', 'ui_set_mission_meta',
    'ui_snapshot', 'Colors', 'ICONS', 'sanitize_input',
    'tool_started', 'tool_finished', 'tool_cached', 'tool_error', 'nuclei_update',
    '_live_view_data', '_live_view_lock', '_stdout_lock', '_buffer_append',
    'ui_main_menu', 'ui_model_selection_menu', 'ui_platform_selection_menu',
    'ui_target_selection_list', 'ui_manual_target_input', 'ui_custom_targets_list',
    'ui_enable_watchdog_mode', 'ui_worker_register', 'ui_worker_done',
    'ui_worker_tool_started', 'ui_worker_tool_finished', 'ui_worker_tool_cached',
    'ui_worker_tool_error', 'ui_worker_nuclei_update', 'ui_cycle_started',
    'set_worker_context', '_get_current_worker',
]
