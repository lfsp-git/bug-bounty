"""
HUNT3R v1.0-EXCALIBUR - Rich-based UI Manager [REAL-TIME EDITION]

Fixed layout:
  - Top 12 rows: Banner (fixed)
  - Middle rows: Scrolling logs (10-20 lines)
  - Bottom 12 rows: Live view (fixed)
"""

import os
import sys
import time
import re
import atexit
import signal
from datetime import datetime
import threading
import logging
from collections import defaultdict
from typing import Any, Dict, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.layout import Layout
from rich.text import Text
from rich.progress import Progress, BarColumn, TextColumn, DownloadColumn, TransferSpeedColumn, TimeRemainingColumn
from rich.box import ROUNDED
from rich.style import Style

# Legacy fallback imports for compatibility
try:
    from colorama import Fore as _Fore, Style as _Style, init as colorama_init
    colorama_init(autoreset=True)
    Fore = _Fore
    Style_colorama = _Style
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    class AnsiFore:
        RED = ''; GREEN = ''; YELLOW = ''; CYAN = ''; MAGENTA = ''; WHITE = ''; BLACK = ''
    class AnsiStyle:
        RESET_ALL = ''; BRIGHT = ''; DIM = ''
    Fore = AnsiFore
    Style_colorama = AnsiStyle

# Legacy Colors class (compatibility layer)
class Colors:
    PRIMARY = "\033[36m"      # Cyan
    SECONDARY = "\033[35m"    # Magenta
    SUCCESS = "\033[32m"      # Green
    WARNING = "\033[33m"      # Yellow
    ERROR = "\033[31m"        # Red
    INFO = "\033[37m"         # White
    DIM = "\033[90m"          # Dim
    BOLD = "\033[1m"          # Bold
    RESET = "\033[0m"         # Reset

# Logging APENAS EM ARQUIVO
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(message)s',
    datefmt='%H:%M:%S',
    handlers=[
        logging.FileHandler('logs/hunt3r.log', encoding='utf-8')
    ]
)

ANSI_ESCAPE_RE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

def sanitize_input(text: str) -> str:
    clean = ANSI_ESCAPE_RE.sub('', str(text))
    return clean.replace('\n', '').replace('\r', '').strip()

# Icons for tools
ICONS = {
    "WATCHDOG": "🚨", "PREDADOR": "🦖", "SUBFINDER": "🌐", "DNSX": "🌍",
    "HTTPX": "⚡", "KATANA": "🕷️", "JS HUNTER": "🔑", "NUCLEI": "☢️",
    "NUCLEI INFRA": "🏗️", "NUCLEI ENDP": "💉", "NUCLEI DEEP": "🕳️",
    "IA": "🧠", "ESCALATOR": "⛓️", "RESULTADO": "🏁", "SMART FILTER": "🧃",
    "UNCOVER": "👁️", "DIFF NOVO": "✨", "DIFF SECRETS": "🔥", "MODE": "⚙️",
    "ERR": "❌", "ABORTADO": "🛑", "ANOMALIA": "⚠️", "DICA": "💡",
    "RECON": "🔍", "EXTRACTION": "🗃️", "RECURSIVIDADE": "🔁", "DISK": "💾"
}

# Global state
_MISSION_START_TIME: Optional[datetime] = None
_console = Console(force_terminal=True)
_live_view_data: Dict[str, Dict[str, Any]] = {}
_live_view_lock = threading.RLock()
_stdout_lock = threading.Lock()
_live_thread: Optional[threading.Thread] = None
_log_lines = []
_log_lines_lock = threading.Lock()
_MAX_LOG_LINES = 20

# Live view metadata
_live_view_meta = {"target": "", "current": 0, "total": 0}

# Initialize live view data structure
def _reset_live_view_data():
    global _live_view_data
    _live_view_data = {
        "Subfinder": {"status": "idle", "subs": 0, "start_time": None, "eta": 0, "input_count": 0},
        "DNSX": {"status": "idle", "live": 0, "start_time": None, "eta": 0, "input_count": 0},
        "Uncover": {"status": "idle", "takeovers": 0, "start_time": None, "eta": 0, "input_count": 0},
        "HTTPX": {"status": "idle", "endpoints": 0, "start_time": None, "eta": 0, "input_count": 0},
        "Katana": {"status": "idle", "crawled": 0, "start_time": None, "eta": 0, "input_count": 0},
        "JS Hunter": {"status": "idle", "secrets": 0, "start_time": None, "eta": 0, "input_count": 0},
        "Nuclei": {"status": "idle", "vulns": 0, "start_time": None, "eta": 0, "input_count": 0,
                   "requests_total": 0, "requests_done": 0, "rps": 0, "matched": 0},
    }

_reset_live_view_data()

# ─────────────────────────────────────────────────────────────
# UI Functions (Public API - maintain backward compatibility)
# ─────────────────────────────────────────────────────────────

def ui_log(module: str, message: str, color=Colors.RESET):
    """Log a message with module prefix"""
    with _log_lines_lock:
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {ICONS.get(module, '●')} {module:<12} {message}"
        _log_lines.append(line)
        if len(_log_lines) > _MAX_LOG_LINES:
            _log_lines.pop(0)
    
    # Also write to file
    logging.info(f"{module} - {message}")

def ui_update_status(step: str, detail: str, color=Colors.PRIMARY):
    """Update a status line (used by spinners)"""
    ui_log(step, detail, color)

def ui_set_mission_meta(target: str, current: int = 0, total: int = 0):
    """Set mission metadata (target, current progress)"""
    _live_view_meta["target"] = target
    _live_view_meta["current"] = current
    _live_view_meta["total"] = total

def ui_banner():
    """Display banner"""
    _console.clear()
    _console.print(Panel(
        "[bold cyan]HUNT3R v1.0-EXCALIBUR[/bold cyan]\n"
        "[dim]UX/UI PREDADOR - EDITION[/dim]",
        border_style="cyan",
        box=ROUNDED
    ))

def ui_clear():
    """Clear screen"""
    _console.clear()

def ui_clear_and_banner():
    """Clear and show banner"""
    ui_clear()
    ui_banner()

def ui_snapshot(label: str = "manual", context: str = ""):
    """Snapshot terminal state to log (for debugging)"""
    with _log_lines_lock:
        ui_log("SNAPSHOT", f"{label}: {context}")

def ui_mission_header(handle: str, score: int = 0):
    """Show mission header with target and score"""
    global _MISSION_START_TIME
    _MISSION_START_TIME = datetime.now()
    
    ui_clear_and_banner()
    
    clean_handle = handle.replace('_', '.').replace('*', '').upper()
    score_color = "green" if score >= 70 else "yellow" if score >= 40 else "dim"
    
    header_table = Table(show_header=False, box=ROUNDED, border_style="cyan")
    header_table.add_row(f"[bold]🎯 TARGET[/bold]", f"[bold cyan]{clean_handle}[/bold cyan]")
    header_table.add_row(f"[bold]📊 SCORE[/bold]", f"[{score_color}]{score}[/{score_color}]")
    
    _console.print(header_table)
    _console.print()  # blank line
    
    # Start live view rendering
    _start_live_view()

def ui_mission_footer(stats: Dict[str, Any]):
    """Display mission footer with summary stats"""
    if _MISSION_START_TIME:
        elapsed = datetime.now() - _MISSION_START_TIME
        mins, secs = divmod(int(elapsed.total_seconds()), 60)
        duration = f" (⏱️ {mins:02d}m {secs:02d}s)"
    else:
        duration = ""
    
    footer_text = f"Mission completed{duration}"
    ui_log("RESULTADO", footer_text, Colors.SUCCESS)

def ui_scan_summary(results: dict):
    """Display scan summary (equivalent to old ui_scan_summary)"""
    global _MISSION_START_TIME
    
    _stop_live_view()
    
    duration_str = ""
    if _MISSION_START_TIME:
        elapsed = datetime.now() - _MISSION_START_TIME
        mins, secs = divmod(int(elapsed.total_seconds()), 60)
        duration_str = f" (⏱️ {mins:02d}m {secs:02d}s)"
    
    clean_handle = results.get('target', 'UNKNOWN').replace('_', '.').replace('*', '').upper()
    
    with _stdout_lock:
        summary_table = Table(title=f"RESUMO DA CAÇADA{duration_str}", box=ROUNDED, border_style="magenta")
        summary_table.add_column("Métrica", style="bold cyan")
        summary_table.add_column("Valor", style="green")
        
        summary_table.add_row("🎯 Alvo", clean_handle)
        summary_table.add_row("📊 Score", str(results.get('score', 0)))
        summary_table.add_row("🌐 Subs Vivos", f"{results.get('alive', 0)} / {results.get('subdomains', 0)}")
        summary_table.add_row("⚡ Endpoints", str(results.get('endpoints', 0)))
        summary_table.add_row("🔑 Secrets", str(results.get('secrets', 0)))
        summary_table.add_row("☢️ Vulns", str(results.get('vulns', 0)))
        
        _console.print(summary_table)

# ─────────────────────────────────────────────────────────────
# Tool Status Tracking
# ─────────────────────────────────────────────────────────────

def tool_started(name: str, input_count: int = 0, avg_eta: float = 0):
    """Mark tool as started"""
    with _live_view_lock:
        if name in _live_view_data:
            _live_view_data[name]["status"] = "running"
            _live_view_data[name]["start_time"] = time.time()
            _live_view_data[name]["eta"] = avg_eta
            _live_view_data[name]["input_count"] = input_count

def tool_finished(name: str, result_count: int = 0, result_key: str = ""):
    """Mark tool as finished"""
    with _live_view_lock:
        if name in _live_view_data:
            _live_view_data[name]["status"] = "finished"
            _live_view_data[name]["start_time"] = None
            if result_key:
                _live_view_data[name][result_key] = result_count

def tool_cached(name: str, result_count: int = 0, result_key: str = ""):
    """Mark tool as cached (skipped)"""
    with _live_view_lock:
        if name in _live_view_data:
            _live_view_data[name]["status"] = "cached"
            _live_view_data[name]["start_time"] = None
            if result_key:
                _live_view_data[name][result_key] = result_count

def tool_error(name: str):
    """Mark tool as errored"""
    with _live_view_lock:
        if name in _live_view_data:
            _live_view_data[name]["status"] = "error"
            _live_view_data[name]["start_time"] = None

def nuclei_update(requests_done: int, requests_total: int, rps: float, matched: int):
    """Update Nuclei progress (called from output parsing)"""
    with _live_view_lock:
        _live_view_data["Nuclei"]["requests_done"] = requests_done
        _live_view_data["Nuclei"]["requests_total"] = requests_total
        _live_view_data["Nuclei"]["rps"] = rps
        _live_view_data["Nuclei"]["matched"] = matched

# ─────────────────────────────────────────────────────────────
# Live View Rendering
# ─────────────────────────────────────────────────────────────

def _get_terminal_rows() -> int:
    """Get terminal height"""
    try:
        return os.get_terminal_size().lines
    except:
        return 40

def _render_tool_status(tool: str, data: Dict[str, Any]) -> Text:
    """Render a single tool status line"""
    now = time.time()
    status = data.get("status", "idle")
    
    # Status icon with color
    if status == "idle":
        icon_style = "dim white"
        status_color = "dim white"
    elif status == "running":
        icon_style = "yellow"
        status_color = "yellow"
    elif status == "cached":
        icon_style = "cyan"
        status_color = "cyan"
    elif status == "finished":
        icon_style = "green" if data.get(list(data.keys())[-1], 0) > 0 else "blue"
        status_color = icon_style
    elif status == "error":
        icon_style = "red"
        status_color = "red"
    else:
        icon_style = "dim white"
        status_color = "dim white"
    
    # Progress bar
    start_t = data.get("start_time")
    eta = data.get("eta", 0)
    
    if status == "running":
        req_total = data.get("requests_total", 0)
        if tool == "Nuclei" and req_total > 0:
            ratio = min(1.0, data.get("requests_done", 0) / req_total)
        elif start_t and eta > 0:
            ratio = min(1.0, (now - start_t) / eta)
        else:
            ratio = 0.0
    elif status in ("finished", "cached", "error"):
        ratio = 1.0
    else:
        ratio = 0.0
    
    filled = int(ratio * 15)
    empty = 15 - filled
    bar_text = f"[{status_color}]{'█' * filled}[/]{'░' * empty}"
    
    # Result count
    count_keys = [k for k in data.keys() if k not in ("status", "start_time", "eta", "input_count", "requests_total", "requests_done", "rps", "matched")]
    count = data.get(count_keys[0], 0) if count_keys else 0
    
    # Extra info for running tools
    extra = ""
    if status == "running" and tool == "Nuclei":
        req_total = data.get("requests_total", 0)
        if req_total > 0:
            rps = data.get("rps", 0)
            done = data.get("requests_done", 0)
            matched = data.get("matched", 0)
            extra = f" Req/s {rps} | {done}/{req_total} | {matched} hits"
    elif status == "running" and start_t and eta > 0:
        remaining = max(0, int(eta - (now - start_t)))
        extra = f" ~{remaining}s"
    
    line = Text()
    line.append(f"● ", style=icon_style)
    line.append(f"{tool:<12} ", style="bold")
    line.append(bar_text, style=status_color)
    line.append(f" {status:<9} ", style=status_color)
    line.append(f"{count:<5}", style="bold cyan")
    line.append(extra, style="dim")
    
    return line

def _render_live_view_panel() -> Panel:
    """Build live view panel with all tool statuses"""
    with _live_view_lock:
        data_snap = {k: dict(v) for k, v in _live_view_data.items()}
        meta_snap = dict(_live_view_meta)
    
    # Build header with mission info
    target = meta_snap.get("target", "")
    cur = meta_snap.get("current", 0)
    total = meta_snap.get("total", 0)
    
    elapsed_str = ""
    if _MISSION_START_TIME:
        secs = int((datetime.now() - _MISSION_START_TIME).total_seconds())
        m, s = divmod(secs, 60)
        elapsed_str = f" ⏱️ {m:02d}m{s:02d}s"
    
    progress_str = f" [{cur}/{total}]" if total else ""
    target_str = f" 🎯 {target}" if target else ""
    
    title = f"LIVE VIEW{target_str}{progress_str}{elapsed_str}"
    
    # Build tool status lines
    lines = []
    for tool in ["Subfinder", "DNSX", "Uncover", "HTTPX", "Katana", "JS Hunter", "Nuclei"]:
        if tool in data_snap:
            lines.append(_render_tool_status(tool, data_snap[tool]))
    
    # Add totals line
    total_subs = data_snap.get("Subfinder", {}).get("subs", 0)
    total_live = data_snap.get("DNSX", {}).get("live", 0)
    total_tech = data_snap.get("HTTPX", {}).get("endpoints", 0)
    total_ep = data_snap.get("Katana", {}).get("crawled", 0)
    total_vulns = data_snap.get("Nuclei", {}).get("vulns", 0)
    
    totals_text = Text()
    totals_text.append("TOTAL: ", style="bold")
    totals_text.append(f"{total_subs} SUB | {total_live} LV | {total_tech} TECH | {total_ep} EP | {total_vulns} VN", style="cyan")
    
    lines.append(Text())  # blank
    lines.append(totals_text)
    
    # Create panel
    panel = Panel(
        *lines,
        title=title,
        border_style="cyan",
        box=ROUNDED,
        padding=(0, 1)
    )
    
    return panel

def _live_view_loop():
    """Background thread: render live view panel periodically"""
    while getattr(_live_thread, 'running', True):
        try:
            panel = _render_live_view_panel()
            with _stdout_lock:
                _console.print(panel)
            time.sleep(0.5)  # Update every 500ms
        except Exception as e:
            logging.error(f"Live view error: {e}")
            time.sleep(1)

def _start_live_view():
    """Start background live view rendering thread"""
    global _live_thread
    if _live_thread and _live_thread.is_alive():
        return
    
    _live_thread = threading.Thread(target=_live_view_loop, daemon=True)
    _live_thread.running = True
    _live_thread.start()

def _stop_live_view():
    """Stop background live view rendering thread"""
    global _live_thread
    if _live_thread:
        _live_thread.running = False
        _live_thread.join(timeout=2.0)
        _live_thread = None

def _terminal_cleanup():
    """Cleanup on exit"""
    _stop_live_view()
    _console.print("[dim]Hunt3r terminated[/dim]")

# Register cleanup handlers
atexit.register(_terminal_cleanup)

def _sigint_handler(signum, frame):
    """Handle CTRL+C"""
    _terminal_cleanup()
    sys.exit(130)

def _sigwinch_handler(signum, frame):
    """Handle terminal resize"""
    _console.file.flush()

signal.signal(signal.SIGINT, _sigint_handler)
signal.signal(signal.SIGWINCH, _sigwinch_handler)

# Backward compatibility exports
__all__ = [
    'ui_log', 'ui_update_status', 'ui_banner', 'ui_clear', 'ui_clear_and_banner',
    'ui_mission_header', 'ui_mission_footer', 'ui_scan_summary', 'ui_set_mission_meta',
    'ui_snapshot', 'Colors', 'ICONS', 'sanitize_input',
    'tool_started', 'tool_finished', 'tool_cached', 'tool_error', 'nuclei_update',
    '_live_view_data', '_live_view_lock', '_stdout_lock'
]
