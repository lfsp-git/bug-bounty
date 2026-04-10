"""
HUNT3R v1.0-EXCALIBUR - UI Manager [UX/UI PREDADOR - EDITION]
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
from typing import Any

# Importar colorama com fallback estruturado
from typing import Any
HAS_COLORAMA = False
Fore: Any = None
Style: Any = None
try:
    from colorama import Fore as _Fore, Style as _Style, init as colorama_init
    colorama_init(autoreset=True)
    Fore = _Fore
    Style = _Style
    HAS_COLORAMA = True
except ImportError:
    class AnsiFore:
        RED = ''; GREEN = ''; YELLOW = ''; CYAN = ''; MAGENTA = ''; WHITE = ''; BLACK = ''
    class AnsiStyle:
        RESET_ALL = ''; BRIGHT = ''; DIM = ''
    Fore = AnsiFore
    Style = AnsiStyle

# Logging APENAS EM ARQUIVO (Para não poluir a tela de caçada)
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

class Colors:
    PRIMARY = Fore.CYAN if HAS_COLORAMA else ""
    SECONDARY = Fore.MAGENTA if HAS_COLORAMA else ""
    SUCCESS = Fore.GREEN if HAS_COLORAMA else ""
    WARNING = Fore.YELLOW if HAS_COLORAMA else ""
    ERROR = Fore.RED if HAS_COLORAMA else ""
    INFO = Fore.WHITE if HAS_COLORAMA else ""
    DIM = Style.DIM if HAS_COLORAMA else ""
    BOLD = Style.BRIGHT if HAS_COLORAMA else ""
    RESET = Style.RESET_ALL if HAS_COLORAMA else ""

# ---------------------------------------------------------------------------
# Dicionário de Ícones para Hierarquia Visual
# ---------------------------------------------------------------------------
ICONS = {
    "WATCHDOG": "🚨",
    "PREDADOR": "🦖",
    "SUBFINDER": "🌐",
    "DNSX": "🌍",
    "HTTPX": "⚡",
    "KATANA": "🕷️",
    "JS HUNTER": "🔑",
    "NUCLEI": "☢️",
    "NUCLEI INFRA": "🏗️",
    "NUCLEI ENDP": "💉",
    "NUCLEI DEEP": "🕳️",
    "IA": "🧠",
    "ESCALATOR": "⛓️",
    "RESULTADO": "🏁",
    "SMART FILTER": "🧃",
    "UNCOVER": "👁️",
    "DIFF NOVO": "✨",
    "DIFF SECRETS": "🔥",
    "MODE": "⚙️",
    "ERR": "❌",
    "ABORTADO": "🛑",
    "ANOMALIA": "⚠️",
    "DICA": "💡",
    "RECON": "🔍",
    "EXTRACTION": "🗃️",
    "RECURSIVIDADE": "🔁",
    "DISK": "💾"
}

_MISSION_START_TIME = None

# ---------------------------------------------------------------------------
# Terminal Snapshot — rolling buffer + error capture
# ---------------------------------------------------------------------------
_SNAPSHOT_BUFFER: list = []          # rolling log of (timestamp, module, message)
_SNAPSHOT_MAX = 200                  # keep last N lines in memory
_SNAPSHOT_DIR = "logs/snapshots"

def _buffer_append(module: str, message: str):
    ts = datetime.now().strftime('%H:%M:%S')
    _SNAPSHOT_BUFFER.append(f"[{ts}] {module}: {sanitize_input(message)}")
    if len(_SNAPSHOT_BUFFER) > _SNAPSHOT_MAX:
        del _SNAPSHOT_BUFFER[0]

def ui_snapshot(label: str = "manual", context: str = ""):
    """Dump current terminal buffer to logs/snapshots/<ts>_<label>.log."""
    try:
        import platform
        os.makedirs(_SNAPSHOT_DIR, exist_ok=True)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        path = os.path.join(_SNAPSHOT_DIR, f"{ts}_{label}.log")
        with open(path, 'w', encoding='utf-8') as f:
            # Header
            f.write("# ═══════════════════════════════════════════════════\n")
            f.write("# Hunt3r Terminal Snapshot\n")
            f.write("# ═══════════════════════════════════════════════════\n")
            f.write(f"# Label    : {label}\n")
            f.write(f"# Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            if context:
                f.write(f"# Context  : {context}\n")
            
            # Mission state
            meta = _live_view_meta
            if meta.get("target"):
                f.write(f"# Target   : {meta['target']}\n")
            if meta.get("total"):
                f.write(f"# Progress : {meta.get('current',0)}/{meta['total']}\n")
            if _MISSION_START_TIME:
                elapsed = int((datetime.now() - _MISSION_START_TIME).total_seconds())
                f.write(f"# Elapsed  : {elapsed//60:02d}m{elapsed%60:02d}s\n")
            
            # Tool status
            f.write("# ─── Tool Status ──────────────────────────────────\n")
            for tool, data in _live_view_data.items():
                status = data.get("status", "?")
                count = data.get('subs', data.get('live', data.get('endpoints',
                        data.get('crawled', data.get('secrets', data.get('vulns', 0))))))
                f.write(f"#   {tool:<12} {status:<10} count={count}\n")
            
            # Environment (masked keys)
            f.write("# ─── Environment ──────────────────────────────────\n")
            keys_to_check = ["TERM", "H1_USER", "H1_TOKEN", "BC_TOKEN", "IT_TOKEN",
                             "TELEGRAM_BOT_TOKEN", "OPENROUTER_API_KEY", "SHODAN_API_KEY"]
            for k in keys_to_check:
                v = os.environ.get(k, "")
                if v:
                    masked = v[:4] + "****" if len(v) > 4 else "****"
                    f.write(f"#   {k}={masked}\n")
                else:
                    f.write(f"#   {k}=(not set)\n")
            
            f.write(f"# ─── Log Buffer ({len(_SNAPSHOT_BUFFER)} lines) ─────────────────────\n\n")
            f.write('\n'.join(_SNAPSHOT_BUFFER))
            f.write('\n')
        return path
    except OSError:
        return ""

def ui_log(module: str, message: str, color=Colors.RESET):
    timestamp = datetime.now().strftime('%H:%M:%S')
    icon = ICONS.get(module.upper(), ">>")
    
    # Acquire stdout lock so live view thread can't corrupt cursor during our write
    with _stdout_lock:
        # \r\033[K clears the current line (resolves spinner collision)
        print(f"\r\033[K[{timestamp}] {icon} {color}{module}: {message}{Colors.RESET}")
    
    # Buffer for snapshots + file log (ANSI-stripped)
    _buffer_append(module, message)
    logging.info(f"{module}: {sanitize_input(message)}")
    
    # Auto-snapshot on errors
    if module.upper() in ("ERR", "ENGINE_ERR", "ENGINE_WARN") or color == Colors.ERROR:
        ui_snapshot(label=f"error_{module.lower().replace(' ','_')}", context=message)

def ui_update_status(step: str, detail: str, color=Colors.PRIMARY):
    icon = ICONS.get(step.upper(), "[*]")
    # No newline: overwrite same line so spinner doesn't scroll the terminal
    with _stdout_lock:
        sys.stdout.write(f"\r\033[K{color}{icon} {step} {detail}{Colors.RESET}")
        sys.stdout.flush()

def ui_clear():
    # Avoid invoking clear when TERM is not set (common in CI/testing)
    if os.getenv('TERM'):
        os.system('cls' if os.name == 'nt' else 'clear')

def ui_banner():
    # 6 art lines (each ends with \n) + 1 version line = 7 lines exactly (_BANNER_LINES)
    b_art = (
        "  ::   .:   ...    ::::::.    :::.:::::::::::: .::.   :::::::..   \n"
        " ,;;   ;;,  ;;     ;;;`;;;;,  `;;;;;;;;;;;'''';'`';;, ;;;;``;;;;  \n"
        ",[[[,,,[[[ [['     [[[  [[[[[. '[[     [[        .n[[  [[[,/[[['  \n"
        "\"$$$\"\"\"$$$ $$      $$$  $$$ \"Y$c$$     $$       ``\"$$$.$$$$$$c    \n"
        " 888   \"88o88    .d888  888    Y88     88,      ,,o888\"888b \"88bo,\n"
        " MMM    YMM \"YmmMMMM\"\"  MMM     YM     MMM      YMMP\"  MMMM   \"W\" \n"
    )
    # print with end="" to suppress extra newline — b_art already has trailing \n per line
    sys.stdout.write(f"{Colors.PRIMARY}{b_art}{Colors.RESET}")
    sys.stdout.write(f"    {Colors.DIM}v1.0 - EXCALIBUR{Colors.RESET}\n")
    sys.stdout.flush()

def ui_clear_and_banner():
    """Stop any active live view, clear screen, and show banner (used by mission header)."""
    # Ensure live view thread is stopped before clearing to avoid overlapping renders
    _stop_live_view()
    ui_clear()
    ui_banner()

# ---------------------------------------------------------------------------
# Live View System (Htop-style)
# ---------------------------------------------------------------------------
_BANNER_LINES = 7    # 6 ASCII art lines + 1 version line (exact, no blanks)
_HEADER_BOX_LINES = 5  # top border + target + score + bottom border + 1 blank
_FIXED_TOP = _BANNER_LINES + _HEADER_BOX_LINES  # lines frozen at top of terminal
_LIVE_VIEW_LINES = 12  # lines rendered by live view block (header+sep+7tools+sep+total+sep)

# Estado global do live view
_live_view_active = False
_live_view_thread = None
_live_view_data = {
    "Subfinder": {"status": "idle", "progress": 0, "subs": 0,      "start_time": None, "eta": 0},
    "DNSX":      {"status": "idle", "progress": 0, "live": 0,      "start_time": None, "eta": 0},
    "Uncover":   {"status": "idle", "progress": 0, "takeovers": 0, "start_time": None, "eta": 0},
    "HTTPX":     {"status": "idle", "progress": 0, "endpoints": 0, "start_time": None, "eta": 0},
    "JS Hunter": {"status": "idle", "progress": 0, "secrets": 0,   "start_time": None, "eta": 0},
    "Katana":    {"status": "idle", "progress": 0, "crawled": 0,   "start_time": None, "eta": 0},
    "Nuclei":    {"status": "idle", "progress": 0, "vulns": 0,     "start_time": None, "eta": 0},
}
_live_view_meta = {"target": "", "current": 0, "total": 0}
_live_view_lock = threading.RLock()  # Re-entrant lock prevents deadlocks from nested acquire calls
_stdout_lock = threading.Lock()      # Serializes all stdout writes to prevent cursor corruption

def ui_set_mission_meta(target: str, current: int = 0, total: int = 0):
    """Update live view header with current target and progress indicators."""
    with _live_view_lock:
        _live_view_meta["target"] = target
        _live_view_meta["current"] = current
        _live_view_meta["total"] = total

def _get_terminal_rows() -> int:
    try:
        return os.get_terminal_size().lines
    except OSError:
        return 24

def _start_live_view():
    """Inicia o live view em uma thread separada, reservando área na base do terminal.
    
    Scroll region = rows (_FIXED_TOP+1) .. (rows-_LIVE_VIEW_LINES)
    Top _FIXED_TOP rows (banner + target box) are frozen.
    Bottom _LIVE_VIEW_LINES rows (live view) are frozen.
    """
    global _live_view_active, _live_view_thread
    rows = _get_terminal_rows()
    scroll_top = _FIXED_TOP + 1
    scroll_bottom = rows - _LIVE_VIEW_LINES
    # Guard: if terminal is too small, just use basic scroll
    if scroll_bottom <= scroll_top:
        scroll_top = 1
        scroll_bottom = rows - _LIVE_VIEW_LINES
    # Set scroll region (frozen top + frozen bottom)
    sys.stdout.write(f"\033[{scroll_top};{scroll_bottom}r")
    # Park cursor at start of scroll region so logs go there
    sys.stdout.write(f"\033[{scroll_top};1H")
    sys.stdout.flush()
    _live_view_active = True
    _live_view_thread = threading.Thread(target=_live_view_loop, daemon=True)
    _live_view_thread.start()

def _terminal_cleanup():
    """Full terminal restore: erase live view area, reset scroll region, show cursor."""
    if not sys.stdout.isatty():
        return
    try:
        rows = _get_terminal_rows()
        live_top = rows - _LIVE_VIEW_LINES + 1
        out = sys.stdout
        out.write("\033[r")               # reset scroll region to full screen
        out.write(f"\033[{live_top};1H")  # jump to start of live view area
        for _ in range(_LIVE_VIEW_LINES):
            out.write("\033[K\n")         # erase each live view line
        out.write(f"\033[{live_top};1H")  # park cursor at start of erased area
        out.write("\033[?25h")            # ensure cursor is visible
        out.flush()
    except OSError:
        pass

def _stop_live_view():
    """Para o live view e restaura o terminal por completo."""
    global _live_view_active
    _live_view_active = False
    if _live_view_thread:
        _live_view_thread.join(timeout=1)
    _terminal_cleanup()

# Register cleanup on normal exit and SIGINT (CTRL+C)
atexit.register(_terminal_cleanup)

def _sigint_handler(signum, frame):
    ui_snapshot(label="sigint", context="CTRL+C received")
    _terminal_cleanup()
    raise KeyboardInterrupt

signal.signal(signal.SIGINT, _sigint_handler)

def _live_view_loop():
    """Loop principal do live view."""
    while _live_view_active:
        _render_live_view()
        time.sleep(0.5)

_last_live_view_render = None
_live_view_update_interval = 1.0
_live_view_last_update = 0

def _render_live_view():
    """Renderiza o live view ancorado na base do terminal."""
    global _last_live_view_render, _live_view_last_update

    if not sys.stdout.isatty():
        return

    with _live_view_lock:
        current_render = str(_live_view_data) + str(_live_view_meta)
        current_time = time.time()

        if current_render == _last_live_view_render and (current_time - _live_view_last_update) < _live_view_update_interval:
            return

        _last_live_view_render = current_render
        _live_view_last_update = current_time

    # Skip render if main thread is printing — avoids cursor race condition
    if not _stdout_lock.acquire(blocking=False):
        return
    try:
        rows = _get_terminal_rows()
        top_of_view = rows - _LIVE_VIEW_LINES + 1  # first line of live view area

        # Build header info
        target = _live_view_meta.get("target", "")
        cur = _live_view_meta.get("current", 0)
        total = _live_view_meta.get("total", 0)

        elapsed_str = ""
        if _MISSION_START_TIME:
            secs = int((datetime.now() - _MISSION_START_TIME).total_seconds())
            m, s = divmod(secs, 60)
            elapsed_str = f"  ⏱ {m:02d}m{s:02d}s"

        progress_str = f"  [{cur}/{total}]" if total else ""
        target_str = f"  🎯 {target}" if target else ""

        out = sys.stdout
        # Jump to start of live view area (below scroll region)
        out.write(f"\033[{top_of_view};1H")

        out.write(f"\r\033[K  {Colors.BOLD}LIVE VIEW{target_str}{progress_str}{elapsed_str}{Colors.RESET}\n")
        out.write(f"\r\033[K  {'─'*56}\n")

        now = time.time()
        for tool, data in _live_view_data.items():
            status_icon = "🟢" if data["status"] == "running" else "🟡" if data["status"] == "idle" else "🔴"

            # Compute progress ratio from start_time + eta
            start_t = data.get("start_time")
            eta = data.get("eta", 0)
            if data["status"] == "running" and start_t and eta > 0:
                ratio = min(1.0, (now - start_t) / eta)
            else:
                ratio = 1.0 if data["status"] == "idle" and any(
                    data.get(k, 0) > 0 for k in ("subs", "live", "endpoints", "crawled", "secrets", "vulns", "takeovers")
                ) else 0.0

            filled = int(ratio * 20)
            empty = 20 - filled
            # Color: green < 65%, yellow 65-85%, red > 85%
            if data["status"] == "running":
                if ratio < 0.65:
                    bar_color = "\033[32m"   # green
                elif ratio < 0.85:
                    bar_color = "\033[33m"   # yellow
                else:
                    bar_color = "\033[31m"   # red
            else:
                bar_color = "\033[90m"       # dim grey for idle
            reset = "\033[0m"
            progress_bar = f"{bar_color}{'█' * filled}{reset}{'░' * empty}"

            count = data.get('subs', data.get('live', data.get('endpoints', data.get('crawled', data.get('secrets', data.get('vulns', 0))))))
            out.write(f"\r\033[K  {status_icon} {tool:<12} [{progress_bar}] {data['status']:<10} | {count:<6}\n")

        out.write(f"\r\033[K  {'─'*56}\n")

        total_subs = _live_view_data["Subfinder"].get("subs", 0)
        total_live = _live_view_data["DNSX"].get("live", 0)
        total_endpoints = _live_view_data["HTTPX"].get("endpoints", 0)
        total_vulns = _live_view_data["Nuclei"].get("vulns", 0)
        out.write(f"\r\033[K  {Colors.INFO}TOTAL: {total_subs} subs | {total_live} live | {total_endpoints} endpoints | {total_vulns} vulns{Colors.RESET}\n")
        out.write(f"\r\033[K  {'─'*56}\n")

        # Return cursor to bottom of scroll region so log output stays above live view
        scroll_bottom = rows - _LIVE_VIEW_LINES
        out.write(f"\033[{scroll_bottom};1H")
        out.flush()
    finally:
        _stdout_lock.release()

def ui_mission_header(handle: str, score: int = 0):
    global _MISSION_START_TIME
    _MISSION_START_TIME = datetime.now()

    ui_clear_and_banner()  # Limpa tela e mostra banner (rows 1.._BANNER_LINES)

    # Limpa o handle: *TEST-ESCALATIONS_VINTEDGO_COM -> TEST-ESCALATIONS.VINTEDGO.COM
    clean_handle = handle.replace('_', '.').replace('*', '').upper()

    # Print exactly _HEADER_BOX_LINES = 5 lines so scroll region aligns correctly
    score_color = Colors.SUCCESS if score >= 70 else Colors.WARNING if score >= 40 else Colors.DIM
    sys.stdout.write(f"\r\033[K  ┌{'─'*56}┐\n")
    sys.stdout.write(f"\r\033[K  │  TARGET  {Colors.BOLD}{clean_handle:<46}{Colors.RESET}│\n")
    sys.stdout.write(f"\r\033[K  │  SCORE   {score_color}{score:<46}{Colors.RESET}│\n")
    sys.stdout.write(f"\r\033[K  └{'─'*56}┘\n")
    sys.stdout.write(f"\r\033[K\n")  # blank separator line
    sys.stdout.flush()

    # Inicia o live view apenas se o terminal estiver configurado
    if os.getenv('TERM') and sys.stdout.isatty():
        _start_live_view()

def ui_scan_summary(results: dict):
    global _MISSION_START_TIME
    duration_str = ""
    
    if _MISSION_START_TIME:
        elapsed = datetime.now() - _MISSION_START_TIME
        mins, secs = divmod(int(elapsed.total_seconds()), 60)
        duration_str = f" (⏱️ {mins:02d}m {secs:02d}s)"

    # Limpeza do nome novamente para o sumário
    clean_handle = results.get('target', 'UNKNOWN').replace('_', '.').replace('*', '').upper()

    # Hold stdout lock so no spinner thread can corrupt our output
    with _stdout_lock:
        print(f"\n\r\033[K{Colors.SECONDARY}{'='*70}{Colors.RESET}")
        print(f"\r\033[K{Colors.BOLD}                     RESUMO DA CAÇADA{duration_str}{Colors.RESET}")
        print(f"\r\033[K{Colors.SECONDARY}{'='*70}{Colors.RESET}")
        
        print(f"\r\033[K  🎯 Alvo: {clean_handle}")
        print(f"\r\033[K  📊 Score: {results.get('score', 0)}%")
        print(f"\r\033[K  🌐 Subs Vivos: {results.get('alive', 0)} / {results.get('subdomains', 0)}")
        print(f"\r\033[K  🕷️ Endpoints: {results.get('endpoints', 0)}")
        
        if 'js_secret_lines' in results:
            print(f"\r\033[K  🔑 JS Secrets: {results['js_secret_lines']}")
            
        vulns = results.get('vulns', 0)
        v_color = Colors.ERROR if vulns > 0 else Colors.SUCCESS
        v_text = f"{vulns}" if vulns > 0 else "0 (Silêncio no rádio)"
        print(f"\r\033[K  ☢️ Vulns: {v_color}{v_text}{Colors.RESET}")
        
        print(f"\r\033[K{Colors.SECONDARY}{'='*70}{Colors.RESET}\n")

def ui_mission_footer():
    """Finaliza a missão, parando o live view e restaurando o terminal."""
    _stop_live_view()
    # Reset scroll region fully so subsequent output (summary, enter prompt) renders normally
    if sys.stdout.isatty():
        sys.stdout.write("\033[r\033[?25h")
        sys.stdout.flush()

def ui_ranking_board(top_targets: list):
    print(f"\n\r\033[K  {Colors.BOLD}RANKING DE ALVOS (TOP {len(top_targets)}){Colors.RESET}")
    print(f"\r\033[K  {'─'*60}")
    for idx, t in enumerate(top_targets, 1):
        score = t.get('score', 0)
        bounty = t.get('bounty', False)
        handle = t.get('original_handle', t.get('handle', '')).replace('*', '')
        
        s_color = Colors.SUCCESS if score >= 70 else Colors.WARNING if score >= 40 else Colors.DIM
        b_raw = "[$ BBP]" if bounty else "[VDP]"
        b_color = Colors.SUCCESS if bounty else Colors.INFO
        
        hot = t.get('hot_score', 0)
        has_hot = 'hot_score' in t
        
        if has_hot:
            if hot >= 80: hot_badge, hot_c = "HOT ", Colors.ERROR
            elif hot >= 60: hot_badge, hot_c = "WARM", Colors.WARNING
            elif hot > 0: hot_badge, hot_c = "COOL", Colors.DIM
            else: hot_badge, hot_c = "    ", Colors.DIM
            print(f"\r\033[K  [{idx:<2}] {b_color}{b_raw:<10}{Colors.RESET} {hot_c}{hot_badge:<4}{Colors.RESET} {s_color}{score:<6}{Colors.RESET} {handle}")
        else:
            print(f"\r\033[K  [{idx:<2}] {b_color}{b_raw:<10}{Colors.RESET} {s_color}{score:<6}{Colors.RESET} {handle}")
    print()

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
    """Present a list of platform names and return the selected platform name (lowercased)."""
    if not platforms:
        return ''
    print("\n  Plataformas disponíveis:")
    for i, p in enumerate(platforms, 1):
        name = p.get('name', str(p))
        print(f"   [{i}] {name}")
    try:
        sel = int(input(f"  Selecione (1-{len(platforms)}): ").strip())
    except (EOFError, ValueError, KeyboardInterrupt):
        return ''
    if 1 <= sel <= len(platforms):
        return platforms[sel-1].get('name')
    return ''

def ui_target_selection_list(ranked: list):
    """Prints ranked targets succinctly for user selection."""
    if not ranked: print("  (Nenhum alvo)"); return
    for i, t in enumerate(ranked, 1):
        handle = t.get('handle', 'unknown')
        score = t.get('score', 0)
        print(f"  [{i}] {handle} (score: {score})")

def ui_manual_target_input() -> dict:
    """Prompt user for a manual target and return a dict suitable for orch.start_mission."""
    from core.config import validate_and_extract_domain
    
    try:
        dom = input("  Dominio (ex: example.com): ").strip()
        if not dom: return {}
        
        # Validate domain input
        clean_domain = validate_and_extract_domain(dom)
        if not clean_domain:
            print(f"  {Colors.ERROR}Dominio invalido. Use formato: example.com ou https://example.com{Colors.RESET}")
            return {}
        
        handle = clean_domain.replace('.', '_').replace('-', '_')
        return {'domains': [clean_domain], 'handle': handle, 'score': 30}
    except Exception as e:
        logging.error(f"Manual target input error: {e}")
        return {}

def ui_custom_targets_list(targets: list) -> dict:
    """Show custom targets and return selected dict."""
    if not targets: return {}
    for i, t in enumerate(targets, 1):
        print(f"  [{i}] {t.get('domain')}")
    try:
        sel = int(input(f"  Selecione (1-{len(targets)}): ").strip())
        if 1 <= sel <= len(targets):
            return targets[sel-1]
    except (ValueError, EOFError, KeyboardInterrupt):
        pass
    return {}

def ui_main_menu() -> str:
    ui_clear()
    ui_banner()
    print(f"  {Colors.BOLD}MENU PRINCIPAL{Colors.RESET}")
    print(f"  {'─'*40}")
    print(f"  {Colors.SECONDARY}[1]{Colors.RESET} {Colors.INFO}Executar Watchdog (Recon Contínuo){Colors.RESET}")
    print(f"  {Colors.SECONDARY}[2]{Colors.RESET} {Colors.INFO}Executar Scan Unico (Alvo Especifico){Colors.RESET}")
    print(f"  {Colors.SECONDARY}[3]{Colors.RESET} {Colors.INFO}Trocar Modelo de IA{Colors.RESET}")
    print(f"  {Colors.SECONDARY}[0]{Colors.RESET} {Colors.INFO}Sair{Colors.RESET}")
    print(f"  {'─'*40}")
    try:
        return input(f"  {Colors.BOLD}Escolha uma opcao: {Colors.RESET}").strip()
    except EOFError:
        # Non-interactive environment: return empty string to allow graceful exit
        return ""
