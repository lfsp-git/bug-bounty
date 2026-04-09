"""
HUNT3R v2.5 - UI Manager [UX/UI PREDADOR - EDITION]
"""

import os
import sys
import time
import re
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

def ui_log(module: str, message: str, color=Colors.RESET):
    timestamp = datetime.now().strftime('%H:%M:%S')
    icon = ICONS.get(module.upper(), ">>")
    
    # \r\033[K limpa a linha atual, resolvendo o problema de colisão do spinner
    print(f"\r\033[K[{timestamp}] {icon} {color}{module}: {message}{Colors.RESET}")
    
    # Grava no ficheiro de log sem os caracteres ANSI e sem os ícones
    logging.info(f"{module}: {sanitize_input(message)}")

def ui_update_status(step: str, detail: str, color=Colors.PRIMARY):
    icon = ICONS.get(step.upper(), "[*]")
    print(f"\r\033[K{color}{icon} {step} {detail}{Colors.RESET}")

def ui_clear():
    # Avoid invoking clear when TERM is not set (common in CI/testing)
    if os.getenv('TERM'):
        os.system('cls' if os.name == 'nt' else 'clear')

def ui_banner():
    b_art = (
        "  ::   .:   ...    ::::::.    :::.:::::::::::: .::.   :::::::..   \n"
        " ,;;   ;;,  ;;     ;;;`;;;;,  `;;;;;;;;;;;'''';'`';;, ;;;;``;;;;  \n"
        ",[[[,,,[[[ [['     [[[  [[[[[. '[[     [[        .n[[  [[[,/[[['  \n"
        "\"$$$\"\"\"$$$ $$      $$$  $$$ \"Y$c$$     $$       ``\"$$$.$$$$$$c    \n"
        " 888   \"88o88    .d888  888    Y88     88,      ,,o888\"888b \"88bo,\n"
        " MMM    YMM \"YmmMMMM\"\"  MMM     YM     MMM      YMMP\"  MMMM   \"W\" \n"
    )
    print(f"{Colors.PRIMARY}{b_art}{Colors.RESET}")
    print(f"    {Colors.DIM}v2.5 - PREDATOR TACTICAL VIEW{Colors.RESET}\n")

def ui_clear_and_banner():
    """Stop any active live view, clear screen, and show banner (used by mission header)."""
    # Ensure live view thread is stopped before clearing to avoid overlapping renders
    _stop_live_view()
    ui_clear()
    ui_banner()

# ---------------------------------------------------------------------------
# Live View System (Htop-style)
# ---------------------------------------------------------------------------
# Estado global do live view
_live_view_active = False
_live_view_thread = None
_live_view_data = {
    "Subfinder": {"status": "idle", "progress": 0, "subs": 0},
    "DNSX": {"status": "idle", "progress": 0, "live": 0},
    "Uncover": {"status": "idle", "progress": 0, "takeovers": 0},
    "HTTPX": {"status": "idle", "progress": 0, "endpoints": 0},
    "JS Hunter": {"status": "idle", "progress": 0, "secrets": 0},
    "Katana": {"status": "idle", "progress": 0, "crawled": 0},
    "Nuclei": {"status": "idle", "progress": 0, "vulns": 0},
}
_live_view_lock = threading.RLock()  # Re-entrant lock prevents deadlocks from nested acquire calls

def _start_live_view():
    """Inicia o live view em uma thread separada."""
    global _live_view_active, _live_view_thread
    _live_view_active = True
    _live_view_thread = threading.Thread(target=_live_view_loop, daemon=True)
    _live_view_thread.start()

def _stop_live_view():
    """Para o live view."""
    global _live_view_active
    _live_view_active = False
    if _live_view_thread:
        _live_view_thread.join(timeout=1)

def _live_view_loop():
    """Loop principal do live view."""
    while _live_view_active:
        _render_live_view()
        time.sleep(0.5)

_last_live_view_render = None
_live_view_update_interval = 2.0  # Update every 2 seconds to avoid flicker
_live_view_last_update = 0

def _render_live_view():
    """Renderiza o live view na tela (only when data changes or every 2 seconds)."""
    global _last_live_view_render, _live_view_last_update
    
    with _live_view_lock:
        # Create a hash of current data to detect changes
        current_render = str(_live_view_data)
        current_time = time.time()
        
        # Skip render if data hasn't changed and not enough time has passed
        if current_render == _last_live_view_render and (current_time - _live_view_last_update) < _live_view_update_interval:
            return
        
        _last_live_view_render = current_render
        _live_view_last_update = current_time
        
        # Save cursor position
        print("\033[s", end="")
        
        # Posiciona no topo da área do live view (linha 9, after banner)
        print("\033[9;1H", end="")
        
        # Cabeçalho do live view
        print(f"  {Colors.BOLD}LIVE VIEW - TOOL STATUS{Colors.RESET}")
        print(f"  {'─'*56}")
        
        # Exibe cada ferramenta
        for tool, data in _live_view_data.items():
            status_icon = "🟢" if data["status"] == "running" else "🟡" if data["status"] == "idle" else "🔴"
            progress_bar = "█" * int(data["progress"] * 20) + "░" * (20 - int(data["progress"] * 20))
            
            # Get the appropriate count field
            count = data.get('subs', data.get('live', data.get('endpoints', data.get('crawled', data.get('secrets', data.get('vulns', 0))))))
            
            print(f"  {status_icon} {tool:<12} [{progress_bar}] {data['status']:<10} | {count:<6}")
        
        # Linha de separação
        print(f"  {'─'*56}")
        
        # Stats gerais
        total_subs = _live_view_data["Subfinder"].get("subs", 0)
        total_live = _live_view_data["DNSX"].get("live", 0)
        total_endpoints = _live_view_data["HTTPX"].get("endpoints", 0)
        total_vulns = _live_view_data["Nuclei"].get("vulns", 0)
        
        print(f"  {Colors.INFO}TOTAL: {total_subs} subs | {total_live} live | {total_endpoints} endpoints | {total_vulns} vulns{Colors.RESET}")
        print(f"  {'─'*56}")
        
        # Restore cursor position
        print("\033[u", end="")

def ui_mission_header(handle: str, score: int = 0):
    global _MISSION_START_TIME
    _MISSION_START_TIME = datetime.now()

    ui_clear_and_banner()  # Limpa tela e mostra banner

    # Limpa o handle: *TEST-ESCALATIONS_VINTEDGO_COM -> TEST-ESCALATIONS.VINTEDGO.COM
    clean_handle = handle.replace('_', '.').replace('*', '').upper()

    print(f"\n\r\033[K  ┌{'─'*56}┐")
    print(f"\r\033[K  │  TARGET  {Colors.BOLD}{clean_handle:<46}{Colors.RESET}│")
    print(f"\r\033[K  │  SCORE   {Colors.SUCCESS if score >= 70 else Colors.WARNING if score >= 40 else Colors.DIM}{score:<46}{Colors.RESET}│")
    print(f"\r\033[K  └{'─'*56}┘\n")

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
    """Finaliza a missão, parando o live view e limpando a tela."""
    _stop_live_view()
    # Limpa a área do live view, mas mantém o último estado visível por um momento
    time.sleep(1)
    print("\033[2J\033[H", end="")  # Limpa a tela e move para o canto superior esquerdo

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
    except EOFError:
        return ''
    except Exception:
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
    from config.validators import validate_and_extract_domain
    
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
    except Exception:
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
