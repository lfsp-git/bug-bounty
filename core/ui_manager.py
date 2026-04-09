"""
HUNT3R v2.4 - UI Manager [UX/UI PREDADOR - EDITION]
"""

import os
os.makedirs("logs", exist_ok=True) # Garante que a pasta existe

import logging
import sys
import re
from datetime import datetime

# Importar colorama com fallback estruturado
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    class Fore:
        RED = ''; GREEN = ''; YELLOW = ''; CYAN = ''; MAGENTA = ''; WHITE = ''; BLACK = ''
    class Style:
        RESET_ALL = ''; BRIGHT = ''; DIM = ''

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

def ui_mission_header(handle: str, score: int = 0):
    global _MISSION_START_TIME
    _MISSION_START_TIME = datetime.now()
    
    ui_clear_and_banner() # Chama o novo banner aqui

    # Limpa o handle: *TEST-ESCALATIONS_VINTEDGO_COM -> TEST-ESCALATIONS.VINTEDGO.COM
    clean_handle = handle.replace('_', '.').replace('*', '').upper()
    
    print(f"\n\r\033[K  ┌{'─'*56}┐")
    print(f"\r\033[K  │  TARGET  {Colors.BOLD}{clean_handle:<46}{Colors.RESET}│")
    
    score_c = Colors.SUCCESS if score >= 70 else Colors.WARNING if score >= 40 else Colors.DIM
    rank = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "STANDARD"
    score_str = f"{score}% - {rank}"
    
    print(f"\r\033[K  │  SCORE   {score_c}{score_str:<46}{Colors.RESET}│")
    print(f"\r\033[K  └{'─'*56}┘\n")

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
    return input(f"\r\033[K  {Colors.BOLD}Selecione o modelo (1-{len(models)}): {Colors.RESET}").strip()

# ---------------------------------------------------------------------------
# CLI Menu & Utilities (Reintegrados para o main.py)
# ---------------------------------------------------------------------------

def ui_clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def ui_clear_and_banner():
    """Limpa a tela e exibe o banner principal."""
    print("\033[2J\033[H", end="")
    b_art = (
        "  ::   .:   ...    ::::::.    :::.:::::::::::: .::.   :::::::..   \n"
        " ,;;   ;;,  ;;     ;;;`;;;;,  `;;;;;;;;;;;'''';'`';;, ;;;;``;;;;  \n"
        ",[[[,,,[[[ [['     [[[  [[[[[. '[[     [[        .n[[  [[[,/[[['  \n"
        "\"$$$\"\"\"$$$ $$      $$$  $$$ \"Y$c$$     $$       ``\"$$$.$$$$$$c    \n"
        " 888   \"88o88    .d888  888    Y88     88,      ,,o888\"888b \"88bo,\n"
        " MMM    YMM \"YmmMMMM\"\"  MMM     YM     MMM      YMMP\"  MMMM   \"W\" \n"
    )
    print(f"{Colors.PRIMARY}{b_art}{Colors.RESET}")
    print(f"    {Colors.DIM}v2.5 - PREDATOR EDITION{Colors.RESET}\n")


def ui_main_menu() -> str:
    ui_clear_and_banner()
    print(f"  {Colors.BOLD}MENU PRINCIPAL{Colors.RESET}")
    print(f"  {'─'*40}")
    print(f"  {Colors.SECONDARY}[1]{Colors.RESET} {Colors.INFO}Executar Watchdog (Recon Contínuo){Colors.RESET}")
    print(f"  {Colors.SECONDARY}[2]{Colors.RESET} {Colors.INFO}Executar Scan Unico (Alvo Especifico){Colors.RESET}")
    print(f"  {Colors.SECONDARY}[3]{Colors.RESET} {Colors.INFO}Trocar Modelo de IA{Colors.RESET}")
    print(f"  {Colors.SECONDARY}[0]{Colors.RESET} {Colors.INFO}Sair{Colors.RESET}")
    print(f"  {'─'*40}")
    return input(f"  {Colors.BOLD}Escolha uma opcao: {Colors.RESET}").strip()

def ui_banner_menu():
    """Banner padrão para os menus"""
    b_art = (
        "  ::   .:   ...    ::::::.    :::.:::::::::::: .::.   :::::::..   \n"
        " ,;;   ;;,  ;;     ;;;`;;;;,  `;;;;;;;;;;;'''';'`';;, ;;;;``;;;;  \n"
        ",[[[,,,[[[ [['     [[[  [[[[[. '[[     [[        .n[[  [[[,/[[['  \n"
        "\"$$$\"\"\"$$$ $$      $$$  $$$ \"Y$c$$     $$       ``\"$$$.$$$$$$c    \n"
        " 888   \"88o88    .d888  888    Y88     88,      ,,o888\"888b \"88bo,\n"
        " MMM    YMM \"YmmMMMM\"\"  MMM     YM     MMM      YMMP\"  MMMM   \"W\" \n"
    )
    print(f"{Colors.PRIMARY}{b_art}{Colors.RESET}")
    print(f"    {Colors.DIM}v2.5 - PREDATOR EDITION{Colors.RESET}\n")

# ---------------------------------------------------------------------------
# CLI Menu & Utilities (Reintegrados para o main.py)
# ---------------------------------------------------------------------------

def ui_clear():
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
    return input(f"  {Colors.BOLD}Escolha uma opcao: {Colors.RESET}").strip()
