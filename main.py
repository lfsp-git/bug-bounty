#!/usr/bin/env python3
"""HUNT3R v2.2 - State Machine UI"""
import sys
import os
import argparse
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.ui_manager import ui_banner, ui_clear, ui_main_menu, ui_log, Colors
from core.ai_client import AIClient
from core.intelligence import IntelMiner
from core.orchestrator import ProOrchestrator
from core.updater import ToolUpdater
from core.constants import AUTO_UPDATE_ON_START
from recon.platforms import PlatformManager, load_custom_targets

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)


def _load_env():
    """Load environment variables from .env file safely."""
    env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    if os.path.exists(env_file):
        try:
            with open(env_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if '=' not in line:
                        continue
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.replace('\r', '').strip().strip('"').strip("'")
                    os.environ.setdefault(key, value)
        except Exception as e:
            logger.error(f"Failed to load .env: {e}")


def init_seq():
    """Initialize tool updates."""
    ui_log("SYSTEM", "Verificando ferramentas...", Colors.PRIMARY)
    try:
        u = ToolUpdater()
        u.update_all()
        ui_log("SYSTEM", "Pronto.", Colors.SUCCESS)
    except Exception as e:
        logger.error(f"Tool update failed: {e}")
        ui_log("UPDATER ERR", str(e), Colors.ERROR)


def init_ai():
    """Setup da IA: verifica se tem modelo selecionado ou pede pro usuario."""
    from core.ai_client import select_model_interactive
    client = AIClient()
    if not client.api_key:
        ui_log("AI", "OPENROUTER_API_KEY nao configurada. IA desativada.", Colors.WARNING)
        return client
    if client.selected_model:
        ui_log("AI", f"Modelo carregado: {client.selected_model}", Colors.SUCCESS)
        return client
    ui_log("AI", "Nenhum modelo selecionado.", Colors.WARNING)
    if select_model_interactive(client):
        ui_log("AI", f"Modelo salvo: {client.selected_model}", Colors.SUCCESS)
    else:
        ui_log("AI", "IA ficara offline ate selecionar um modelo.", Colors.DIM)
    return client

def state_platforms(orch):
    ui_clear(); ui_banner()

    pm = PlatformManager()
    avail = pm.get_available_platforms()
    if not avail:
        ui_log("AVISO", "Sem plataformas no YAML.", Colors.WARNING)
        input(f"\n  {Colors.DIM}[Enter]{Colors.RESET} "); return

    from core.ui_manager import ui_platform_selection_menu, ui_target_selection_list
    sel = ui_platform_selection_menu(avail)
    if not sel: return

    # CACHED FIRST: avoid expensive H1 API fetch if cache < 1h
    cached = orch.intel.load_cached_programs()
    if cached:
        ui_log("H1 CACHE", f"{len(cached)} programas carregados do cache.", Colors.SUCCESS)
        ranked = cached
    else:
        ui_log("H1 API", "Cache expirado. Buscando programas...", Colors.WARNING)
        progs = pm.get_all_programs_from_platform(sel)
        if not progs:
            input(f"\n  {Colors.DIM}[Enter]{Colors.RESET} "); return
        ranked = orch.intel.rank_programs_for_list(progs)

    # UX PERFEITA: A tabela desce suavemente logo abaixo do log de sucesso
    print()
    ui_target_selection_list(ranked)

    try:
        idx = int(input(f"  {Colors.WARNING}ID do Alvo:{Colors.RESET} ")) - 1
        if 0 <= idx < len(ranked):
            t = ranked[idx]
            ui_clear(); ui_banner()
            orch.start_mission(t['handle'], t['domains'], f"recon/db/{t['handle']}", t['score'])
            input(f"\n  {Colors.DIM}[Enter para voltar]{Colors.RESET} ")
    except (ValueError, KeyboardInterrupt): pass

def state_manual(orch):
    ui_clear(); ui_banner()
    from core.ui_manager import ui_manual_target_input
    t = ui_manual_target_input()
    if not t: return
    if input(f"\n  {Colors.WARNING}Scan {t['domains'][0]}? (s/n): {Colors.RESET}").lower() == 's':
        orch.start_mission(t['handle'], t['domains'], f"recon/db/{t['handle']}", t['score'])
        input(f"\n  {Colors.DIM}[Enter para voltar]{Colors.RESET} ")

def state_list(orch):
    ui_clear(); ui_banner()
    tgts = load_custom_targets()
    if not tgts:
        ui_log("AVISO", "alvos.txt vazio.", Colors.WARNING)
        input(f"\n  {Colors.DIM}[Enter]{Colors.RESET} "); return
    from core.ui_manager import ui_custom_targets_list
    sel = ui_custom_targets_list(tgts)
    if not sel: return
    if input(f"\n  {Colors.WARNING}Scan {sel['domains'][0]}? (s/n): {Colors.RESET}").lower() == 's':
        orch.start_mission(sel['handle'], sel['domains'], f"recon/db/{sel['handle']}", sel['score'])
        input(f"\n  {Colors.DIM}[Enter para voltar]{Colors.RESET} ")

def main():
    _load_env()

    # --watchdog CLI argument
    parser = argparse.ArgumentParser(description="HUNT3R - Autonomous Recon")
    parser.add_argument("--watchdog", action="store_true", help="Modo contínuo: Top 15 Wildcards, 24/7")
    args = parser.parse_args()

    if args.watchdog:
        ui_clear()
        from core.watchdog import run_watchdog
        run_watchdog()
        return

    # TELA INICIAL: Renderiza o estado Menu
    ui_clear(); ui_banner()
    init_seq()
    ai = init_ai()

    if not ai.api_key or not ai.selected_model:
        ui_log("AVISO", "IA indisponivel. Analise de vulnerabilidades sera pulada.", Colors.DIM)
    orch = ProOrchestrator(IntelMiner(ai))

    while True:
        ui_clear(); ui_banner()
        ch = ui_main_menu()

        if ch == 0:
            ui_log("SAINDO", "Ate logo.", Colors.WARNING); break
        elif ch == 1: state_platforms(orch)
        elif ch == 2: state_manual(orch)
        elif ch == 3: state_list(orch)
        else:
            ui_log("ERRO", "Invalido.", Colors.ERROR)
            input(f"\n  {Colors.DIM}[Enter]{Colors.RESET} ")

if __name__ == "__main__": main()
