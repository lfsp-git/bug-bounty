#!/usr/bin/env python3
"""HUNT3R v1.0-EXCALIBUR — Autonomous Bug Bounty Hunter"""
import sys
import os
import argparse
import glob
import json
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.ui import ui_banner, ui_clear, ui_main_menu, ui_log, Colors
from core.ui import ui_platform_selection_menu, ui_target_selection_list
from core.ui import ui_manual_target_input, ui_custom_targets_list
from core.ai import AIClient, IntelMiner, select_model_interactive
from core.runner import ProOrchestrator
from core.updater import ToolUpdater
from core.config import AUTO_UPDATE_ON_START
from recon.platforms import PlatformManager, load_custom_targets

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)


def _load_env() -> None:
    """Load .env file and validate required tokens."""
    env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(env_file):
        try:
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    os.environ.setdefault(
                        key.strip(),
                        value.replace("\r", "").strip().strip('"').strip("'"),
                    )
        except OSError as e:
            logger.error(f"Failed to load .env: {e}")

    missing = [t for t in ("H1_TOKEN", "BC_TOKEN", "IT_TOKEN") if not os.getenv(t)]
    if missing:
        logger.warning(f"Missing platform tokens: {', '.join(missing)}")
    if os.getenv("H1_TOKEN") and not os.getenv("H1_USER"):
        logger.warning("H1_TOKEN set but H1_USER missing")

    # Detect placeholder values that were never replaced
    placeholder_markers = ("your_", "xxxxx", "changeme", "token_here", "key_here")
    for key in ("H1_TOKEN", "BC_TOKEN", "IT_TOKEN", "OPENROUTER_API_KEY", "TELEGRAM_BOT_TOKEN"):
        val = os.getenv(key, "")
        if val and any(m in val.lower() for m in placeholder_markers):
            logger.warning(f"Env var {key} looks like a placeholder — did you fill in .env?")


def init_seq() -> None:
    ui_log("SYSTEM", "Verificando ferramentas...", Colors.PRIMARY)
    try:
        ToolUpdater().update_all()
        ui_log("SYSTEM", "Pronto.", Colors.SUCCESS)
    except KeyboardInterrupt:
        ui_log("SYSTEM", "Verificacao interrompida. Continuando...", Colors.WARNING)
    except Exception as e:
        logger.error(f"Tool update failed: {e}")
        ui_log("UPDATER ERR", str(e), Colors.ERROR)


def init_ai() -> AIClient:
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


def state_platforms(orch: ProOrchestrator) -> None:
    ui_clear()
    ui_banner()
    pm = PlatformManager()
    avail = pm.get_available_platforms()
    if not avail:
        ui_log("AVISO", "Sem plataformas no YAML.", Colors.WARNING)
        try:
            input(f"\n  {Colors.DIM}[Enter]{Colors.RESET} ")
        except EOFError:
            pass
        return

    sel = ui_platform_selection_menu(avail)
    if not sel:
        return

    orch._ensure_intel()
    cached = orch.intel.load_cached_programs()  # type: ignore[union-attr]
    if cached:
        ui_log("H1 CACHE", f"{len(cached)} programas carregados do cache.", Colors.SUCCESS)
        ranked = cached
    else:
        ui_log("H1 API", "Cache expirado. Buscando programas...", Colors.WARNING)
        progs = pm.get_all_programs_from_platform(sel)
        if not progs:
            try:
                input(f"\n  {Colors.DIM}[Enter]{Colors.RESET} ")
            except EOFError:
                pass
            return
        ranked = orch.intel.rank_programs_for_list(progs)  # type: ignore[union-attr]

    print()
    ui_target_selection_list(ranked)
    try:
        idx = int(input(f"  {Colors.WARNING}ID do Alvo:{Colors.RESET} ")) - 1
        if 0 <= idx < len(ranked):
            t = ranked[idx]
            ui_clear()
            ui_banner()
            orch.start_mission(t["handle"], t["domains"], f"recon/db/{t['handle']}", t["score"])
            try:
                input(f"\n  {Colors.DIM}[Enter para voltar]{Colors.RESET} ")
            except EOFError:
                pass
    except (ValueError, KeyboardInterrupt):
        pass


def state_manual(orch: ProOrchestrator) -> None:
    ui_clear()
    ui_banner()
    t = ui_manual_target_input()
    if not t:
        return
    try:
        ans = input(f"\n  {Colors.WARNING}Scan {t['domains'][0]}? (s/n): {Colors.RESET}")
    except EOFError:
        ans = ""
    if ans.lower() == "s":
        try:
            orch.start_mission(t["handle"], t["domains"], f"recon/db/{t['handle']}", t["score"])
        except KeyboardInterrupt:
            ui_log("SCAN", "Scan cancelado pelo usuario.", Colors.WARNING)
        try:
            input(f"\n  {Colors.DIM}[Enter para voltar]{Colors.RESET} ")
        except (EOFError, KeyboardInterrupt):
            pass


def state_list(orch: ProOrchestrator) -> None:
    ui_clear()
    ui_banner()
    tgts = load_custom_targets()
    if not tgts:
        ui_log("AVISO", "alvos.txt vazio.", Colors.WARNING)
        try:
            input(f"\n  {Colors.DIM}[Enter]{Colors.RESET} ")
        except EOFError:
            pass
        return
    sel = ui_custom_targets_list(tgts)
    if not sel:
        return
    try:
        ans = input(f"\n  {Colors.WARNING}Scan {sel['domains'][0]}? (s/n): {Colors.RESET}")
    except EOFError:
        ans = ""
    if ans.lower() == "s":
        try:
            orch.start_mission(sel["handle"], sel["domains"], f"recon/db/{sel['handle']}", sel["score"])
        except KeyboardInterrupt:
            ui_log("SCAN", "Scan cancelado pelo usuario.", Colors.WARNING)
        try:
            input(f"\n  {Colors.DIM}[Enter para voltar]{Colors.RESET} ")
        except (EOFError, KeyboardInterrupt):
            pass


def _load_all_findings() -> list:
    """Load all JSONL findings from recon/baselines/."""
    findings = []
    for path in glob.glob("recon/baselines/*_findings.jsonl"):
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            findings.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        except OSError:
            pass
    return findings


def main() -> None:
    _load_env()

    parser = argparse.ArgumentParser(description="HUNT3R v1.0-EXCALIBUR — Autonomous Bug Bounty Hunter")
    parser.add_argument("--watchdog", action="store_true", help="24/7 autonomous watchdog mode")
    parser.add_argument("--dry-run", action="store_true", help="Preview targets without executing tools")
    parser.add_argument("--resume", type=str, metavar="MISSION_ID", help="Resume from checkpoint")
    parser.add_argument("--export", type=str, choices=["csv", "xlsx", "xml"], help="Export all findings")
    args = parser.parse_args()

    if args.watchdog:
        ui_clear()
        from core.watchdog import run_watchdog
        run_watchdog()
        return

    if args.dry_run:
        ui_clear()
        ui_banner()
        ui_log("DRY-RUN", "Preview mode — no tools will execute", Colors.WARNING)
        from core.output import run_dry_run
        run_dry_run()
        return

    if args.resume:
        ui_clear()
        ui_banner()
        ui_log("RESUME", f"Resuming: {args.resume}", Colors.WARNING)
        from core.state import resume_mission
        resume_mission(args.resume)
        return

    if args.export:
        ui_clear()
        ui_banner()
        ui_log("EXPORT", f"Exporting as {args.export.upper()}...", Colors.WARNING)
        from core.output import ExportFormatter
        findings = _load_all_findings()
        if not findings:
            ui_log("EXPORT", "No findings in recon/baselines/. Run a scan first.", Colors.WARNING)
        else:
            path = ExportFormatter().export(findings, args.export)
            ui_log("EXPORT", f"Exported {len(findings)} findings → {path}", Colors.SUCCESS)
        return

    # Interactive menu
    ui_clear()
    ui_banner()
    init_seq()
    ai = init_ai()

    if not ai.api_key or not ai.selected_model:
        ui_log("AVISO", "IA indisponivel. Validacao de vulnerabilidades sera pulada.", Colors.DIM)

    orch = ProOrchestrator(IntelMiner(ai))

    while True:
        try:
            ui_clear()
            ui_banner()
            ch = ui_main_menu()
            if not ch:
                ui_log("SAINDO", "Sem entrada. Encerrando.", Colors.WARNING)
                break
            try:
                choice = int(ch)
            except ValueError:
                choice = -1

            if choice == 0:
                ui_log("SAINDO", "Ate logo.", Colors.WARNING)
                break
            elif choice == 1:
                state_platforms(orch)
            elif choice == 2:
                state_manual(orch)
            elif choice == 3:
                state_list(orch)
            else:
                ui_log("ERRO", "Opcao invalida.", Colors.ERROR)
                try:
                    input(f"\n  {Colors.DIM}[Enter]{Colors.RESET} ")
                except EOFError:
                    pass
        except KeyboardInterrupt:
            print()  # newline after ^C
            continue  # back to menu


if __name__ == "__main__":
    main()
