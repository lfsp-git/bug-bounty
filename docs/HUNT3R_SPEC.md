# 🛡️ HUNT3R: Technical Specification (current)

## 🔄 THE PIPELINE (PREDATOR CYCLE)
1. WATCHDOG: coleta wildcards (H1/BC/IT) em ciclos de 4–6h com cache de 12h.
2. DIFF ENGINE: compara descobertas com `recon/baselines/{handle}*` e só processa novos/alterados.
3. DUAL-SCAN:
   - Infra phase: Nuclei (tags: cve,takeover,misconfig for premium).
   - Endpoints phase: Katana crawler => tactical Nuclei (anti-tarpit rates).
4. JS HUNTER: extração passiva de secrets via regex em assets JS.

## 🧩 ARCHITECTURE NOTES (UPDATED)
- ProOrchestrator: coordenador leve (delegates mission execution to MissionRunner).
- MissionRunner: nova classe que encapsula o ciclo de uma missão (prepare, vuln phase, finalize).
- Engines (recon/engines.py): remain procedural; adapters planned next.
- UI (core/ui_manager.py): funções exportadas compatíveis com main.py (ui_main_menu, ui_platform_selection_menu, etc.).

## 📡 NOTIFICATION ROUTING
- Telegram: urgent (Critical/High/Medium, JS secrets, escalations).
- Discord: informational logs and watchdog cycles.

## 🗄️ DIRECTORY STRUCTURE
- `core/`: orchestration, AI client, notifier, UI, refactored orchestrator.
- `recon/`: engines, baselines, tool wrappers.
- `docs/`: project specs and operational prompts.

## STATUS
- Refactor: ProOrchestrator decoupled; MissionRunner extracted.
- Static checks: pyright passes after recent fixes.
- Backwards compatibility: ProOrchestrator.start_mission supports legacy calls.
