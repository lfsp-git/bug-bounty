# 🧠 HUNT3R AI DNA: UNIVERSAL PROTOCOL

## 🎯 ESSENCE
Hunt3r é um orquestrador de recon autônomo focado em precisão e segurança para programas de Bug Bounty.

## KEY RULES
- Nunca usar shell=True em subprocessos; sempre passar listas e sanear entradas.
- Preferir flags de stealth e anti-flood por padrão (HTTPX/Nuclei).
- Não armazenar chaves no código; use .env.

## ARCHITECTURE
- UI (core/ui_manager) separada da lógica.
- ProOrchestrator delega execução a MissionRunner (refactor concluído).
- Backwards compatibility: start_mission suporta a API legada e a nova dict-based API.

## STATUS
- Refatoração do orchestrator: concluída (MissionRunner extraído).
- Static checks (pyright) passados após correções.
- Próximo: adicionar adaptadores para engines e testes unitários para MissionRunner.
