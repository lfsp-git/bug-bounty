# 🧠 HUNT3R AI CONTEXT (DNA)

## 🎯 PERFIL
- Orquestrador de Recon Contínuo (H1, BC, IT).
- Foco: Bug Bounty lucrativo e automação tática.

## 🛡️ REGRAS DE OURO (NÃO NEGOCIÁVEIS)
1. **NÃO EXPLIQUE O BÁSICO:** O operador é sênior. Vá direto ao código.
2. **SECURITY FIRST:** Proibido usar `shell=True`. Use listas e `shlex`.
3. **STEALTH MODE:** Todo scan (httpx/nuclei) deve usar User-Agents aleatórios.
4. **ANTI-FLOOD:** Sempre usar `-wd` no dnsx para matar wildcards de 10k+ subdomínios.
5. **UI MANAGER:** Interações de tela devem usar a classe `Colors` e `ui_log`.

## 🚧 ESTADO ATUAL
- Phase 1 (Security) concluída pelo Haiku.
- Pendente: Refatoração de funções longas no `orchestrator.py` (Cuidado: Não quebre o spinner de progresso!).