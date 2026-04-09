# 🛡️ HUNT3R-v1.0: SPECIFICATION & ROADMAP

## 🎯 Objetivo
Sniper de infraestrutura para Bug Bounty (H1, BC, IT). Precisão > Velocidade.

## 🏗️ Arquitetura Atual (v1.0-EXCALIBUR)
1. **Watchdog 24/7:** Ciclos paralelos de H1/BC/IT. Cache de wildcards de 12h para evitar timeouts.
2. **Dual-Scan Nuclei:** Fase 1 (Infra - 300 rps) | Fase 2 (Endpoints - 50 rps + Anti-Tarpit).
3. **JS Hunter:** Extração passiva de segredos em arquivos .js via regex.
4. **Notifier Routing:** Separação tática de ruído (Telegram vs Discord).

## 🚀 Épicos de Blindagem (IMEDIATO)
- [ ] **Hardening VPS:** Desativar senhas SSH, configurar Fail2Ban e UFW.
- [ ] **Sanitização de Código:** Remover todos os `shell=True` remanescentes em `updater.py` e `template_manager.py`.
- [ ] **Stealth Mode:** Implementar rotação de User-Agent real em todos os comandos do HTTPX e Nuclei.
- [ ] **Git Cleanup:** Remover permanentemente o histórico do `.env` do repositório.

## 🚧 Status das Integrações
- **HackerOne:** Full (API Key).
- **BugCrowd:** Ativo (bbscope via Token).
- **Intigrity:** Ativo (bbscope via Token).
- **Portfolio/OpenClaw:** Pausado/Inativo.