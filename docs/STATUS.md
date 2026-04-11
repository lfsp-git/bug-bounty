# Hunt3r — Status Operacional

## Checkpoint atual

- **Data**: 2026-04-11
- **Branch**: `main`
- **Commit**: `5f246ef`
- **Estado**: Totalmente operacional — watchdog 24/7 + scoring real + notificações corretas
- **Testes**: 364 aprovados, 11 subtestes, 0 falhas

## Commits recentes (mais relevantes)

| Commit | Descrição |
|--------|-----------|
| `5f246ef` | Fix: platform tagging por fonte + nomenclatura de relatórios |
| `97d6081` | Fix: score writeback + severidade de segredos JS + ciclo watchdog 1h |
| `00f2d1a` | Fix: output --clean (ANSI, noise, versão httpx) |
| `ed74494` | Improve: workflow --clean completo com health checks |
| `298aeb9` | Fix: _ensure_venv() no guard __main__ + fix teste pdf |
| `ed0af87` | Fix: validação token Censys curto + export PDF |
| `26d23a4` | Tests: suite abrangente para todos os módulos alterados |
| `84c8471` | Fix: Discord apenas estatísticas + remover Low/Info das notificações |
| `ecaddab` | Fix P1: guard templates nuclei + dedup JS + timeout adaptativo Katana |
| `61d1e17` | Fix: venv enforcement + rewrite bounty scorer + validação Censys |
| `57d8ddd` | Fix P0: import ML module-level + threshold AI validation |

## Arquitetura ativa

- **Superfícies unificadas**: `runner.py`, `intel.py`, `state.py`, `output.py`, `tools.py`
- **Watchdog**: ciclo 1-2h adaptativo + plataforma tagueada por alvo (h1/it/custom)
- **Scoring**: 4 sinais (wildcard 35% / breadth 25% / quality 25% / platform 15%)
- **AI Validation**: dispara para score ≥ 60 (score agora escrito de volta no target)
- **Notificações**: Telegram → vulns Medium/High/Critical; Discord → stats de scan + heartbeat
- **Relatórios**: `.md` por alvo com plataforma correta (HackerOne / Custom (alvos.txt) / etc.)
- **Scanner**: pipeline recon → tática → validação com contratos explícitos por fase
- **Filtro FP**: 7 camadas determinísticas + ML LightGBM
- **JS Hunter**: severidade por tipo de segredo (CRITICAL: AWS/private key/Stripe; HIGH: Google/JWT/Slack)
- **--clean**: purge → update tools → update deps → health → API keys → uncover sync → ML → testes
- **UI**: dashboard tático fullscreen (Rich Live)

## Limitações conhecidas

- APIs de plataforma (bbscope) requerem H1_USER/H1_TOKEN ou IT_TOKEN válidos
- Censys API usa token curto (ex: `Pu1KHr6r`) — não é UUID nem e-mail
- Modelo ML treinado com dados sintéticos — retraining com dados reais melhora precisão
- Terminais < 80x24 reduzem legibilidade do dashboard
- Uncover retorna 0 resultados se Shodan/Censys sem créditos de consulta

