# Hunt3r — Status Operacional

## Checkpoint atual

- **Data**: 2026-04-12
- **Branch**: `main`
- **Estado**: Totalmente operacional — watchdog 24/7 + pipeline OVERLORD completo
- **Testes**: 382 aprovados, 11 subtestes, 0 falhas

## Commits recentes (mais relevantes)

| Commit | Descrição |
|--------|-----------|
| `18da047` | Fix: stealth URL cap + spinner 1s + banner duplo |
| `e9b7988` | Fix: nuclei scope 13.8M→~12K (rm http/cves core + drop -tags com dirs) |
| `c897e81` | Feat: ui_log bridge + TTL crash recovery + 18 testes bridge |
| `40a0473` | Feat: Redis PubSub UI bridge (workers → watchdog Live UI) |
| `2657df7` | Feat: ReAct Heuristic Agent (LLM IDOR/BAC antes do Nuclei) |
| `e82b2a5` | Feat: Stealth — jitter, UA rotation, proxy pool, nuclei tech dirs |
| `2717bac` | Feat: Celery distributed execution + Redis broker |

## Arquitetura ativa

- **Pipeline** (9 tools): Subfinder → DNSX → Uncover → **Naabu** → HTTPX → Katana → **URLFinder** → JS Hunter → **ReAct Agent** → Nuclei
- **Distribuído**: Celery workers + Redis broker — `worker.py` + `docker-compose.yml`
- **UI Bridge**: Redis PubSub — workers atualizam watchdog Live em tempo real
- **Stealth**: jitter gaussiano + UA rotation + proxy pool + nuclei tech dirs
- **Nuclei scope**: `http/cves` removido de core_dirs; stealth URL cap 100 (hosts vs URLs)
- **ReAct Agent**: LLM (OpenRouter) analisa endpoints pré-Nuclei para IDOR/BAC
- **Notificações Telegram**: agrupado por template + tipo; summary card por scan
- **Naabu (IP mode)**: port-scan em 30 portas web comuns antes do HTTPX
- **URLFinder**: URLs históricas (Wayback/AlienVault) após Katana; merged + deduped
- **Katana**: `-js-crawl` + depth 3 — extrai endpoints embutidos em bundles Angular/React
- **Watchdog**: ciclo 1-2h adaptativo + plataforma tagueada por alvo (h1/it/custom)
- **Scoring**: 4 sinais (wildcard 35% / breadth 25% / quality 25% / platform 15%)
- **AI Validation**: dispara para score ≥ 60 (score escrito de volta no target)
- **Filtro FP**: 7 camadas determinísticas + ML LightGBM
- **JS Hunter**: severidade por tipo de segredo (CRITICAL: AWS/private key/Stripe; HIGH: Google/JWT/Slack)
- **Relatórios**: `.md` por alvo com plataforma correta (HackerOne / Custom / etc.)

## Hunt validado — VPS (DVWA + Juice Shop)

Caçada real em `31.220.80.221` confirma pipeline funcionando:
- 1 CRITICAL: DVWA default login (admin/password) ✅
- 4 HIGH: CORS wildcard em Juice Shop `/api/`, `/api/v1/`, `/api/v2/`, `/` ✅
- 8 MEDIUM: open redirect via params redirect/url/next/return/continue/to/goto/returnUrl ✅
- 4 MEDIUM: info disclosure (stack trace, prometheus metrics, config listing) ✅
- 43 JS Secrets detectados ✅
- Nuclei: ~12K req vs 13.8M original (redução 99.9%) ✅

## Limitações conhecidas

- APIs de plataforma (bbscope) requerem H1_USER/H1_TOKEN ou IT_TOKEN válidos
- Censys API usa token curto (ex: `Pu1KHr6r`) — não é UUID nem e-mail
- Modelo ML treinado com dados sintéticos — retraining com dados reais melhora precisão
- Terminais < 80x24 reduzem legibilidade do dashboard
- Uncover retorna 0 resultados se Shodan/Censys sem créditos de consulta
- URLFinder em alvos IP retorna 0 (esperado — sem domínio para consultar arquivos históricos)
- ReAct Agent desativado automaticamente quando OPENROUTER_API_KEY não definida

