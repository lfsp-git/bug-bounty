# Hunt3r — Status Operacional

## Checkpoint atual

- **Data**: 2026-04-11
- **Branch**: `main`
- **Commit**: `ccd749c`
- **Estado**: Totalmente operacional — watchdog 24/7 + port scan + hist URLs + JS-crawl profundo
- **Testes**: 364 aprovados, 11 subtestes, 0 falhas

## Commits recentes (mais relevantes)

| Commit | Descrição |
|--------|-----------|
| `ccd749c` | Fix: UI/UX completa para novos tools Naabu + URLFinder |
| `f1af61d` | Feat: port scan + hist URLs + JS-crawl deep pipeline |
| `21521f2` | Fix: UI single-mode spinner + duplo banner + scope_type descartado |
| `703b70f` | Fix: menu interativo corrigido + opcao Cacar todos alvos.txt |
| `c7de89d` | Feat: suporte a IPs e CIDRs como alvos |
| `5f246ef` | Fix: platform tagging por fonte + nomenclatura de relatórios |
| `97d6081` | Fix: score writeback + severidade de segredos JS + ciclo watchdog 1h |

## Arquitetura ativa

- **Pipeline** (9 tools): Subfinder → DNSX → Uncover → **Naabu** → HTTPX → Katana → **URLFinder** → JS Hunter → Nuclei
- **Naabu (IP mode)**: port-scan em 30 portas web comuns antes do HTTPX (3000, 8080, 8443, etc.)
- **URLFinder**: URLs históricas (Wayback/AlienVault) após Katana; merged + deduped antes do Nuclei
- **Katana**: `-js-crawl` + depth 3 — extrai endpoints embutidos em bundles Angular/React
- **Superfícies unificadas**: `runner.py`, `intel.py`, `state.py`, `output.py`, `tools.py`
- **Watchdog**: ciclo 1-2h adaptativo + plataforma tagueada por alvo (h1/it/custom)
- **Scoring**: 4 sinais (wildcard 35% / breadth 25% / quality 25% / platform 15%)
- **AI Validation**: dispara para score ≥ 60 (score escrito de volta no target)
- **Notificações**: Telegram → vulns Medium/High/Critical; Discord → stats de scan + heartbeat
- **Relatórios**: `.md` por alvo com plataforma correta (HackerOne / Custom (alvos.txt) / etc.)
- **Scanner**: pipeline recon → tática → validação com contratos explícitos por fase
- **Filtro FP**: 7 camadas determinísticas + ML LightGBM
- **JS Hunter**: severidade por tipo de segredo (CRITICAL: AWS/private key/Stripe; HIGH: Google/JWT/Slack)
- **UI**: dashboard tático fullscreen (Rich Live) — 9 tools, painéis height=15, PIPELINE_TOOLS atualizado
- **--clean**: purge → update tools → update deps → health → API keys → uncover sync → ML → testes

## Limitações conhecidas

- APIs de plataforma (bbscope) requerem H1_USER/H1_TOKEN ou IT_TOKEN válidos
- Censys API usa token curto (ex: `Pu1KHr6r`) — não é UUID nem e-mail
- Modelo ML treinado com dados sintéticos — retraining com dados reais melhora precisão
- Terminais < 80x24 reduzem legibilidade do dashboard
- Uncover retorna 0 resultados se Shodan/Censys sem créditos de consulta
- URLFinder em alvos IP retorna 0 (esperado — sem domínio para consultar arquivos históricos)

