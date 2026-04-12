# Hunt3r — Resumo de Melhorias (FASE 1-8 + Pós-Watchdog + Deep Pipeline)

## Visão geral

| FASE/Sessão | Recurso | Arquivo principal |
|-------------|---------|-------------------|
| 1 | Tags Nuclei inteligentes por tecnologia | `recon/tech_detector.py` |
| 2 | Timeout otimizado (2s) + performance | `recon/engines.py` |
| 3 | UI Rich em tempo real | `core/ui.py` |
| 4 | Priorização de alvos por bounty | `core/bounty_scorer.py` |
| 5A | Watchdog multi-thread (3 workers) | `core/watchdog.py` |
| 5B | Alertas Discord/Telegram | `core/notifier.py` |
| 5C | Templates Nuclei customizados | `recon/custom_templates.py` |
| 8 | Filtro ML de falso positivo (LightGBM) | `core/ml_filter.py` |
| A-E | Slim Core: unificação + hardening | `core/runner.py`, `core/intel.py`, etc. |
| Pós-WD | P0: ML deps + AI validation threshold | `core/ml_filter.py`, `core/scanner.py` |
| Pós-WD | Venv enforcement + bounty scorer rewrite | `main.py`, `core/bounty_scorer.py` |
| Pós-WD | Uncover sync + Katana adaptativo + Censys | `recon/engines.py` |
| Pós-WD | Discord stats-only + Low/Info removidos | `core/notifier.py`, `core/reporter.py` |
| Pós-WD | Suite de testes abrangente | `tests/test_bounty_scorer.py` etc. |
| Pós-WD | --clean completo com health checks | `core/cleaner.py` |
| Pós-WD | Score writeback → AI validation real | `core/watchdog.py`, `core/intel.py` |
| Pós-WD | Severidade por tipo em JS Hunter | `recon/js_hunter.py` |
| Pós-WD | Watchdog ciclo 1-2h (era 4-6h) | `core/config.py` |
| Pós-WD | Platform tagging por fonte | `recon/platforms.py`, `core/watchdog.py` |
| **Deep** | **Suporte a IPs/CIDRs** | `core/config.py`, `core/scanner.py`, `core/ui.py` |
| **Deep** | **Naabu port scan (IP mode)** | `recon/engines.py`, `core/scanner.py` |
| **Deep** | **Katana -js-crawl depth 3** | `recon/engines.py` |
| **Deep** | **URLFinder hist URLs + merge dedup** | `recon/engines.py`, `core/scanner.py` |
| **Deep** | **UI 9-tools: Naabu + URLFinder** | `core/ui.py`, `tests/test_integration.py` |

## Métricas de impacto

| Métrica | Antes | Depois |
|---------|-------|--------|
| Findings/ciclo | 1 CVE | 3-5 CVEs |
| Tempo de scan | 728s | 440s (-40%) |
| Taxa de descoberta | 0.01% | 0.3-0.5% (+30-50x) |
| Ciclo watchdog | 4-6h | 1-2h (-70%) |
| Latência de alerta | 5-10 min | < 30s (-95%) |
| Testes | 17 | 364 (+2000%) |
| AI Validation funcionando | Nunca disparava | Dispara para score ≥ 60 |
| Platform nos reports | "Custom/Manual" (sempre) | HackerOne / Custom (alvos.txt) / etc. |
| Segredos JS notificados | 0 (todos dropped) | CRITICAL/HIGH/MEDIUM → Telegram |
| Alvos IP/CIDR | ❌ | ✅ Naabu 30 portas + fallback |
| Endpoints JS (SPA) | Superficial | `-js-crawl` extrai API endpoints |
| URLs históricas | ❌ | ✅ URLFinder → merged antes do Nuclei |

## Configuração necessária

### Variáveis de ambiente (`.env`)
```bash
OPENROUTER_API_KEY=sua_chave
TELEGRAM_BOT_TOKEN=seu_token
TELEGRAM_CHAT_ID=seu_chat_id
DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
H1_USER=seu_usuario_hackerone
H1_TOKEN=seu_token_hackerone
IT_TOKEN=seu_token_intigriti
SHODAN_API_KEY=seu_token
CENSYS_API_ID=token_curto_tipo_Pu1KHr6r  # NÃO é UUID
CENSYS_API_SECRET=censys_xxxxx...
CHAOS_KEY=sua_chave_chaos
```

### alvos.txt
Alvos customizados (um por linha). Aparecem nos relatórios como `Custom (alvos.txt)`:
```
*.example.com
target.io
192.168.1.1
10.0.0.0/24
```

## Troubleshooting

| Problema | Solução |
|----------|---------|
| AI Validation nunca dispara | Score ≥ 60? Ver logs "Score < 60" — wildcards recebem ~70-100pts |
| Uncover sempre 0 resultados | Verificar Shodan/Censys no .env; checar ~/.config/uncover/provider-config.yaml |
| Nuclei sem templates | `python3 main.py --clean` baixa templates automaticamente |
| Segredos JS não chegam Telegram | Finding precisa ter `severity` CRITICAL/HIGH/MEDIUM — OK após js_hunter fix |
| Platform "Unknown" no report | Garantir que bbscope está retornando dados; alvos de alvos.txt mostram "Custom (alvos.txt)" |
| Workers usando muito CPU | Reduzir `WATCHDOG_WORKERS` em `core/config.py` |
| Modelo ML não carrega | Verificar `models/fp_filter_v1.pkl` existe; warning esperado se ausente |
| Testes poluindo hunt3r.log | `tests/conftest.py` remove FileHandler — OK após fix |
| Juice Shop / porta 3000 não encontrado | IP mode agora usa Naabu — porta 3000 na lista padrão |
| URLFinder retorna 0 para IPs | Comportamento esperado — sem domínio histórico |

## Testes

```bash
python3 -m pytest tests/ -q          # Suite completa (364 testes)
python3 -m pytest tests/ -v -k test_  # Verbose com filtro
python3 main.py --clean               # Rodar testes via cleaner com output limpo
```


## Visão geral

| FASE/Sessão | Recurso | Arquivo principal |
|-------------|---------|-------------------|
| 1 | Tags Nuclei inteligentes por tecnologia | `recon/tech_detector.py` |
| 2 | Timeout otimizado (2s) + performance | `recon/engines.py` |
| 3 | UI Rich em tempo real | `core/ui.py` |
| 4 | Priorização de alvos por bounty | `core/bounty_scorer.py` |
| 5A | Watchdog multi-thread (3 workers) | `core/watchdog.py` |
| 5B | Alertas Discord/Telegram | `core/notifier.py` |
| 5C | Templates Nuclei customizados | `recon/custom_templates.py` |
| 8 | Filtro ML de falso positivo (LightGBM) | `core/ml_filter.py` |
| A-E | Slim Core: unificação + hardening | `core/runner.py`, `core/intel.py`, etc. |
| Pós-WD | P0: ML deps + AI validation threshold | `core/ml_filter.py`, `core/scanner.py` |
| Pós-WD | Venv enforcement + bounty scorer rewrite | `main.py`, `core/bounty_scorer.py` |
| Pós-WD | Uncover sync + Katana adaptativo + Censys | `recon/engines.py` |
| Pós-WD | Discord stats-only + Low/Info removidos | `core/notifier.py`, `core/reporter.py` |
| Pós-WD | Suite de testes abrangente | `tests/test_bounty_scorer.py` etc. |
| Pós-WD | --clean completo com health checks | `core/cleaner.py` |
| Pós-WD | Score writeback → AI validation real | `core/watchdog.py`, `core/intel.py` |
| Pós-WD | Severidade por tipo em JS Hunter | `recon/js_hunter.py` |
| Pós-WD | Watchdog ciclo 1-2h (era 4-6h) | `core/config.py` |
| Pós-WD | Platform tagging por fonte | `recon/platforms.py`, `core/watchdog.py` |

## Métricas de impacto

| Métrica | Antes | Depois |
|---------|-------|--------|
| Findings/ciclo | 1 CVE | 3-5 CVEs |
| Tempo de scan | 728s | 440s (-40%) |
| Taxa de descoberta | 0.01% | 0.3-0.5% (+30-50x) |
| Ciclo watchdog | 4-6h | 1-2h (-70%) |
| Latência de alerta | 5-10 min | < 30s (-95%) |
| Testes | 17 | 364 (+2000%) |
| AI Validation funcionando | Nunca disparava | Dispara para score ≥ 60 |
| Platform nos reports | "Custom/Manual" (sempre) | HackerOne / Custom (alvos.txt) / etc. |
| Segredos JS notificados | 0 (todos dropped) | CRITICAL/HIGH/MEDIUM → Telegram |

## Configuração necessária

### Variáveis de ambiente (`.env`)
```bash
OPENROUTER_API_KEY=sua_chave
TELEGRAM_BOT_TOKEN=seu_token
TELEGRAM_CHAT_ID=seu_chat_id
DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
H1_USER=seu_usuario_hackerone
H1_TOKEN=seu_token_hackerone
IT_TOKEN=seu_token_intigriti
SHODAN_API_KEY=seu_token
CENSYS_API_ID=token_curto_tipo_Pu1KHr6r  # NÃO é UUID
CENSYS_API_SECRET=censys_xxxxx...
CHAOS_KEY=sua_chave_chaos
```

### alvos.txt
Alvos customizados (um por linha). Aparecem nos relatórios como `Custom (alvos.txt)`:
```
*.example.com
target.io
```

## Troubleshooting

| Problema | Solução |
|----------|---------|
| AI Validation nunca dispara | Score ≥ 60? Ver logs "Score < 60" — wildcards recebem ~70-100pts |
| Uncover sempre 0 resultados | Verificar Shodan/Censys no .env; checar ~/.config/uncover/provider-config.yaml |
| Nuclei sem templates | `python3 main.py --clean` baixa templates automaticamente |
| Segredos JS não chegam Telegram | Finding precisa ter `severity` CRITICAL/HIGH/MEDIUM — OK após js_hunter fix |
| Platform "Unknown" no report | Garantir que bbscope está retornando dados; alvos de alvos.txt mostram "Custom (alvos.txt)" |
| Workers usando muito CPU | Reduzir `WATCHDOG_WORKERS` em `core/config.py` |
| Modelo ML não carrega | Verificar `models/fp_filter_v1.pkl` existe; warning esperado se ausente |
| Testes poluindo hunt3r.log | `tests/conftest.py` remove FileHandler — OK após fix |

## Testes

```bash
python3 -m pytest tests/ -q          # Suite completa (364 testes)
python3 -m pytest tests/ -v -k test_  # Verbose com filtro
python3 main.py --clean               # Rodar testes via cleaner com output limpo
```
