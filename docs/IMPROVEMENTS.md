# Hunt3r — Resumo de Melhorias (FASE 1-8)

## Visão geral

| FASE | Recurso | Arquivo principal |
|------|---------|-------------------|
| 1 | Tags Nuclei inteligentes por tecnologia | `recon/tech_detector.py` |
| 2 | Timeout otimizado (2s) + performance | `recon/engines.py` |
| 3 | UI Rich em tempo real | `core/ui.py` |
| 4 | Priorização de alvos por bounty | `core/bounty_scorer.py` |
| 5A | Watchdog multi-thread (3 workers) | `core/watchdog.py` |
| 5B | Alertas Discord/Telegram | `core/notifier.py` |
| 5C | Templates Nuclei customizados | `recon/custom_templates.py` |
| 8 | Filtro ML de falso positivo (LightGBM) | `core/ml_filter.py` |
| A-E | Slim Core: unificação + hardening | `core/runner.py`, `core/intel.py`, etc. |

## Métricas de impacto

| Métrica | Antes | Depois |
|---------|-------|--------|
| Findings/ciclo | 1 CVE | 3-5 CVEs |
| Tempo de scan | 728s | 440s (-40%) |
| Taxa de descoberta | 0.01% | 0.3-0.5% (+30-50x) |
| Ciclo watchdog | 8h | 2-3h (-60%) |
| Latência de alerta | 5-10 min | < 30s (-95%) |
| Testes | 17 | 73 (+330%) |

## Configuração necessária

### Variáveis de ambiente (`.env`)
```bash
OPENROUTER_API_KEY=sua_chave
TELEGRAM_BOT_TOKEN=seu_token
TELEGRAM_CHAT_ID=seu_chat_id
DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
H1_USER=seu_usuario
H1_TOKEN=seu_token
BC_TOKEN=seu_token
IT_TOKEN=seu_token
```

### Templates customizados
Criados automaticamente em `recon/templates/` na primeira execução.

## Troubleshooting

| Problema | Solução |
|----------|---------|
| Templates não carregam | `python3 -c "from recon.custom_templates import load_custom_templates; load_custom_templates()"` |
| Workers usando muito CPU | Reduzir `WATCHDOG_WORKERS` em `core/config.py` |
| Sem alertas Discord | Verificar `DISCORD_WEBHOOK` no `.env` |
| Timeout Nuclei em alvos grandes | Aumentar `TOOL_TIMEOUTS["nuclei"]` em `core/config.py` |
| Modelo ML não carrega | Verificar `models/fp_filter_v1.pkl` existe |

## Testes

```bash
python3 -m pytest tests/ -q          # Suite completa (73 testes)
python3 -m pytest tests/ -v -k test_  # Verbose com filtro
```
