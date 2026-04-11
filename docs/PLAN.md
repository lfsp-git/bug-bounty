# Hunt3r — Plano Operacional

## Objetivo

Manter o Hunt3r operando com máxima eficiência, mínimo falso positivo e execução autônoma confiável.

## Perfil da VPS

- CPU: 4 cores / 4 threads (Broadwell virtualizado)
- RAM: 8 GB
- Disco: ~161 GB (volume ext4 148 GB)

## Configuração de runtime atual (auto-tuning para 4c/8GB)

- `RATE_LIMIT = 80`
- `NUCLEI_RATE_LIMIT = 120`
- `NUCLEI_CONCURRENCY = 25`
- `WATCHDOG_WORKERS = 3`
- `WATCHDOG_SLEEP_MIN = 3600` (1h)
- `WATCHDOG_SLEEP_MAX = 7200` (2h)
- AI Validation: score ≥ 60

## Estado atual (2026-04-11)

Todas as issues críticas identificadas na análise pós-watchdog foram resolvidas:

| Bug | Status |
|-----|--------|
| AI Validation nunca disparava (score não gravado) | ✅ Corrigido |
| Segredos JS todos silenciados (sem campo severity) | ✅ Corrigido |
| Platform "Custom/Manual" em todos os reports | ✅ Corrigido |
| Watchdog ciclo 4-6h (lento) | ✅ 1-2h |
| Testes poluindo hunt3r.log | ✅ conftest.py |
| PDF export sem nome do alvo | ✅ Corrigido |

## Próximos passos operacionais

1. **Retraining do modelo ML**: coletar findings reais marcados como TP/FP para retraining do `fp_filter_v1.pkl`
2. **bbscope com credenciais reais**: instalar bbscope e configurar H1_USER/H1_TOKEN para coleta automática de wildcards
3. **Validação de segredos JS ativos**: step opcional pós-JS Hunter para verificar se API keys encontradas são válidas (evitar alertas de chaves expiradas)
4. **Monitorar ciclos**: após 2-3 ciclos com novas configs (1-2h), avaliar se score ≥ 60 está filtrando corretamente

## Verificação rápida

```bash
python3 -m py_compile core/config.py core/watchdog.py core/scanner.py
python3 -m pytest tests/ -q
python3 main.py --clean
python3 main.py --watchdog
```

