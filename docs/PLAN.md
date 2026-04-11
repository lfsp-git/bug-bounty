# Hunt3r — Plano Operacional

## Objetivo

Manter o Hunt3r operando com máxima eficiência, mínimo falso positivo e execução autônoma confiável.

## Perfil da VPS

- CPU: 4 cores / 4 threads (Broadwell virtualizado)
- RAM: 8 GB
- Disco: ~161 GB (volume ext4 148 GB)

## Configuração de runtime (auto-tuning)

Para este perfil (4c/8GB):
- `RATE_LIMIT = 80`
- `NUCLEI_RATE_LIMIT = 120`
- `NUCLEI_CONCURRENCY = 25`
- `WATCHDOG_WORKERS = 3`

## Próximos passos operacionais

1. Instalar `bbscope` e validar coleta de alvos via APIs H1/BC/IT
2. Executar watchdog em ciclo estendido e monitorar taxa de erro/snapshot
3. Coletar findings reais para retraining do modelo ML
4. Ajustar timeouts conforme saturação observada nos logs

## Verificação rápida

```bash
python3 -m py_compile core/config.py core/watchdog.py core/scanner.py
python3 -m pytest tests/ -q
python3 main.py --watchdog
```

