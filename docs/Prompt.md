# Hunt3r — Contexto de Sessão

## Estado atual

- FASE 1-8 entregues + Slim Core consolidado
- Watchdog tático com UI Rich Live ativo
- Pipeline estabilizado com contratos explícitos por fase
- Filtro FP 8 camadas (7 determinísticas + ML)
- 73 testes aprovados, 0 falhas

## Perfil da VPS

- CPU: 4 cores / 4 threads (Broadwell virtualizado)
- RAM: 8 GB
- Disco: ~161 GB

## Tuning de runtime

Defaults automáticos em `core/config.py`:
- Nós pequenos (≤2 cores ou ≤4 GB): conservador
- Nós médios (≤4 cores ou ≤8 GB): balanceado
- Nós maiores: maior throughput

Para esta VPS (4c/8GB):
- `RATE_LIMIT = 80`
- `NUCLEI_RATE_LIMIT = 120`
- `NUCLEI_CONCURRENCY = 25`
- `WATCHDOG_WORKERS = 3`

## Verificação rápida

```bash
python3 -m py_compile core/config.py core/watchdog.py core/scanner.py recon/engines.py
python3 -m pytest tests/ -q
python3 main.py --watchdog
```

## Guardrails

- Sem falhas silenciosas
- Commits atômicos e com testes
- Atualizar docs no mesmo commit quando mudar defaults operacionais

