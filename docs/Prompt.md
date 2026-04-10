# Hunt3r Prompt — Current Session Context (Updated)

## State now

- FASE 1-8 delivered.
- Watchdog tactical UI active with 3-panel worker view.
- Worker/thread routing stabilized.
- Engine non-interactive false-skip fixed.
- Docs refreshed to current architecture.

## VPS profile (from attached hardware docs)

- CPU: 4 cores / 4 threads (Broadwell virtualized)
- RAM: 8 GB
- Disk: ~161 GB (148 GB ext4 volume)

## Runtime tuning policy

Hardware-aware defaults in `core/config.py` now auto-tune:

- Small nodes (<=2 cores or <=4 GB): conservative
- Mid nodes (<=4 cores or <=8 GB): balanced
- Bigger nodes: higher throughput

For this VPS (4c/8GB) target profile:

- `RATE_LIMIT = 80`
- `NUCLEI_RATE_LIMIT = 120`
- `NUCLEI_CONCURRENCY = 25`
- `WATCHDOG_WORKERS = 3` (bounded by CPU)

## Immediate goals

1. Keep watchdog stable under long-running cycles.
2. Preserve UI alignment with dense activity logs.
3. Maintain low false-positive rate with ML layer.
4. Keep tests green and warnings-free.

## Quick verify

```bash
python3 -m py_compile core/config.py core/watchdog.py core/scanner.py recon/engines.py
python3 -m pytest tests/ -q
python3 main.py --watchdog
```

## Guardrails

- No silent failures.
- No broad behavior changes outside performance/scheduling.
- Keep commits atomic and test-backed.
- If changing operational defaults, update docs in same commit.

