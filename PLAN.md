# Hunt3r Roadmap (Updated)

## Current delivery status

- FASE 1-8: implemented
- Watchdog tactical UI: refactored and aligned with parallel execution
- ML FP filter: integrated as final layer
- Test baseline: 66 passing

## Delivered milestones

1. Smart nuclei tag detection + tech inference
2. Performance optimization and timeout tuning
3. Rich terminal UX foundation
4. Bounty prioritization strategy
5. Parallel watchdog execution (3 workers)
6. Notification routing (Telegram/Discord)
7. Custom templates
8. ML false-positive reduction layer
9. Tactical UI hardening (worker panels, activity telemetry, snapshots)

## Operational goals (next cycle)

1. Validate watchdog against real platform APIs with full credentials/tool chain.
2. Improve large-target resilience (adaptive nuclei timeout/rate).
3. Expand observability KPIs (tool latency histograms, cycle SLA, drop/error rates).
4. Optional: expose a lightweight read-only runtime status endpoint.

## Guardrails

- Keep CLI workflow stable (`main.py`, `--watchdog`, `--dry-run`, `--resume`, `--export`)
- Preserve backward compatibility in scanner/watchdog integration
- Treat silent failures as bugs; always surface into logs/snapshots
- Keep changes test-backed (`python3 -m pytest tests/ -q`)

