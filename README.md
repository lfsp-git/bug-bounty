# Hunt3r v1.0-EXCALIBUR

Hunt3r is a terminal-first autonomous bug bounty recon pipeline with watchdog execution, deterministic filtering, AI-assisted validation, and operational reporting.

## Current architecture (slim core)

- `main.py` — CLI entry point and mode routing
- `core/runner.py` — unified mission orchestration entry (`MissionRunner`, `ProOrchestrator`)
- `core/intel.py` — unified intelligence/scoring entry (`AIClient`, `IntelMiner`, bounty scoring)
- `core/state.py` — unified baseline/checkpoint entry
- `core/output.py` — unified notifier/reporter/export entry
- `recon/tools.py` — unified tooling entry (tool discovery + engines)
- `core/watchdog.py` — adaptive 24/7 loop with cycle metrics
- `core/ui.py` — full-screen tactical UI

## Pipeline

`WATCHDOG -> DIFF -> Subfinder -> DNSX -> Uncover -> HTTPX -> Katana -> JS Hunter -> Nuclei -> FP Filter -> AI Validation -> Notify -> Report`

## Quick start

```bash
pip install -r requirements.txt
python3 main.py
```

Useful modes:

```bash
python3 main.py --watchdog
python3 main.py --dry-run
python3 main.py --resume <mission_id>
python3 main.py --export csv
```

## Validation

```bash
python3 -m py_compile core/scanner.py core/watchdog.py core/notifier.py
python3 -m pytest tests/ -q
```

Latest baseline: `71 passed, 11 subtests passed`.
