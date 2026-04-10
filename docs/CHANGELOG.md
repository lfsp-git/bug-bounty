# Hunt3r Changelog

## v1.0-EXCALIBUR — Clean Architecture (current)

### Refactor: 25 arquivos → 12 módulos unificados
- `core/config.py` — merged: constants + timeouts + rate_limiter + dedup + validators
- `core/ai.py` — merged: ai_client + intelligence
- `core/storage.py` — merged: diff_engine + checkpoint
- `core/export.py` — merged: exporter + dry_run
- `core/ui.py` — renamed from ui_manager
- `core/filter.py` — renamed from fp_filter
- `core/scanner.py` — renamed from orchestrator
- Deleted 14 dead/merged files (logging_utils, logger, escalator, template_manager, validation, cache, constants, timeouts, rate_limiter, dedup, ai_client, intelligence, diff_engine, checkpoint, exporter, dry_run, fp_filter, ui_manager, orchestrator)

### Features
- Wired NotificationDispatcher into MissionRunner (Telegram/Discord live)
- Added `core/reporter.py`: BugBountyReporter → `reports/<handle>_<date>_report.md`
- Fixed `--export` CLI: loads all findings from `recon/baselines/`
- Rate limiting ativo em todas as 7 fases do pipeline

### Security
- `.env.example` sanitizado: zero dados reais, apenas placeholders genéricos
- `_load_env()` detecta valores placeholder não substituídos
- Exception handling específico (sem bare `except Exception`)

### Tests
- `tests/test_hunt3r.py`: **36 testes, 36 PASS** cobrindo todos os módulos core
- Corrigido `datetime.utcnow()` deprecation em `core/reporter.py`

---

## v1.0-EXCALIBUR (anterior)
- Wired NotificationDispatcher into MissionRunner
- Added core/reporter.py: BugBountyReporter
- Fixed --export CLI flag
- Cleaned legacy docs and dead code

## FASE 4 (2024)
- Dry-run mode (`--dry-run`)
- Resume capability (`--resume`)
- Export formats (`--export csv|xlsx|xml`)
- Structured logging
- Code style guide (`.github/CODE_STYLE.md`)

## FASE 1-3 (2024)
- 20 critical/high/medium issues fixed
- Bare except → specific exceptions
- Race condition UI (threading.RLock)
- Dynamic tool path discovery (tool_discovery.py)
- CLI input validation (domain/URL regex)
- Rate limiting per-target
- JSON parsing error handling (Nuclei JSONL)
- Env variable validation at startup
- Centralized timeouts
- Watchdog history file I/O optimization

