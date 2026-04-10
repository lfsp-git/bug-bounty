# Hunt3r Changelog

## v1.0-EXCALIBUR — Session 2 Bug Fixes (current) — `ac59c92`

### Nuclei
- Fixed `-uau` (invalid flag) → removed (caused silent 0s exit)
- Fixed `-t tags_string` (template path flag) → corrected to `-tags`
- Fixed `-rate-limit=N` → corrected to `-rl N`
- Added `-duc` to skip Nuclei update check (~5s saved on startup)
- Added `-timeout 5` per-template HTTP cap to prevent hangs
- Added `-severity critical,high,medium` to restrict template scope
  (cve+misconfig+takeover = thousands of templates; was always timing out)
- Added `-c 25` concurrency cap for slow/gov targets
- Removed `-stats -sj` (conflict with `-silent`; output went to DEVNULL)
- Lowered default rate limit `100 → 50`

### UI / Terminal
- Banner + Live View frozen at fixed positions via terminal scroll region
  (`_FIXED_TOP=12` = banner 7 + header box 5; `_LIVE_VIEW_LINES=12`)
- Progress bars colored by elapsed/ETA ratio (green/yellow/red)
- `_stdout_lock` (`threading.Lock`) serializes all stdout writes
- `_render_live_view` uses non-blocking acquire to skip frame during main-thread writes
- `ui_scan_summary` now holds `_stdout_lock` while printing (no spinner interleave)
- `ui_mission_footer()` called BEFORE `ui_scan_summary()` (stops live view thread first)
- `ui_mission_footer` no longer calls `clear` (was wiping scan summary)
- Spinner thread join timeout: `0.5s → 2.0s`

### Scanner / Pipeline
- Katana + Nuclei now receive HTTPX URLs (full URLs) instead of raw hostnames
- `_tool_start(name)` / `_tool_done(name, key, file)` helpers added
- `results` dict includes `target`, `alive`, `score` keys (was showing "UNKNOWN")
- `class MissionRunner:` declaration was accidentally deleted → restored
- CTRL+C at `[Enter para voltar]` prompt no longer produces traceback

### Engines / Debug
- `run_cmd`: stderr now captured to temp file; logged if non-empty (first 120 chars)
  (previously silently discarded — was masking all tool errors)

### Tests
- **52 tests, 52 PASS** (36 unit + 16 integration) at every commit in this session

---

## v1.0-EXCALIBUR — Clean Architecture — `93bfbee`

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

