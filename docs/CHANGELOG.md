# Hunt3r Changelog

## v1.0-EXCALIBUR — Session 4 Stability Checkpoint — `e1b0285`

### Smart 1h Cache (Recon Phase)
- `_is_cache_valid(filepath)` — checks file exists, non-empty, mtime < 3600s
- `_tool_cached(name, key, file)` — new status `"cached"`, renders **cyan** full bar in live view
- `_run_recon_phase`: Subfinder, DNSX, Uncover, HTTPX serve from cache when valid (<1h)
- `_run_tactical_phase`: Katana uses cache; **JS Hunter + Nuclei always run fresh** (by design)

### Auto-Cleanup
- `_auto_cleanup(target_dir)` called at scan start
- Removes stale recon files (>1h) for the current target
- Removes old snapshots from `logs/snapshots/` (>1h)
- Cache and cleanup share the same 3600s TTL → perfectly synchronized

### Nuclei TypeError Fix
- `_nuclei_progress_callback`: replaced fragile `float(str(val or 0))` with `_to_int`/`_to_float` helpers
  that catch `TypeError` and `ValueError` — handles any non-numeric value Nuclei may emit
- `_nuclei_extra_stats`: added `isinstance(total, (int, float))` guard as second safety net
- Root cause: Nuclei `-stats -sj` output may contain strings like `"N/A"` for not-yet-known fields
- Effect: spinner thread no longer crashes; Nuclei runs to completion

### Live View Order Fix
- `_live_view_data` and `_TOOL_COUNT_KEYS` reordered: Katana before JS Hunter
- Matches actual pipeline execution order: Subfinder → DNSX → Uncover → HTTPX → Katana → JS Hunter → Nuclei

### FP TITANIUM Snapshot Noise Fix
- `Colors.ERROR → Colors.WARNING` on "Eliminados N FPs" log
- `ui_log` only auto-snapshots on `Colors.ERROR` — watchdog startup no longer floods `logs/snapshots/`

### Terminal Resize Fix (SIGWINCH)
- `_sigwinch_handler` now clears last 3 lines of scroll region on resize (erases stale wrapped spinner text)
- `ui_update_status` truncates detail string to terminal width (prevents line wrap on narrow terminals)

### Tests
- **52 tests, 52 PASS** maintained across all changes

---

## v1.0-EXCALIBUR — Session 3 Hardening (current) — `2d00398`+

### CTRL+C / Graceful Shutdown
- `MissionRunner.run()` catches `KeyboardInterrupt`, calls `ui_mission_footer()` to clean up live view before re-raising
- `state_manual()` and `state_list()` catch `KeyboardInterrupt` from `start_mission()` — user returns to menu instead of seeing traceback
- `main()` loop wrapped in `try/except KeyboardInterrupt` — CTRL+C at any menu point returns to menu
- Previously: CTRL+C during Nuclei (or any tool) crashed with full traceback to terminal

### Live View Race Condition Fix
- `_live_view_loop()` wrapped in `try/except` — prevents thread death on any render error
- `_render_live_view()` now snapshots `_live_view_data` inside `_live_view_lock` before rendering
  (was reading dict outside lock — race condition with `_nuclei_progress_callback`)
- Eliminated "Exception in thread Thread-1 (_live_view_loop)" crash during Nuclei scan

### JS Secrets Pipeline (JSONL + Severity Routing)
- `run_js_hunter()` now outputs JSONL format: `{type, value, source, url, severity}`
  (was plaintext — `NotificationDispatcher.alert_js_secrets` silently failed to parse)
- `SECRET_SEVERITY` dict maps 14 secret types → `critical/high/medium/low`
- `alert_js_secrets()` routes by severity: Critical/High/Medium → Telegram, Low → Discord
  (was sending all to Telegram regardless of severity)

### Nuclei Improvements
- Non-JSON stderr lines now logged at INFO level (errors, template loading, debug output)
  (was silently discarded — impossible to debug Nuclei failures)
- Uses `Popen` + `-stats -sj` for real-time progress in live view
- Timeout: 3600s (1 hour — vulns at any cost)

### Notification Routing
- `alert_nuclei()`: Medium severity now routes to Telegram (was only Critical/High)
- Low/Info now routes to Discord only (was sending all severities to Discord)
- Added Medium emoji 🟡 in Telegram alerts (was falling back to ⚪)

### Code Quality
- Fixed FD leaks in `_count_lines()` and `_count_findings()` — now use `with` statement
- Output file truncation at start of every tool run (dedup across re-scans)
- `run_js_hunter()` also accepts `.mjs` and `.ts` files

### Tests
- **52 tests, 52 PASS** (36 unit + 16 integration) at every commit

---

## v1.0-EXCALIBUR — Session 2 Bug Fixes — `ac59c92`

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

