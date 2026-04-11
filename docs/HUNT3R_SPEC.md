# HUNT3R v1.0-EXCALIBUR — Technical Specification (Current)

## 1. End-to-end execution model

1. **Watchdog loop** (`core/watchdog.py`)
   - Pulls/synchronizes wildcard targets
   - Prioritizes with unified intel scoring
   - Executes parallel scans with adaptive sleep per cycle delta
2. **Mission orchestration** (`core/runner.py` -> `core/scanner.py`)
   - `ProOrchestrator.start_mission()` -> `MissionRunner.run()`
3. **Recon phase**
   - Subfinder -> DNSX -> Uncover -> HTTPX
4. **Tactical phase**
   - Katana -> JS Hunter -> Nuclei
5. **Validation/filtering**
   - FalsePositiveKiller + ML layer + optional AI validation
6. **Output/state**
   - Notifications + markdown report + export + baseline/checkpoints

## 2. Unified module surfaces

- `core/runner.py`: orchestration entrypoint
- `core/intel.py`: AI client + target scoring entrypoint
- `core/state.py`: baseline/checkpoint entrypoint
- `core/output.py`: notify/report/export entrypoint
- `recon/tools.py`: tool discovery + execution entrypoint

Legacy implementation files still back these facades internally, but project imports route through unified surfaces.

## 3. Terminal UI architecture

`core/ui.py` uses fixed top/bottom zones with synchronized stdout and worker-scoped telemetry:

- `_stdout_lock` serializes terminal writes
- `_live_view_lock` protects shared live state
- worker routing via `set_worker_context()`

Call order in scanner remains:

1. `ui_mission_footer()`
2. `ui_scan_summary()`

## 4. Pipeline contracts

`MissionRunner` emits explicit phase payloads with:

- `ok`
- `errors`
- `counts`
- `paths`

Final mission result includes:

- `phase_results`
- `errors`
- `ok`
- per-phase duration metrics (`metrics.phase_duration_seconds`)

## 5. Watchdog operational behavior

- Parallel workers from `WATCHDOG_WORKERS`
- Cycle metrics aggregation:
  - changed targets
  - non-cached errors
  - average phase durations
- Adaptive next sleep window computed from cycle delta/error ratio

## 6. Notification deduplication

Notifier applies temporal dedup cache (`recon/cache/notifier_dedup.json`) with TTL (`NOTIFY_DEDUP_TTL_SECONDS`) to reduce repeated Telegram/Discord alerts for the same artifact.

## 7. Tool flags (implemented)

```bash
subfinder  -dL <file> -o <out> -silent -rate-limit=N
dnsx       -l <file> -o <out> -wd -silent -a -rate-limit=N
httpx      -l <file> -o <out> -silent -rate-limit N
katana     -list <file> -o <out> -silent -rate-limit=N -timeout 15 -depth 2
nuclei     -l <file> -o <out> -duc -silent -rl N -c 25 -timeout 5 -severity critical,high,medium [-tags tags]
```

## 8. Known limitations

- Platform API path depends on local `bbscope` and valid credentials
- Very small terminals can degrade watchdog rendering
- Very large target sets may require Nuclei timeout tuning

## 9. Validation baseline

- `python3 -m pytest tests/ -q`
- Current baseline: **71 passed, 11 subtests passed**
