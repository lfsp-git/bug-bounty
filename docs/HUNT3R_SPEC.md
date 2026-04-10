# HUNT3R v1.0-EXCALIBUR — Technical Specification (Current)

## 1. End-to-end execution model

1. **Watchdog loop** (`core/watchdog.py`)
   - Pulls target wildcards (cache-aware)
   - Prioritizes by bounty potential
   - Executes up to 3 scans in parallel
2. **Mission orchestration** (`core/scanner.py`)
   - `ProOrchestrator.start_mission()` -> `MissionRunner.run()`
3. **Recon phase**
   - Subfinder -> DNSX -> Uncover -> HTTPX
4. **Tactical phase**
   - Katana -> JS Hunter -> Nuclei
5. **Validation/filtering**
   - FalsePositiveKiller + ML filter layer
6. **Output**
   - Notifications + markdown report + baseline persistence

## 2. Terminal UI architecture (active implementation)

`core/ui.py` uses Rich Live with full-screen rendering:

- **Mode**: `Live(..., screen=True, refresh_per_second=4)`
- **Sections**:
  - Banner (runtime/cycle/telemetry)
  - 3 worker panels (`W1/W2/W3`) side-by-side
  - Activity log panel (rolling events)
- **Synchronization**:
  - `_workers_lock` (`RLock`) for worker state
  - `_activity_lock` for timeline log
  - `_stdout_lock` for single-mode terminal writes
- **Worker routing**:
  - Thread-local identity via `set_worker_context()`
  - Worker slot queue in watchdog for stable thread->panel mapping

### Banner telemetry

Top bar exposes:

- Current clock
- Cycle counter
- Session runtime
- Total scanned
- `RUN / DONE / ERR` counters

### Worker panel content

Each worker panel shows:

- Target + `[idx/total]` + elapsed
- Tool rows: status symbol, tool name, progress bar, per-tool info
- Nuclei request telemetry (`done/total`, `rps`, `hits`)
- Mission metrics footer (`SUB`, `LV`, `EP`, `SEC`, `VN`)

### Activity log semantics

Event feed includes `[WID] MODULE message` with semantic coloring:

- red: errors/abort
- yellow: warning/anomaly
- green: result/success
- cyan: watchdog/mission lifecycle

## 3. Watchdog parallelism details

`run_watchdog()`:

- Disables tool-time writes in watchdog scans (`_RECORD_TOOL_TIMES = False`)
- Starts live tactical UI once
- For each cycle:
  - updates cycle counter (`ui_cycle_started()`)
  - fetches + prioritizes targets
  - dispatches tasks to `ThreadPoolExecutor(max_workers=3)`

`_scan_target_parallel_wrapper()`:

- Acquires worker slot from queue (`W1/W2/W3`)
- Binds current thread to that slot
- Registers worker mission in UI
- Runs scan + records scan history
- Emits snapshot on exceptions
- Releases worker slot back to queue in `finally`

## 4. Filtering model (current)

FalsePositiveKiller pipeline now includes ML-based decisioning:

- Legacy deterministic filters remain
- ML model acts as final layer (FASE 8 integration)
- Model artifact: `models/fp_filter_v1.pkl`

## 5. Tool flags (as implemented)

```bash
subfinder  -dL <file> -o <out> -silent -rate-limit=N
dnsx       -l <file> -o <out> -wd -silent -a -rate-limit=N
httpx      -l <file> -o <out> -silent -rate-limit N
katana     -list <file> -o <out> -silent -rate-limit=N -timeout 15 -depth 2
nuclei     -l <file> -o <out> -duc -silent -rl N -c 25 -timeout 5 -severity critical,high,medium [-tags tags]
```

## 6. Error observability

- Persistent logs: `logs/hunt3r.log`
- Runtime snapshots (JSON): `logs/snapshot_<label>_<timestamp>.json`
- Snapshot captures:
  - per-worker statuses
  - active tool states
  - recent activity entries

## 7. Current known limitations

- Platform API coverage in watchdog remains environment-dependent (`bbscope`/credentials)
- Very small terminals may reduce readability
- High-volume targets can require tuning nuclei timeout/rate limits

## 8. Validation baseline

Current baseline from repository test suite:

- `python3 -m pytest tests/ -q`
- Result: **66 passed**, with pre-existing warning set in improvement tests

