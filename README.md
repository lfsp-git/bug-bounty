# Hunt3r v1.0-EXCALIBUR — Tactical Autonomous Bug Bounty Hunter

Hunt3r is an autonomous recon + vuln hunting pipeline focused on fast cycles, low false positives, and operational visibility in terminal-first environments.

## Current state

- **Phase status**: FASE 8 complete (ML false-positive layer integrated)
- **Watchdog UI**: Rich Live full-screen tactical dashboard (3 worker panels + activity log)
- **Latest tests**: `66 passed, 0 warnings, 11 subtests passed`
- **Recent core commits**:
  - `c7e1084` UX telemetry alignment for watchdog
  - `14d2c57` full tactical UI redesign (3 workers)
  - `9d2fbd9` military-grade Rich Live watchdog display
  - `8d29e27` silent-failure + tool-times watchdog fixes

## Pipeline (Predator cycle)

1. **WATCHDOG**: wildcard collection + prioritization + 3 parallel workers
2. **DIFF ENGINE**: baseline compare, only changed/new data gets attention
3. **RECON**: Subfinder -> DNSX -> Uncover -> HTTPX
4. **TACTICAL**: Katana -> JS Hunter -> Nuclei
5. **FILTERING**: 8-layer FalsePositiveKiller (last layer = ML filter)
6. **AI VALIDATION**: score-based validation path
7. **NOTIFY + REPORT**: Telegram/Discord + markdown bug bounty report

## Quick start

```bash
pip install -r requirements.txt
cp .env.example .env
python3 main.py
```

Useful modes:

```bash
python3 main.py --watchdog
python3 main.py --dry-run
python3 main.py --resume <mission_id>
python3 main.py --export csv
```

## Watchdog UI/UX (current)

- Full-screen Rich Live (`screen=True`) for stable in-place rendering
- Top banner with cycle/runtime + operational counters: `RUN / DONE / ERR`
- 3 fixed worker panels (`W1`, `W2`, `W3`) with per-tool progress
- Rolling activity log with timestamps and worker tags (`[W1]`, `[W2]`, `[W3]`)
- Dynamic worker-slot mapping via queue to keep panel↔thread consistency
- Auto-snapshot on worker/scan errors:
  - `logs/snapshot_<label>_<timestamp>.json`

## VPS-aware performance tuning

Hunt3r now auto-tunes runtime constants from host capacity (`os.cpu_count()` + `/proc/meminfo`):

- `RATE_LIMIT`
- `NUCLEI_RATE_LIMIT`
- `NUCLEI_CONCURRENCY`
- `WATCHDOG_WORKERS`

Default policy:
- low-capacity hosts: conservative
- mid-capacity hosts (4c/8GB): balanced
- higher-capacity hosts: higher throughput

## Main modules

- `core/scanner.py`: MissionRunner + ProOrchestrator + runtime pipeline orchestration
- `core/watchdog.py`: 24/7 loop, API target sync, parallel execution, worker assignment
- `core/ui.py`: tactical terminal dashboard, activity feed, snapshots, worker state
- `core/filter.py` + `core/ml_filter.py`: 8-layer FP filtering with ML model support
- `recon/engines.py`: tool wrappers and Nuclei progress streaming

## Testing

```bash
python3 -m py_compile core/ui.py core/watchdog.py core/scanner.py
python3 -m pytest tests/ -q
```

## Documentation map

- `docs/HUNT3R_SPEC.md`: technical architecture/spec
- `docs/CHANGELOG.md`: release history and notable fixes
- `STATUS.md`: current execution status snapshot
- `PLAN.md`: phase roadmap and milestones
- `FASE8_SUMMARY.md`: ML integration/training details
