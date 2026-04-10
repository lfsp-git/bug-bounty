# Hunt3r Changelog

## 2026-04-10 — Tactical watchdog UI stabilization + telemetry alignment

### `c7e1084`
- Improved watchdog execution-to-UI alignment:
  - Worker slot mapping now uses queue-based assignment (prevents worker label drift)
  - Added top banner operational counters (`RUN`, `DONE`, `ERR`)
  - Added semantic coloring in activity log for rapid triage

### `14d2c57`
- Full tactical dashboard refactor:
  - Rich Live full-screen UI (`screen=True`)
  - 3 worker panels (`W1/W2/W3`) with per-tool progress
  - Rolling activity log panel
  - Thread-local worker context and per-worker routing
  - Auto-snapshot on worker-level failures

### `9d2fbd9`
- Military-grade watchdog live view rollout:
  - New panel architecture and execution visibility
  - Baseline worker telemetry and session stats
  - Core UI/scanner/watchdog wiring for concurrent rendering

### `8d29e27`
- Silent failure fix in watchdog:
  - `ui_mission_footer` optional stats arg fix
  - Prevented `tool_times.json` updates during watchdog mode

---

## 2026-04-10 — FASE 8 ML false-positive layer

### `b5e6c09`
- Integrated ML filter into FP pipeline
- Added config knobs and integration docs

### `c5b1a98`
- Added training/data prep pipeline for ML filter
- Generated model artifacts and validation outputs

---

## Historical notes

The repository previously tracked phase-by-phase history in detail (FASE 1..7).
That implementation history remains visible in git log and in:

- `PLAN.md`
- `FASE8_SUMMARY.md`

This changelog now focuses on current operationally relevant releases.

