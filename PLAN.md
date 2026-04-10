# Hunt3r Plan — Runtime Alignment (Refreshed)

## Objective

Align tool execution, watchdog coworkers, and UI throughput with actual VPS capacity while keeping reliability high.

## Completed in this update

1. Hardware-aware runtime tuning added in `core/config.py`.
2. Watchdog worker count now sourced from config (`WATCHDOG_WORKERS`) instead of hardcoded value.
3. Worker slot queue now honors effective worker limit.
4. Legacy pytest warnings fixed in `tests/test_improvements.py` by replacing return-based tests with assertions.
5. Prompt context updated (`Prompt.md`) to reflect current architecture and VPS profile.

## Current operating profile (this VPS)

- CPU: 4c/4t
- RAM: 8 GB
- Workers: 3
- Core rate limits tuned for balanced throughput vs stability.

## Next operational checks

1. Run watchdog for extended cycle and compare error/snapshot rates.
2. Monitor nuclei saturation under high target volume.
3. Validate API collection path when bbscope is available.
4. Tune timeouts only if sustained overload appears in logs.

