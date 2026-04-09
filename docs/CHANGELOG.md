# Hunt3r Changelog

## v1.0-EXCALIBUR (current)
- Wired NotificationDispatcher into MissionRunner (Telegram/Discord now live)
- Added core/reporter.py: BugBountyReporter generates Markdown submission reports
- Fixed --export CLI flag: now loads all findings from recon/baselines/
- Cleaned legacy docs and dead code

## FASE 4 (2024)
- Dry-run mode (--dry-run)
- Resume capability (--resume)
- Export formats (--export csv|xlsx|xml)
- Structured logging (core/logger.py)
- Code style guide (.github/CODE_STYLE.md)

## FASE 1-3 (2024)
- Fixed 20 critical/high/medium issues
- Bare except clauses replaced with specific exceptions
- Race condition in UI fixed (threading.RLock)
- Dynamic tool path discovery
- CLI input validation (domain/URL regex)
- Rate limiting per-target
- JSON parsing error handling for Nuclei output
- Environment variable validation at startup
- Centralized timeouts
- Watchdog history file I/O optimization
