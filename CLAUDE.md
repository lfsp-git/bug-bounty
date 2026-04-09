# CLAUDE CODE & AIDER OPERATIONAL GUIDE

## WORKFLOW
- Architect Mode: use `/architect` para grandes refactors (orchestrator).
- Atomic commits for each bugfix or feature.
- Avoid reading recon/db/ directly; use baselines metadata.

## COMMON FIXES
- Subfinder 0 subs: use subprocess.PIPE and capture output in memory.
- Nuclei timeout: ensure `-stats -sj` is passed and stderr/stdout are handled.
- venv issues: ensure paths and activate scripts are correct.

## RECENT CHANGES
- Orchestrator refactor: MissionRunner extracted; ProOrchestrator is backward-compatible now.
