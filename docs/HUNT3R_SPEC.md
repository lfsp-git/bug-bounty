# 🛡️ HUNT3R v1.0-EXCALIBUR: Technical Specification

## 🔄 THE PIPELINE (PREDATOR CYCLE)
1. WATCHDOG: coleta wildcards (H1/BC/IT) em ciclos de 4–6h com cache de 12h.
2. DIFF ENGINE: compara com `recon/baselines/{handle}*`, processa apenas novos/alterados.
3. RECON: Subfinder → DNSX → Uncover → HTTPX.
4. TACTICAL: Katana crawler → JS Hunter → Nuclei (tags: cve, takeover, misconfig).
5. VALIDATION: FalsePositiveKiller + AI (score ≥ 80 targets only).
6. NOTIFY: Telegram (Critical/High/Medium) · Discord (Low/Info batch).
7. REPORT: BugBountyReporter gera `reports/<handle>_<date>_report.md`.

## 🧩 ARCHITECTURE

```
ProOrchestrator
  └── MissionRunner.run()
        ├── _run_recon_phase()        [subfinder/dnsx/uncover/httpx]
        ├── _run_vulnerability_phase() [sniper filter + truncation guard]
        │     └── _run_tactical_phase()
        │           ├── katana
        │           ├── js_hunter
        │           ├── nuclei
        │           └── _filter_and_validate_findings() [FP + AI]
        ├── _notify_and_report()      [NotificationDispatcher + BugBountyReporter]
        └── ReconDiff.save_baseline()
```

## 📡 NOTIFICATION ROUTING
- **Telegram**: Critical, High, Medium, JS secrets, escalations.
- **Discord**: Low, Info (batch embed), recon logs.

## 📤 OUTPUTS
- `recon/baselines/<handle>_findings.jsonl` — raw Nuclei JSONL
- `recon/baselines/<handle>_live.txt.js_secrets` — JS secrets (raw lines)
- `reports/<handle>_<date>_report.md` — submission-ready Markdown

## 🗄️ KEY FILES
| File | Role |
|------|------|
| `core/orchestrator.py` | MissionRunner + ProOrchestrator |
| `core/watchdog.py` | 24/7 continuous loop |
| `core/notifier.py` | Telegram + Discord |
| `core/reporter.py` | Bug bounty report generator |
| `core/fp_filter.py` | FalsePositiveKiller |
| `core/diff_engine.py` | Baseline diff |
| `core/rate_limiter.py` | Per-target throttling |
| `core/checkpoint.py` | Scan resume |
| `core/exporter.py` | CSV/XLSX/XML export |
| `core/dry_run.py` | Dry-run preview |
| `recon/engines.py` | Tool wrappers |
| `recon/js_hunter.py` | JS secret extractor |
| `recon/platforms.py` | H1/BC/IT API |
| `recon/tool_discovery.py` | Dynamic binary discovery |

## 🔒 SECURITY CONSTRAINTS
- All subprocess calls use list form (no shell=True).
- API keys never logged (stored in Session.headers).
- Rate limiting enforced per-target (1 req/s default).
- MAX_SUBS_PER_TARGET = 2000 (guards against runaway scans).

## 📋 CLI FLAGS
```
python3 main.py                    # Interactive menu
python3 main.py --watchdog         # 24/7 autonomous mode
python3 main.py --dry-run          # Preview targets, no execution
python3 main.py --resume <id>      # Resume from checkpoint
python3 main.py --export csv|xlsx|xml  # Export all findings
```

## STATUS
- Pipeline: fully wired end-to-end (recon → vuln → notify → report).
- Notifications: live (Telegram + Discord).
- Reports: auto-generated after every scan.
- Checkpoints: save/load implemented.
- Export: CSV/XML/XLSX from CLI.

