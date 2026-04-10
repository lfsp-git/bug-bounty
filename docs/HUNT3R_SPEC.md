# 🛡️ HUNT3R v1.0-EXCALIBUR: Technical Specification

## 🔄 THE PIPELINE (PREDATOR CYCLE)
1. **WATCHDOG**: coleta wildcards (H1/BC/IT) em ciclos de 4–6h com cache de 12h.
2. **DIFF ENGINE**: compara com `recon/baselines/{handle}.json`, processa apenas novos/alterados.
3. **RECON**: Subfinder → DNSX → Uncover → HTTPX.
4. **TACTICAL**: Katana crawler → JS Hunter → Nuclei (`-tags cve,misconfig,takeover -severity critical,high,medium`).
5. **VALIDATION**: FalsePositiveKiller (6 filtros) + AI scoring (AIClient, score ≥ 80).
6. **NOTIFY**: Telegram (Critical/High/Medium) · Discord (Low/Info batch).
7. **REPORT**: BugBountyReporter gera `reports/<handle>_<date>_report.md`.

## 🧩 ARCHITECTURE (Clean)

```
main.py (CLI entry point, ~283 linhas)
  ├── ProOrchestrator
  │     └── MissionRunner.run()
  │           ├── _run_recon_phase()          [subfinder/dnsx/uncover/httpx]
  │           ├── _run_vulnerability_phase()  [sniper filter + truncation guard]
  │           │     └── _run_tactical_phase()
  │           │           ├── katana          [-timeout 15 -depth 2]
  │           │           ├── js_hunter
  │           │           ├── nuclei          [-duc -severity crit/high/med -c 25 -timeout 5]
  │           │           └── FalsePositiveKiller + _filter_and_validate_findings()
  │           ├── _notify_and_report()        [NotificationDispatcher + BugBountyReporter]
  │           └── ReconDiff.save_baseline()
  └── WatchdogLoop (--watchdog)

core/ (12 módulos, ~2750 linhas total)
  config.py    — constantes, timeouts, rate limiter, dedup, validators
  ai.py        — AIClient (OpenRouter)
  storage.py   — ReconDiff (baseline diff) + CheckpointManager
  export.py    — ExportFormatter (CSV/XLSX/XML) + run_dry_run
  ui.py        — terminal UI, scroll region, live view, _stdout_lock, snapshots
  filter.py    — FalsePositiveKiller (6 filtros: WAF, placeholder, Micro, etc.)
  scanner.py   — MissionRunner + ProOrchestrator + _run_with_progress
  notifier.py  — NotificationDispatcher (Telegram/Discord)
  reporter.py  — BugBountyReporter (Markdown reports)
  watchdog.py  — loop 24/7 autônomo
  updater.py   — ToolUpdater (PDTM + nuclei-templates)
  __init__.py

recon/ (4 módulos, ~540 linhas total)
  engines.py        — run_subfinder/dnsx/uncover/httpx/katana/nuclei/js_hunter
                      run_cmd captura stderr em temp file para debug
  js_hunter.py      — JSHunter (extração real de secrets de JS)
  platforms.py      — H1Platform, BCPlatform, ITigriti, PlatformManager
  tool_discovery.py — find_tool() com cache, busca em ~/.pdtm/go/bin + ~/go/bin + PATH
```

## 📡 NOTIFICATION ROUTING
| Severity | Canal | Formato |
|----------|-------|---------|
| Critical / High | Telegram | HTML individual por finding |
| Medium | Telegram | HTML batch |
| JS Secrets | Telegram | HTML individual |
| Low / Info | Discord | Embed batch |
| Recon logs | Discord | Text |

## 🛡️ SECURITY
- Tokens: nunca logados, nunca em código — apenas via `.env`
- Command injection: `shlex.quote()` em todos os subprocessos
- `.env.example`: apenas placeholders genéricos (sem dados reais)
- Exception handling: específico em todos os módulos

## 🧪 TESTES
```bash
python3 -m pytest tests/ -v  # 52 testes, 52 PASS (36 unit + 16 integration)
```
Cobre: config, storage, filter, export, ai, notifier, reporter, dry-run, imports, scanner helpers.

## ⚠️ COMPORTAMENTOS ESPERADOS (NÃO SÃO BUGS)

- **FP Titanium no startup do Watchdog**: Normal — filtro roda sobre dados em cache da sessão anterior.
- **Nuclei 0 findings**: Normal em alvos sem vulnerabilidades conhecidas. Confirme com `-severity` adequada.
- **Nuclei timeout em alvos grandes (400+ live)**: Aumentar `TOOL_TIMEOUTS["nuclei"]` em `core/config.py` se necessário.
- **Templates update failed no startup**: Normal se não há git ou acesso à internet; scan continua com templates existentes.

## 📋 CLI
```bash
python3 main.py                    # Menu interativo
python3 main.py --target h1.com    # Scan direto
python3 main.py --watchdog         # Modo autônomo 24/7
python3 main.py --dry-run          # Preview sem executar ferramentas
python3 main.py --resume <id>      # Retomar scan interrompido
python3 main.py --export csv       # Exportar findings
python3 main.py --update           # Atualizar ferramentas PDTM
```

## 🔜 PRÓXIMO (FASE 5)
1. Race condition UI — auditar acessos a `_live_view_data` no watchdog
2. Teste de integração real com ferramentas instaladas
3. bbscope fallback gracioso no watchdog
4. CENSYS_API_ID/SECRET no .env real


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

