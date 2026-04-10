# 🛡️ HUNT3R v1.0-EXCALIBUR: Technical Specification

## 🔄 THE PIPELINE (PREDATOR CYCLE)
1. **WATCHDOG**: coleta wildcards (H1/BC/IT) em ciclos de 4–6h com cache de 12h.
2. **DIFF ENGINE**: compara com `recon/baselines/{handle}.json`, processa apenas novos/alterados.
3. **RECON**: Subfinder → DNSX → Uncover → HTTPX.
4. **TACTICAL**: Katana crawler → JS Hunter (JSONL com severity) → Nuclei (`-tags cve,misconfig,takeover -severity critical,high,medium -stats -sj`).
5. **VALIDATION**: FalsePositiveKiller (6 filtros) + AI scoring (AIClient, score ≥ 80).
6. **NOTIFY**: Telegram (Critical/High/Medium + JS secrets severos) · Discord (Low/Info).
7. **REPORT**: BugBountyReporter gera `reports/<handle>_<date>_report.md`.

## 🧩 ARCHITECTURE (Clean)

```
main.py (CLI entry point, ~290 linhas)
  ├── ProOrchestrator
  │     └── MissionRunner.run()
  │           ├── _run_recon_phase()          [subfinder/dnsx/uncover/httpx]
  │           ├── _run_vulnerability_phase()  [sniper filter + truncation guard]
  │           │     └── _run_tactical_phase()
  │           │           ├── katana          [-timeout 15 -depth 2]
  │           │           ├── js_hunter       [JSONL output, severity classification]
  │           │           ├── nuclei          [-duc -stats -sj -severity crit/high/med -c 25 -timeout 5]
  │           │           └── FalsePositiveKiller + _filter_and_validate_findings()
  │           ├── _notify_and_report()        [NotificationDispatcher + BugBountyReporter]
  │           └── ReconDiff.save_baseline()
  └── WatchdogLoop (--watchdog)

core/ (12 módulos)
  config.py    — constantes, timeouts, rate limiter, validators
  scanner.py   — MissionRunner + ProOrchestrator + _run_with_progress
  ui.py        — terminal UI, scroll region, live view (snapshot under lock), _stdout_lock, snapshots
  filter.py    — FalsePositiveKiller (6 filtros: WAF, placeholder, Micro, NULL, PH, curl)
  ai.py        — AIClient + IntelMiner (OpenRouter)
  storage.py   — ReconDiff (baseline diff) + CheckpointManager
  export.py    — ExportFormatter (CSV/XLSX/XML) + run_dry_run
  notifier.py  — NotificationDispatcher (Telegram/Discord, severity-based routing)
  reporter.py  — BugBountyReporter (Markdown reports)
  watchdog.py  — loop 24/7 autônomo
  updater.py   — ToolUpdater (PDTM + nuclei-templates)

recon/ (4 módulos)
  engines.py        — run_subfinder/dnsx/uncover/httpx/katana/nuclei/js_hunter
                      run_nuclei uses Popen + stderr streaming (-stats -sj)
                      run_js_hunter outputs JSONL with severity field
  js_hunter.py      — JSHunter (extração real de secrets de JS via regex)
  platforms.py      — H1Platform, BCPlatform, ITigriti, PlatformManager
  tool_discovery.py — find_tool() com cache, busca em ~/.pdtm/go/bin + ~/go/bin + PATH
```

## 🔧 TOOL FLAGS (verified working)
```
subfinder  -dL <file> -o <out> -silent -rate-limit=50
dnsx       -l <file> -o <out> -wd -silent -a -rate-limit=50
httpx      -l <file> -o <out> -silent -rate-limit 50
katana     -list <file> -o <out> -silent -rate-limit=50 -timeout 15 -depth 2
nuclei     -l <file> -o <out> -duc -stats -sj -rl 50 -c 25 -timeout 5
           -severity critical,high,medium [-tags cve,misconfig,takeover]
```

## 📡 NOTIFICATION ROUTING
| Severity | Canal | Formato |
|----------|-------|---------|
| Critical / High | Telegram | HTML individual por finding |
| Medium | Telegram | HTML individual (🟡) |
| JS Secrets (Critical/High/Medium) | Telegram | HTML individual com tipo/valor |
| Low / Info | Discord | Embed batch |
| JS Secrets (Low) | Discord | Embed batch |

## 🖥️ TERMINAL UI
- `_FIXED_TOP=12` (7 banner + 5 header) → frozen via scroll region
- `_LIVE_VIEW_LINES=12` → frozen at bottom
- `_stdout_lock` (threading.Lock) → serializes ALL stdout writes
- `_live_view_lock` (threading.RLock) → protects `_live_view_data`
- `_render_live_view` → snapshots data under lock, non-blocking acquire on `_stdout_lock`
- `_live_view_loop` → wrapped in try/except (prevents thread crash)
- Status icons: ● grey (idle) → yellow (running) → green (done) / blue (0 results) / red (error)
- TOTAL line: `x SUB | x LV | x TECH | x EP | x VN`
- Nuclei progress: real-time from `-stats -sj` (requests_done/total, rps, matched)
- Call order: `ui_mission_footer()` BEFORE `ui_scan_summary()` (mandatory)

## ⏱️ TIMEOUTS (`core/config.py`)
```python
TOOL_TIMEOUTS = {
    "subfinder": 60, "dnsx": 60, "uncover": 90,
    "httpx": 120, "katana": 180, "js_hunter": 30,
    "nuclei": 3600,  # 1h — vulns at any cost
}
RATE_LIMIT = 50
MAX_SUBS_PER_TARGET = 2000
```

## 🛡️ SECURITY
- Tokens: nunca logados, nunca em código — apenas via `.env`
- Command injection: `shlex.quote()` em todos os subprocessos
- `.env.example`: apenas placeholders genéricos (sem dados reais)
- API keys stored in `Session.headers` (never in log output)
- All subprocess calls use list form (no shell=True)
- MAX_SUBS_PER_TARGET = 2000 (guards against runaway scans)

## 🧪 TESTES
```bash
python3 -m pytest tests/ -q  # 52 testes, 52 PASS (36 unit + 16 integration)
```
Cobre: config, storage, filter, export, ai, notifier, reporter, dry-run, imports, scanner helpers.

## ⚠️ COMPORTAMENTOS ESPERADOS (NÃO SÃO BUGS)

- **FP Titanium no startup do Watchdog**: Normal — filtro roda sobre dados em cache da sessão anterior.
- **Nuclei 0 findings**: Normal em alvos sem vulnerabilidades conhecidas.
- **Templates update failed no startup**: Normal se não há git ou acesso à internet; scan continua com templates existentes.
- **HTTPX 0s em saída vazia do DNSX**: Comportamento correto, sem hosts vivos.

## 📤 OUTPUTS
- `recon/baselines/<handle>_findings.jsonl` — raw Nuclei JSONL (filtered)
- `recon/baselines/<handle>_live.txt.js_secrets` — JS secrets (JSONL with severity)
- `reports/<handle>_<date>_report.md` — submission-ready Markdown
- `logs/snapshots/` — terminal snapshots on errors/SIGINT

## 📋 CLI
```bash
python3 main.py                    # Menu interativo
python3 main.py --watchdog         # Modo autônomo 24/7
python3 main.py --dry-run          # Preview sem executar ferramentas
python3 main.py --resume <id>      # Retomar scan interrompido
python3 main.py --export csv       # Exportar findings (csv|xlsx|xml)
```

## 🔜 PRÓXIMO (FASE 5)
1. Teste de integração real com ferramentas instaladas (Nuclei stats validation)
2. bbscope fallback gracioso no watchdog
3. Terminal em telas pequenas (<24 linhas): guard no scroll region
4. Watchdog mode: H1/BC/IT platform API untested (bbscope not installed)
