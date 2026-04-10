# 🛡️ HUNT3R v1.0-EXCALIBUR: Autonomous Bug Bounty Hunter

## 🎯 Mission
Hunt3r is an autonomous reconnaissance and vulnerability scanner for bug bounty hunters. It automates the full pipeline — from target discovery to **submission-ready reports** — via Telegram/Discord notifications.

## 🔄 Pipeline (Predator Cycle)
1. **WATCHDOG**: Collects wildcards from HackerOne, BugCrowd, Intigriti every 4-6h (12h cache)
2. **DIFF ENGINE**: Compares with baselines, processes only new/modified targets
3. **RECON PHASE**:
   - Subfinder (subdomain enumeration)
   - DNSX (live subdomain resolution)
   - Uncover (takeover candidate detection)
   - HTTPX (tech fingerprint + live URL discovery — output feeds Katana/Nuclei)
4. **TACTICAL PHASE**:
   - Katana crawler (`-timeout 15 -depth 2`)
   - JS Hunter (real extraction of secrets from JavaScript assets, JSONL output with severity)
   - Nuclei (`-severity critical,high,medium -tags cve,misconfig,takeover -c 25 -timeout 5 -duc -stats -sj`)
5. **VALIDATION**: FalsePositiveKiller (6 filters) + AI confirmation (score ≥ 80)
6. **NOTIFICATION**: Telegram (Critical/High/Medium) · Discord (Low/Info)
7. **REPORT**: Markdown bug bounty report ready for H1/BC/IT submission

## 🚀 Quick Start
```bash
pip install -r requirements.txt
cp .env.example .env  # Fill in API keys and Telegram/Discord tokens

python3 main.py              # Interactive menu
python3 main.py --watchdog   # 24/7 autonomous mode
python3 main.py --dry-run    # Preview targets, no tools executed
python3 main.py --export csv # Export findings (csv|xlsx|xml)
python3 main.py --resume <id> # Resume interrupted scan
```

## ⚙️ Environment (.env)
```
H1_TOKEN=your_hackerone_token
H1_USER=your_hackerone_username
BC_TOKEN=your_bugcrowd_token
IT_TOKEN=your_intigriti_token
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
DISCORD_WEBHOOK=your_discord_webhook_url
OPENROUTER_API_KEY=your_openrouter_key  # optional, for AI validation
SHODAN_API_KEY=your_shodan_key          # optional, for Uncover
```

## 📊 Live View (Terminal UI)
Real-time htop-style dashboard frozen at the bottom of the terminal:
- **Status icons**: ● grey (idle) → yellow (running) → green (finished) / blue (0 results) / red (error)
- **Progress bars**: colored by status; Nuclei uses real request progress from `-stats -sj`
- **Counters**: `TOTAL: x SUB | x LV | x TECH | x EP | x VN`
- **ETA**: based on historical tool times; Nuclei uses requests_done/requests_total
- CTRL+C during scan: gracefully stops tools, cleans up live view, returns to menu

## 🗂️ Architecture
```
main.py                     ← CLI entry point (~290 lines)
core/
  scanner.py                ← MissionRunner + ProOrchestrator
  ui.py                     ← Terminal UI, scroll region, _stdout_lock, live view, snapshots
  config.py                 ← Constants, timeouts, rate limiter, validators
  filter.py                 ← FalsePositiveKiller (6 filters: WAF, placeholder, Micro, NULL, PH, curl)
  watchdog.py               ← 24/7 autonomous scan loop
  updater.py                ← PDTM + nuclei-templates auto-update
  ai.py                     ← AIClient + IntelMiner (OpenRouter)
  storage.py                ← ReconDiff + CheckpointManager
  notifier.py               ← NotificationDispatcher (Telegram/Discord)
  reporter.py               ← BugBountyReporter (Markdown reports)
  export.py                 ← CSV/XLSX/XML export + dry-run
recon/
  engines.py                ← Tool wrappers; run_nuclei uses Popen + stderr streaming
  js_hunter.py              ← JSHunter (real JS secret extraction via regex)
  platforms.py              ← H1/BC/IT API clients
  tool_discovery.py         ← find_tool() with cache (~/.pdtm/go/bin + ~/go/bin + PATH)
reports/                    ← Generated bug bounty reports (Markdown)
recon/baselines/            ← Scan baselines and findings (JSONL)
logs/
  hunt3r.log                ← Persistent scan log
  snapshots/                ← Auto-captured terminal snapshots on errors/SIGINT
```

## 📤 Output
After each scan:
- `recon/baselines/<handle>_findings.jsonl` — raw Nuclei findings (filtered)
- `recon/baselines/<handle>_live.txt.js_secrets` — JS secrets (JSONL with severity)
- `reports/<handle>_<date>_report.md` — submission-ready Markdown report
- Telegram: Critical/High/Medium alerts (per finding + JS secrets)
- Discord: Low/Info batch logs

## 🔧 Key Configuration (`core/config.py`)
```python
TOOL_TIMEOUTS = {
    "subfinder": 60, "dnsx": 60, "httpx": 120,
    "katana": 180, "nuclei": 3600,  # 1h — vulns at any cost
}
RATE_LIMIT = 50          # requests/s for tools
MAX_SUBS_PER_TARGET = 2000
```

## 🧪 Tests
```bash
python3 -m pytest tests/ -q   # 52 tests, 52 PASS (36 unit + 16 integration)
```

## 📝 Changelog
See `docs/CHANGELOG.md`

## 🙏 Credits
- [ProjectDiscovery](https://projectdiscovery.io) — subfinder, dnsx, httpx, katana, nuclei, uncover
- Telegram Bot API / Discord Webhooks
- OpenRouter AI API

## 📄 License
MIT